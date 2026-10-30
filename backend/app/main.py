"""FastAPI application factory."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api import admin, auth, cases, custody, evidence
from .config import Settings, get_settings
from .core.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from .database import init_engine

log = logging.getLogger("traceforge")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    settings.ensure_dirs()
    factory = init_engine(settings.sqlalchemy_url)

    app = FastAPI(
        title="TraceForge API",
        version="1.0.0",
        description="Digital forensics & threat investigation platform",
        docs_url=None if settings.is_production else "/api/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/api/openapi.json",
    )
    app.state.sessionmaker = factory
    app.dependency_overrides[get_settings] = lambda: settings

    for router in (auth.router, cases.router, evidence.router, custody.router, admin.router):
        app.include_router(router)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        errors = [{"loc": [str(p) for p in e.get("loc", [])], "msg": e.get("msg", "")} for e in exc.errors()]
        return JSONResponse({"detail": "invalid request", "errors": errors}, status_code=422)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        # Log server-side; never leak stack traces, paths or secrets to clients.
        log.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse({"detail": "internal server error"}, status_code=500)

    # Serve the built single-page app when present (production / Docker). Evidence is never served statically.
    dist = Path(settings.static_dir)
    if dist.is_dir():
        index = dist / "index.html"

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            if full_path.startswith("api/"):
                raise HTTPException(404, "not found")
            candidate = (dist / full_path).resolve()
            if full_path and dist.resolve() in candidate.parents and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(index)

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, upload_limit=settings.max_upload_bytes)
    return app


app = None


def get_app() -> FastAPI:  # uvicorn --factory app.main:get_app
    return create_app()
