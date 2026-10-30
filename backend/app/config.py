"""Runtime configuration, loaded from environment variables prefixed ``TRACEFORGE_``."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRACEFORGE_", env_file=".env", extra="ignore")

    env: str = "development"
    data_dir: Path = BACKEND_DIR / "data"
    database_url: str | None = None
    rules_dir: Path = BACKEND_DIR / "rules"
    static_dir: Path = REPO_DIR / "frontend" / "dist"  # built SPA, served when present

    # Upload handling
    max_upload_bytes: int = 50 * 1024 * 1024
    max_files_per_upload: int = 20

    # Sessions
    session_ttl_minutes: int = 8 * 60
    session_idle_minutes: int = 60
    cookie_secure: bool = False
    login_max_failures: int = 5
    login_lockout_seconds: int = 300

    # Analysis defaults (overridable at runtime through the settings API)
    assumed_timezone: str = "UTC"
    correlation_window_minutes: int = 120

    # Development CORS (the Vite dev server proxies /api, so this is normally unused)
    cors_origins: list[str] = []

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "work"

    @property
    def sqlalchemy_url(self) -> str:
        return self.database_url or f"sqlite:///{self.data_dir / 'traceforge.db'}"

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.evidence_dir, self.reports_dir, self.work_dir):
            path.mkdir(parents=True, exist_ok=True)
            try:
                path.chmod(0o700)
            except OSError:
                pass


@lru_cache
def get_settings() -> Settings:
    return Settings()
