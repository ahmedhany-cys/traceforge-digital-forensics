from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..core.security import (
    SESSION_COOKIE, authenticate, create_session, current_session, current_user, destroy_session, throttle,
)
from ..database import get_db
from ..forensics.ledger import append_record
from ..models import User, UserSession
from . import serializers as ser

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db),
          settings: Settings = Depends(get_settings)):
    client = request.client.host if request.client else "unknown"
    key = (body.username.lower(), client)
    if throttle.locked(key, settings):
        append_record(db, actor=body.username[:64], action="login_locked_out", details={"client": client})
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many failed attempts; try again later")
    user = authenticate(db, body.username, body.password)
    if user is None:
        throttle.fail(key)
        append_record(db, actor=body.username[:64], action="login_failed", details={"client": client})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password")
    throttle.reset(key)
    token, sess = create_session(db, user, settings)
    user.last_login_at = datetime.now(timezone.utc)
    db.flush()
    append_record(db, actor=user.username, action="login", details={"client": client}, commit=False)
    db.commit()
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict", secure=settings.cookie_secure,
                        max_age=settings.session_ttl_minutes * 60, path="/")
    return {"user": ser.user(user), "csrf_token": sess.csrf_token}


@router.post("/logout")
def logout(request: Request, response: Response, sess: UserSession = Depends(current_session), db: Session = Depends(get_db)):
    username = sess.user.username
    destroy_session(db, request.cookies.get(SESSION_COOKIE))
    append_record(db, actor=username, action="logout", commit=False)
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(sess: UserSession = Depends(current_session)):
    return {"user": ser.user(sess.user), "csrf_token": sess.csrf_token}


@router.get("/ping")
def ping(user: User = Depends(current_user)):
    return {"ok": True}
