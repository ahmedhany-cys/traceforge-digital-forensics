"""Authentication, sessions, CSRF and role-based authorisation.

* Passwords are hashed with Argon2id (argon2-cffi defaults).
* Sessions are opaque random tokens stored server-side as SHA-256 hashes and
  sent to the browser in an ``HttpOnly``, ``SameSite=Strict`` cookie (``Secure``
  in production). Sessions expire after an absolute lifetime and an idle timeout.
* State-changing requests must carry the per-session CSRF token in the
  ``X-CSRF-Token`` header (synchroniser-token pattern). SameSite=Strict already
  blocks most cross-site requests; the token is defence in depth.
* Repeated login failures lock the account/IP pair out for a period.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..database import get_db
from ..models import User, UserSession

SESSION_COOKIE = "tf_session"
CSRF_HEADER = "X-CSRF-Token"
ROLES = ("viewer", "investigator", "admin")
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}

_hasher = PasswordHasher()
# Dummy hash so that unknown usernames take the same time as wrong passwords.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_policy_error(password: str) -> str | None:
    if len(password) < 12:
        return "password must be at least 12 characters"
    if len(password) > 256:
        return "password must be at most 256 characters"
    classes = sum(bool(any(f(c) for c in password)) for f in (str.islower, str.isupper, str.isdigit, lambda c: not c.isalnum()))
    if classes < 3:
        return "password must contain at least three of: lowercase, uppercase, digit, symbol"
    return None


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class LoginThrottle:
    """In-memory failure counter keyed by (username, client IP)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._failures: dict[tuple[str, str], list[float]] = {}

    def locked(self, key: tuple[str, str], settings: Settings) -> bool:
        now = time.monotonic()
        with self._lock:
            attempts = [t for t in self._failures.get(key, []) if now - t < settings.login_lockout_seconds]
            self._failures[key] = attempts
            return len(attempts) >= settings.login_max_failures

    def fail(self, key: tuple[str, str]) -> None:
        with self._lock:
            self._failures.setdefault(key, []).append(time.monotonic())

    def reset(self, key: tuple[str, str]) -> None:
        with self._lock:
            self._failures.pop(key, None)


throttle = LoginThrottle()


def authenticate(db: Session, username: str, password: str) -> User | None:
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if user is None or not user.is_active:
        verify_password(_DUMMY_HASH, password)
        return None
    if not verify_password(user.password_hash, password):
        return None
    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    return user


def create_session(db: Session, user: User, settings: Settings) -> tuple[str, UserSession]:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    sess = UserSession(token_hash=_token_hash(token), csrf_token=secrets.token_urlsafe(32), user_id=user.id,
                       created_at=now, expires_at=now + timedelta(minutes=settings.session_ttl_minutes), last_seen_at=now)
    db.add(sess)
    db.execute(delete(UserSession).where(UserSession.expires_at < now))
    return token, sess


def destroy_session(db: Session, token: str | None) -> None:
    if token:
        db.execute(delete(UserSession).where(UserSession.token_hash == _token_hash(token)))


def _load_session(request: Request, db: Session, settings: Settings) -> UserSession:
    token = request.cookies.get(SESSION_COOKIE)
    if not token or len(token) > 128:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    sess = db.execute(select(UserSession).where(UserSession.token_hash == _token_hash(token))).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if sess is None or sess.expires_at <= now or now - sess.last_seen_at > timedelta(minutes=settings.session_idle_minutes):
        if sess is not None:
            db.delete(sess)
            db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session expired or invalid")
    if not sess.user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account disabled")
    if now - sess.last_seen_at > timedelta(seconds=60):
        sess.last_seen_at = now
        db.commit()
    return sess


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def current_session(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)) -> UserSession:
    sess = _load_session(request, db, settings)
    if request.method not in SAFE_METHODS:
        supplied = request.headers.get(CSRF_HEADER, "")
        if not supplied or not hmac.compare_digest(supplied, sess.csrf_token):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "missing or invalid CSRF token")
    return sess


def current_user(sess: UserSession = Depends(current_session)) -> User:
    return sess.user


def require_role(minimum: str):
    def dependency(user: User = Depends(current_user)) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"requires role '{minimum}' or higher")
        return user

    return dependency
