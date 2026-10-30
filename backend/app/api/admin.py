from __future__ import annotations

import csv
import io
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..core.security import current_user, hash_password, password_policy_error, require_role
from ..database import get_db
from ..forensics import yara_engine
from ..forensics.artifact_rules import RULE_DOCS
from ..forensics.correlation import load_correlation_rules
from ..forensics.event_rules import load_event_rules
from ..forensics.ioc import make_domain, make_hash, make_ip
from ..forensics.ledger import append_record
from ..models import User, WatchlistEntry
from ..services import runtime_settings
from . import serializers as ser

router = APIRouter(prefix="/api", tags=["admin"])


@router.get("/settings")
def get_settings_api(db: Session = Depends(get_db), settings: Settings = Depends(get_settings), user: User = Depends(current_user)):
    return {
        "values": runtime_settings.get_all(db),
        "descriptions": runtime_settings.DESCRIPTIONS,
        "static": {"max_upload_bytes": settings.max_upload_bytes, "max_files_per_upload": settings.max_files_per_upload,
                   "session_ttl_minutes": settings.session_ttl_minutes, "session_idle_minutes": settings.session_idle_minutes,
                   "environment": settings.env},
    }


class SettingsIn(BaseModel):
    values: dict[str, Any]


@router.put("/settings")
def put_settings(body: SettingsIn, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    changed = {}
    try:
        for key, value in body.values.items():
            changed[key] = runtime_settings.set_value(db, key, value, user.username)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from exc
    append_record(db, actor=user.username, action="settings_changed", details=changed, commit=False)
    db.commit()
    return {"values": runtime_settings.get_all(db),
            "note": "Re-run case reconstruction for changes to affect existing timelines, correlations and IOCs."}


# ------------------------------------------------------------------ users

class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9._-]+$")
    display_name: str = Field(min_length=1, max_length=128)
    role: Literal["viewer", "investigator", "admin"]
    password: str = Field(min_length=12, max_length=256)


class UserPatch(BaseModel):
    role: Literal["viewer", "investigator", "admin"] | None = None
    is_active: bool | None = None


@router.get("/users")
def list_users(db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    return [ser.user(u) for u in db.execute(select(User).order_by(User.username)).scalars()]


@router.post("/users", status_code=201)
def create_user(body: UserIn, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    err = password_policy_error(body.password)
    if err:
        raise HTTPException(422, err)
    if db.execute(select(User).where(User.username == body.username)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
    new = User(username=body.username, display_name=body.display_name, role=body.role, password_hash=hash_password(body.password))
    db.add(new)
    db.flush()
    append_record(db, actor=user.username, action="user_created", details={"username": new.username, "role": new.role}, commit=False)
    db.commit()
    return ser.user(new)


@router.patch("/users/{user_id}")
def patch_user(user_id: int, body: UserPatch, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if target.id == user.id and (body.is_active is False or (body.role and body.role != "admin")):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "administrators cannot demote or disable themselves")
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(target, k, v)
    append_record(db, actor=user.username, action="user_updated", details={"username": target.username, **changes}, commit=False)
    db.commit()
    return ser.user(target)


# ------------------------------------------------------------------ rules

@router.get("/rules")
def rules(settings: Settings = Depends(get_settings), user: User = Depends(current_user)):
    ys = yara_engine.load_rules(settings.rules_dir / "yara")
    events = load_event_rules(settings.rules_dir / "detections" / "windows_events.json")
    corr = load_correlation_rules(settings.rules_dir / "detections" / "correlation.json")
    return {
        "yara": {"files": ys.files, "errors": ys.errors, "engine": yara_engine.ENGINE_VERSION,
                 "rules": [{"name": r.name, "file": r.source_file, **{k: r.meta.get(k) for k in ("id", "description", "severity", "explanation")}} for r in ys.rules]},
        "windows_events": [{k: r.get(k) for k in ("id", "title", "event_ids", "severity", "classification", "confidence",
                                                   "description", "rationale", "prerequisites", "mitre")} for r in events],
        "correlation": [{"id": r["id"], "title": r["title"], "severity": r["severity"], "description": r["description"],
                         "steps": [s["name"] for s in r["steps"]]} for r in corr],
        "artifact": RULE_DOCS,
    }


class YaraValidateIn(BaseModel):
    source: str = Field(min_length=1, max_length=256 * 1024)


@router.post("/rules/yara/validate")
def validate_yara(body: YaraValidateIn, user: User = Depends(require_role("investigator"))):
    """Compile a rule (never persisted) and check the required metadata."""
    try:
        infos = yara_engine.validate_rule_source(body.source)
    except yara_engine.RuleValidationError as exc:
        return {"valid": False, "error": str(exc), "rules": []}
    return {"valid": True, "error": None, "rules": [{"name": i.name, "meta": i.meta, "tags": i.tags} for i in infos]}


# ------------------------------------------------------------------ watchlist

@router.get("/watchlist")
def watchlist(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [{"id": w.id, "indicator": w.indicator, "type": w.ioc_type, "confidence": w.confidence, "source": w.source,
             "description": w.description} for w in db.execute(select(WatchlistEntry).order_by(WatchlistEntry.id)).scalars()]


@router.post("/watchlist/import")
async def import_watchlist(file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(require_role("investigator"))):
    raw = await file.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "watchlist file too large (max 2 MiB)")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "watchlist must be UTF-8 CSV") from exc
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or "indicator" not in reader.fieldnames or "type" not in reader.fieldnames:
        raise HTTPException(422, "CSV must have 'indicator' and 'type' columns")
    added, rejected = 0, []
    validators = {"ipv4": make_ip, "domain": make_domain, "sha256": make_hash, "sha1": make_hash, "md5": make_hash}
    for n, row in enumerate(reader, start=2):
        typ = (row.get("type") or "").strip().lower()
        val = (row.get("indicator") or "").strip()
        ind = validators.get(typ, lambda _v: None)(val)
        if ind is None:
            rejected.append({"line": n, "indicator": val[:100], "reason": f"invalid or unsupported {typ or 'type'}"})
            continue
        if db.execute(select(WatchlistEntry).where(WatchlistEntry.indicator == ind.normalized)).scalar_one_or_none():
            continue
        conf = (row.get("confidence") or "low").strip().lower()
        db.add(WatchlistEntry(indicator=ind.normalized, ioc_type=typ, confidence=conf if conf in ("low", "medium", "high") else "low",
                              source=(row.get("source") or file.filename or "upload").strip()[:128],
                              description=(row.get("description") or "").strip()[:1000]))
        added += 1
    append_record(db, actor=user.username, action="watchlist_imported",
                  details={"file": (file.filename or "")[:200], "entries_added": added, "rejected": len(rejected)}, commit=False)
    db.commit()
    return {"added": added, "rejected": rejected[:100],
            "note": "Re-run case reconstruction to re-assess indicators against the updated watchlist."}
