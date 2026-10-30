"""Analyst-adjustable settings persisted in the database (changes are audited)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..forensics.timeutil import resolve_zone
from ..models import Setting

DEFAULTS: dict[str, Any] = {
    "assumed_timezone": "UTC",
    "correlation_window_minutes": 180,
    "large_transfer_bytes": 10 * 1024 * 1024,
    "sensitive_path_keywords": ["\\confidential\\", "\\restricted\\", "\\hr\\payroll\\", "\\finance\\board\\"],
    "internal_domains": ["meridianfs.example"],
}

DESCRIPTIONS = {
    "assumed_timezone": "IANA timezone applied to source timestamps that carry no timezone (results are flagged as assumed).",
    "correlation_window_minutes": "Maximum span of a correlated event sequence.",
    "large_transfer_bytes": "Outbound bytes in one session at or above which NET-001 is raised.",
    "sensitive_path_keywords": "Path fragments (case-insensitive) that mark a file location as sensitive.",
    "internal_domains": "Domains owned by the investigated organisation; indicators under them are assessed as internal context.",
}


def get_all(db: Session) -> dict[str, Any]:
    values = dict(DEFAULTS)
    for row in db.query(Setting).all():
        if row.key in values:
            values[row.key] = row.value
    return values


def validate(key: str, value: Any) -> Any:
    if key not in DEFAULTS:
        raise ValueError(f"unknown setting '{key}'")
    if key == "assumed_timezone":
        if not isinstance(value, str):
            raise ValueError("assumed_timezone must be a string")
        resolve_zone(value)
        return value
    if key in ("correlation_window_minutes", "large_transfer_bytes"):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{key} must be an integer")
        low, high = (5, 7 * 24 * 60) if key == "correlation_window_minutes" else (1024, 1 << 40)
        if not low <= value <= high:
            raise ValueError(f"{key} must be between {low} and {high}")
        return value
    if key in ("sensitive_path_keywords", "internal_domains"):
        if not isinstance(value, list) or not all(isinstance(v, str) and 0 < len(v) <= 200 for v in value) or len(value) > 50:
            raise ValueError(f"{key} must be a list of up to 50 non-empty strings")
        return [v.strip().lower() for v in value]
    return value


def set_value(db: Session, key: str, value: Any, actor: str) -> Any:
    value = validate(key, value)
    row = db.get(Setting, key)
    if row is None:
        row = Setting(key=key, value=value, updated_by=actor)
        db.add(row)
    else:
        row.value = value
        row.updated_by = actor
    return value
