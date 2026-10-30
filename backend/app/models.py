"""ORM models.

Naming convention for classification fields used throughout TraceForge:

* ``classification`` on findings: ``confirmed_rule_match`` | ``suspicious`` |
  ``informational`` | ``inconclusive``
* ``severity``: ``critical`` | ``high`` | ``medium`` | ``low`` | ``info``
* ``confidence``: ``high`` | ``medium`` | ``low``
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Stores timezone-aware datetimes as naive UTC and restores tzinfo on load (SQLite has no tz support)."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime rejected; all timestamps must be timezone-aware")
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # admin | investigator | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class UserSession(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    user: Mapped[User] = relationship()


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_number: Mapped[str] = mapped_column(String(64), unique=True)
    title: Mapped[str] = mapped_column(String(255))
    organization: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="open")  # open | analysis | reporting | closed
    priority: Mapped[str] = mapped_column(String(16), default="medium")
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    lead_investigator_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    conclusions: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    lead_investigator: Mapped[User | None] = relationship()


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)  # EV-YYYYMMDD-XXXXXXXX
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="RESTRICT"), index=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    storage_name: Mapped[str] = mapped_column(String(64))  # random name inside the vault; never user supplied
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    sha1: Mapped[str] = mapped_column(String(40))
    md5: Mapped[str] = mapped_column(String(32))
    declared_mime: Mapped[str] = mapped_column(String(128), default="")
    detected_type: Mapped[str] = mapped_column(String(64))
    artifact_type: Mapped[str] = mapped_column(String(32))
    source_description: Mapped[str] = mapped_column(Text, default="")
    source_host: Mapped[str] = mapped_column(String(128), default="")
    acquired_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    acquired_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    duplicate_of: Mapped[str | None] = mapped_column(String(40), nullable=True)
    analysis_status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|running|complete|error
    integrity_status: Mapped[str] = mapped_column(String(16), default="verified")  # verified|mismatch|missing
    last_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    acquired_by: Mapped[User] = relationship()
    __table_args__ = (UniqueConstraint("case_id", "sha256", name="uq_case_sha256"),)


class AuditRecord(Base):
    """One link in the hash-chained audit ledger (see ``forensics/ledger.py``)."""

    __tablename__ = "audit_ledger"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    record_id: Mapped[str] = mapped_column(String(36), unique=True)
    timestamp: Mapped[str] = mapped_column(String(40))  # canonical ISO-8601 string, hashed verbatim
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    case_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    evidence_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    details: Mapped[str] = mapped_column(Text)  # canonical JSON, hashed verbatim
    prev_hash: Mapped[str] = mapped_column(String(64))
    record_hash: Mapped[str] = mapped_column(String(64))


class IntegrityCheck(Base):
    __tablename__ = "integrity_checks"
    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), index=True)
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    checked_by: Mapped[str] = mapped_column(String(64))
    expected_sha256: Mapped[str] = mapped_column(String(64))
    observed_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result: Mapped[str] = mapped_column(String(16))  # match | mismatch | missing
    trigger: Mapped[str] = mapped_column(String(32), default="manual")


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), index=True)
    analyzer: Mapped[str] = mapped_column(String(32))
    engine_version: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    errors: Mapped[list[Any]] = mapped_column(JSON, default=list)
    input_sha256: Mapped[str] = mapped_column(String(64))
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True, index=True)
    analysis_run_id: Mapped[int | None] = mapped_column(ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=True)
    source: Mapped[str] = mapped_column(String(32))  # pe | yara | evtx | browser | network | correlation | ioc
    rule_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    classification: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text, default="")
    event_time: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    source_ref: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class WindowsEvent(Base):
    __tablename__ = "windows_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    analysis_run_id: Mapped[int] = mapped_column(ForeignKey("analysis_runs.id", ondelete="CASCADE"))
    record_number: Mapped[int] = mapped_column(BigInteger)
    event_id: Mapped[int] = mapped_column(Integer, index=True)
    provider: Mapped[str] = mapped_column(String(255))
    channel: Mapped[str] = mapped_column(String(255))
    computer: Mapped[str] = mapped_column(String(255))
    level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timestamp_utc: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    original_timestamp: Mapped[str] = mapped_column(String(64))
    user_sid: Mapped[str | None] = mapped_column(String(128), nullable=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    description: Mapped[str] = mapped_column(String(255), default="")


class BrowserArtifact(Base):
    __tablename__ = "browser_artifacts"
    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    analysis_run_id: Mapped[int] = mapped_column(ForeignKey("analysis_runs.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(16))  # visit | download
    url: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text, default="")
    timestamp_utc: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, index=True)
    original_timestamp: Mapped[str] = mapped_column(String(64), default="")
    visit_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    target_path: Mapped[str] = mapped_column(Text, default="")
    referrer: Mapped[str] = mapped_column(Text, default="")
    total_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class LogRecord(Base):
    """Normalised row from CSV/JSON/text logs."""

    __tablename__ = "log_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    analysis_run_id: Mapped[int] = mapped_column(ForeignKey("analysis_runs.id", ondelete="CASCADE"))
    line_number: Mapped[int] = mapped_column(Integer)
    record_kind: Mapped[str] = mapped_column(String(32))  # network | dns | file | generic
    timestamp_utc: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, index=True)
    original_timestamp: Mapped[str] = mapped_column(String(64), default="")
    timezone_assumed: Mapped[bool] = mapped_column(Boolean, default=False)
    fields: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    message: Mapped[str] = mapped_column(Text, default="")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"))
    timestamp_utc: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    original_timestamp: Mapped[str] = mapped_column(String(64))
    timezone_assumed: Mapped[bool] = mapped_column(Boolean, default=False)
    source_type: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(48), index=True)
    summary: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    confidence: Mapped[str] = mapped_column(String(16), default="high")
    host: Mapped[str] = mapped_column(String(128), default="")
    entities: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source_ref: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)


class Correlation(Base):
    __tablename__ = "correlations"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    classification: Mapped[str] = mapped_column(String(32), default="hypothesis")
    start_time: Mapped[datetime] = mapped_column(UTCDateTime)
    end_time: Mapped[datetime] = mapped_column(UTCDateTime)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    explanation: Mapped[str] = mapped_column(Text)
    caveats: Mapped[list[str]] = mapped_column(JSON, default=list)


class IOC(Base):
    __tablename__ = "iocs"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    ioc_type: Mapped[str] = mapped_column(String(24), index=True)
    value: Mapped[str] = mapped_column(Text)
    normalized: Mapped[str] = mapped_column(String(512), index=True)
    classification: Mapped[str] = mapped_column(String(32))  # address-space / namespace classification
    assessment: Mapped[str] = mapped_column(String(32))  # observed | suspicious | watchlist_match | benign_context
    assessment_reason: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    occurrences: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    __table_args__ = (UniqueConstraint("case_id", "ioc_type", "normalized", name="uq_case_ioc"),)


class WatchlistEntry(Base):
    __tablename__ = "watchlist"
    id: Mapped[int] = mapped_column(primary_key=True)
    indicator: Mapped[str] = mapped_column(String(512), index=True)
    ioc_type: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    report_format: Mapped[str] = mapped_column(String(8))
    generated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    generated_by: Mapped[str] = mapped_column(String(64))
    storage_name: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    content_sha256: Mapped[str] = mapped_column(String(64))  # hash of deterministic content (excludes generation metadata)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    updated_by: Mapped[str] = mapped_column(String(64), default="system")


Index("ix_timeline_case_time", TimelineEvent.case_id, TimelineEvent.timestamp_utc)
