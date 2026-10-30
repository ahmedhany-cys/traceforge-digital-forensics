"""Tamper-evident, hash-linked audit ledger.

Every security-relevant action (acquisition, access, analysis, verification,
report generation, configuration change, login) is appended as a record whose
hash covers its own content *and* the hash of the previous record:

    record_hash = SHA-256( canonical_json({seq, record_id, timestamp, actor,
                                          action, case_id, evidence_id,
                                          details, prev_hash}) )

Changing, deleting, re-ordering or inserting any record breaks the chain from
that point on, which :func:`verify_ledger` detects and localises.

Tamper-evident is not the same as immutable. Someone with write access to the
database can rewrite the *whole* chain consistently. Detecting that requires
anchoring the head hash somewhere the attacker cannot reach (a printed report,
a ticket, a WORM bucket, a signed timestamp). TraceForge exposes the head hash
for exactly that purpose and includes it in every generated report.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AuditRecord

GENESIS_HASH = "0" * 64
_append_lock = threading.Lock()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_record_hash(
    *, seq: int, record_id: str, timestamp: str, actor: str, action: str,
    case_id: int | None, evidence_id: str | None, details: str, prev_hash: str,
) -> str:
    payload = canonical_json({
        "seq": seq,
        "record_id": record_id,
        "timestamp": timestamp,
        "actor": actor,
        "action": action,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "details": details,
        "prev_hash": prev_hash,
    })
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_record(
    db: Session,
    *,
    actor: str,
    action: str,
    case_id: int | None = None,
    evidence_id: str | None = None,
    details: dict[str, Any] | None = None,
    commit: bool = True,
) -> AuditRecord:
    """Append a record to the ledger. Appends are serialised process-wide."""
    with _append_lock:
        last = db.execute(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1)).scalar_one_or_none()
        seq = (last.seq + 1) if last else 1
        prev_hash = last.record_hash if last else GENESIS_HASH
        record_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        details_json = canonical_json(details or {})
        record_hash = compute_record_hash(
            seq=seq, record_id=record_id, timestamp=timestamp, actor=actor, action=action,
            case_id=case_id, evidence_id=evidence_id, details=details_json, prev_hash=prev_hash,
        )
        record = AuditRecord(
            seq=seq, record_id=record_id, timestamp=timestamp, actor=actor, action=action,
            case_id=case_id, evidence_id=evidence_id, details=details_json,
            prev_hash=prev_hash, record_hash=record_hash,
        )
        db.add(record)
        if commit:
            db.commit()
        else:
            db.flush()
        return record


@dataclass
class LedgerVerification:
    valid: bool
    records_checked: int
    head_hash: str
    problems: list[dict[str, Any]] = field(default_factory=list)
    first_invalid_seq: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "records_checked": self.records_checked,
            "head_hash": self.head_hash,
            "first_invalid_seq": self.first_invalid_seq,
            "problems": self.problems,
        }


def verify_ledger(db: Session) -> LedgerVerification:
    """Walk the full chain and report every inconsistency found."""
    problems: list[dict[str, Any]] = []
    expected_prev = GENESIS_HASH
    expected_seq = 1
    count = 0
    head = GENESIS_HASH
    for record in db.execute(select(AuditRecord).order_by(AuditRecord.seq)).scalars():
        count += 1
        if record.seq != expected_seq:
            problems.append({
                "seq": record.seq, "issue": "sequence_gap",
                "detail": f"expected seq {expected_seq}, found {record.seq} (records removed or inserted)",
            })
        if record.prev_hash != expected_prev:
            problems.append({
                "seq": record.seq, "issue": "broken_link",
                "detail": "prev_hash does not equal the hash of the preceding record",
            })
        recomputed = compute_record_hash(
            seq=record.seq, record_id=record.record_id, timestamp=record.timestamp, actor=record.actor,
            action=record.action, case_id=record.case_id, evidence_id=record.evidence_id,
            details=record.details, prev_hash=record.prev_hash,
        )
        if recomputed != record.record_hash:
            problems.append({
                "seq": record.seq, "issue": "content_modified",
                "detail": "stored record_hash does not match the recomputed hash of the record content",
            })
        expected_prev = record.record_hash
        expected_seq = record.seq + 1
        head = record.record_hash
    first_invalid = min((p["seq"] for p in problems), default=None)
    return LedgerVerification(valid=not problems, records_checked=count, head_hash=head,
                              problems=problems, first_invalid_seq=first_invalid)


def ledger_head(db: Session) -> tuple[int, str]:
    last = db.execute(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1)).scalar_one_or_none()
    if last is None:
        return 0, GENESIS_HASH
    return last.seq, last.record_hash


def ledger_count(db: Session) -> int:
    return db.execute(select(func.count()).select_from(AuditRecord)).scalar_one()
