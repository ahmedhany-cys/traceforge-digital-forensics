"""Evidence integrity verification."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..config import Settings
from ..forensics.hashing import sha256_file
from ..forensics.ledger import append_record
from ..models import Evidence, IntegrityCheck
from .acquisition import evidence_path


def verify_evidence(db: Session, settings: Settings, evidence: Evidence, actor: str, trigger: str = "manual",
                    commit: bool = True) -> IntegrityCheck:
    """Re-hash the vault copy and compare with the SHA-256 recorded at acquisition."""
    path = evidence_path(settings, evidence)
    now = datetime.now(timezone.utc)
    if not path.exists():
        observed, result = None, "missing"
    else:
        observed = sha256_file(path)
        result = "match" if observed == evidence.sha256 else "mismatch"
    check = IntegrityCheck(evidence_id=evidence.id, checked_at=now, checked_by=actor, expected_sha256=evidence.sha256,
                           observed_sha256=observed, result=result, trigger=trigger)
    db.add(check)
    evidence.integrity_status = {"match": "verified", "mismatch": "mismatch", "missing": "missing"}[result]
    evidence.last_verified_at = now
    db.flush()
    append_record(db, actor=actor, action="integrity_verified" if result == "match" else "integrity_failure",
                  case_id=evidence.case_id, evidence_id=evidence.id,
                  details={"expected_sha256": evidence.sha256, "observed_sha256": observed, "result": result,
                           "trigger": trigger}, commit=False)
    if commit:
        db.commit()
    return check
