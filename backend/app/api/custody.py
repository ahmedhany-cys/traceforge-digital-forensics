from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.security import current_user, require_role
from ..database import get_db
from ..forensics.ledger import append_record, ledger_head, verify_ledger
from ..models import AuditRecord, User
from . import serializers as ser

router = APIRouter(prefix="/api/custody", tags=["custody"])


@router.get("/ledger")
def ledger(case_id: int | None = None, evidence_id: str | None = Query(default=None, max_length=40),
           action: str | None = Query(default=None, max_length=64), page: int = Query(default=1, ge=1),
           page_size: int = Query(default=50, ge=1, le=500), db: Session = Depends(get_db), user: User = Depends(current_user)):
    stmt = select(AuditRecord)
    if case_id is not None:
        stmt = stmt.where(AuditRecord.case_id == case_id)
    if evidence_id:
        stmt = stmt.where(AuditRecord.evidence_id == evidence_id)
    if action:
        stmt = stmt.where(AuditRecord.action.in_(action.split(",")))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.execute(stmt.order_by(AuditRecord.seq.desc()).offset((page - 1) * page_size).limit(page_size)).scalars().all()
    actions = [a for (a,) in db.execute(select(AuditRecord.action).distinct().order_by(AuditRecord.action))]
    seq, head = ledger_head(db)
    return {"total": total, "page": page, "page_size": page_size, "items": [ser.audit(r) for r in rows],
            "actions": actions, "head": {"seq": seq, "hash": head}}


@router.post("/verify")
def verify(db: Session = Depends(get_db), user: User = Depends(require_role("investigator"))):
    result = verify_ledger(db)
    append_record(db, actor=user.username, action="ledger_verified",
                  details={"valid": result.valid, "records_checked": result.records_checked,
                           "head_hash": result.head_hash, "problems": len(result.problems)})
    return result.as_dict()
