from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..core.security import current_user, require_role
from ..database import get_db
from ..forensics.ledger import append_record
from ..models import AnalysisRun, AuditRecord, Case, Evidence, Finding, IntegrityCheck, Report, User
from ..services.acquisition import evidence_path
from ..services.analysis import analyze_evidence
from ..services.case_analysis import rebuild_case
from ..services.integrity import verify_evidence
from ..services.reports import FORMATS, report_path
from . import serializers as ser

router = APIRouter(prefix="/api", tags=["evidence"])
EVIDENCE_ID = re.compile(r"^EV-\d{8}-[0-9A-F]{8}$")


def get_evidence(evidence_id: str, db: Session) -> Evidence:
    if not EVIDENCE_ID.match(evidence_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "evidence not found")
    ev = db.get(Evidence, evidence_id)
    if ev is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "evidence not found")
    return ev


@router.get("/evidence/{evidence_id}")
def evidence_detail(evidence_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    ev = get_evidence(evidence_id, db)
    append_record(db, actor=user.username, action="evidence_viewed", case_id=ev.case_id, evidence_id=ev.id)
    runs = db.execute(select(AnalysisRun).where(AnalysisRun.evidence_id == ev.id).order_by(AnalysisRun.id.desc())).scalars().all()
    checks = db.execute(select(IntegrityCheck).where(IntegrityCheck.evidence_id == ev.id).order_by(IntegrityCheck.id.desc())).scalars().all()
    history = db.execute(select(AuditRecord).where(AuditRecord.evidence_id == ev.id).order_by(AuditRecord.seq.desc()).limit(200)).scalars().all()
    findings = db.execute(select(Finding).where(Finding.evidence_id == ev.id)).scalars().all()
    return {
        "evidence": ser.evidence(ev),
        "analysis_runs": [ser.run(r, include_summary=r.is_current) for r in runs],
        "integrity_checks": [ser.integrity_check(c) for c in checks],
        "custody": [ser.audit(a) for a in history],
        "findings": [ser.finding(f) for f in findings],
    }


@router.get("/evidence/{evidence_id}/malware")
def malware(evidence_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    ev = get_evidence(evidence_id, db)
    pe = db.execute(select(AnalysisRun).where(AnalysisRun.evidence_id == ev.id, AnalysisRun.analyzer == "pe",
                                              AnalysisRun.is_current.is_(True))).scalar_one_or_none()
    yara = db.execute(select(AnalysisRun).where(AnalysisRun.evidence_id == ev.id, AnalysisRun.analyzer == "yara",
                                                AnalysisRun.is_current.is_(True))).scalar_one_or_none()
    return {"evidence": ser.evidence(ev), "pe": ser.run(pe) if pe else None, "yara": ser.run(yara) if yara else None}


@router.post("/evidence/{evidence_id}/verify")
def verify(evidence_id: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
           user: User = Depends(require_role("investigator"))):
    ev = get_evidence(evidence_id, db)
    check = verify_evidence(db, settings, ev, user.username, trigger="manual")
    return {"check": ser.integrity_check(check), "evidence": ser.evidence(ev)}


@router.post("/evidence/{evidence_id}/analyze")
def analyze(evidence_id: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
            user: User = Depends(require_role("investigator"))):
    ev = get_evidence(evidence_id, db)
    result = analyze_evidence(db, settings, ev, user.username)
    rebuild = rebuild_case(db, settings, db.get(Case, ev.case_id), user.username)
    return {"analysis": result, "reconstruction": rebuild, "evidence": ser.evidence(db.get(Evidence, evidence_id))}


@router.get("/evidence/{evidence_id}/download")
def download(evidence_id: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
             user: User = Depends(require_role("investigator"))):
    """Export a copy of the evidence. Served as an opaque attachment; never rendered by the browser."""
    ev = get_evidence(evidence_id, db)
    path = evidence_path(settings, ev)
    if not path.exists():
        raise HTTPException(status.HTTP_410_GONE, "evidence file missing from vault")
    append_record(db, actor=user.username, action="evidence_exported", case_id=ev.case_id, evidence_id=ev.id,
                  details={"sha256": ev.sha256})
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", ev.original_filename)[:120] + ".evidence"
    return FileResponse(path, media_type="application/octet-stream", filename=safe_name,
                        headers={"X-Evidence-SHA256": ev.sha256, "Content-Security-Policy": "sandbox"})


@router.get("/reports/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                    user: User = Depends(current_user)):
    if not re.fullmatch(r"RPT-\d{8}-[0-9A-F]{6}", report_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    path = report_path(settings, report)
    if not path.exists():
        raise HTTPException(status.HTTP_410_GONE, "report file missing")
    append_record(db, actor=user.username, action="report_downloaded", case_id=report.case_id,
                  details={"report_id": report.id, "sha256": report.sha256})
    media, ext = FORMATS[report.report_format]
    return FileResponse(path, media_type=media, filename=f"{report.id}{ext}", headers={"X-Report-SHA256": report.sha256})
