from __future__ import annotations

from collections import Counter
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..core.security import current_user, require_role
from ..database import get_db
from ..forensics.event_rules import EVENT_CATALOG
from ..forensics.ledger import append_record
from ..models import (
    IOC, BrowserArtifact, Case, Correlation, Evidence, Finding, IntegrityCheck, Report, TimelineEvent, User, WindowsEvent,
)
from ..services.acquisition import AcquisitionError, acquire
from ..services.analysis import analyze_evidence
from ..services.case_analysis import rebuild_case
from ..services.integrity import verify_evidence
from ..services.reports import generate_report
from . import serializers as ser

router = APIRouter(prefix="/api/cases", tags=["cases"])
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def get_case(case_id: int, db: Session) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "case not found")
    return case


def _counts(db: Session, case_id: int) -> dict:
    return {
        "evidence": db.scalar(select(func.count()).select_from(Evidence).where(Evidence.case_id == case_id)),
        "findings": db.scalar(select(func.count()).select_from(Finding).where(Finding.case_id == case_id,
                                                                            Finding.classification.in_(["suspicious", "confirmed_rule_match"]))),
        "correlations": db.scalar(select(func.count()).select_from(Correlation).where(Correlation.case_id == case_id)),
        "iocs": db.scalar(select(func.count()).select_from(IOC).where(IOC.case_id == case_id)),
    }


class CaseIn(BaseModel):
    case_number: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    title: str = Field(min_length=3, max_length=255)
    organization: str = Field(default="", max_length=255)
    description: str = Field(default="", max_length=20000)
    priority: Literal["low", "medium", "high", "critical"] = "medium"


class CasePatch(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=255)
    description: str | None = Field(default=None, max_length=20000)
    status: Literal["open", "analysis", "reporting", "closed"] | None = None
    priority: Literal["low", "medium", "high", "critical"] | None = None
    conclusions: str | None = Field(default=None, max_length=50000)


@router.get("")
def list_cases(db: Session = Depends(get_db), user: User = Depends(current_user)):
    cases = db.execute(select(Case).order_by(Case.created_at.desc())).scalars().all()
    return [ser.case(c, _counts(db, c.id)) for c in cases]


@router.post("", status_code=201)
def create_case(body: CaseIn, db: Session = Depends(get_db), user: User = Depends(require_role("investigator"))):
    if db.execute(select(Case).where(Case.case_number == body.case_number)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "case number already exists")
    case = Case(case_number=body.case_number, title=body.title, organization=body.organization,
                description=body.description, priority=body.priority, lead_investigator_id=user.id)
    db.add(case)
    db.flush()
    append_record(db, actor=user.username, action="case_created", case_id=case.id,
                  details={"case_number": case.case_number, "title": case.title}, commit=False)
    db.commit()
    return ser.case(case, _counts(db, case.id))


@router.get("/{case_id}")
def case_detail(case_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    return ser.case(get_case(case_id, db), _counts(db, case_id))


@router.patch("/{case_id}")
def update_case(case_id: int, body: CasePatch, db: Session = Depends(get_db), user: User = Depends(require_role("investigator"))):
    case = get_case(case_id, db)
    changes = body.model_dump(exclude_none=True)
    for key, value in changes.items():
        setattr(case, key, value)
    append_record(db, actor=user.username, action="case_updated", case_id=case.id,
                  details={"fields": sorted(changes)}, commit=False)
    db.commit()
    return ser.case(case, _counts(db, case.id))


@router.get("/{case_id}/dashboard")
def dashboard(case_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    case = get_case(case_id, db)
    evidence = db.execute(select(Evidence).where(Evidence.case_id == case_id)).scalars().all()
    findings = db.execute(select(Finding).where(Finding.case_id == case_id)).scalars().all()
    timeline = db.execute(select(TimelineEvent).where(TimelineEvent.case_id == case_id).order_by(TimelineEvent.timestamp_utc)).scalars().all()
    correlations = db.execute(select(Correlation).where(Correlation.case_id == case_id)).scalars().all()
    iocs = db.execute(select(IOC).where(IOC.case_id == case_id)).scalars().all()
    actionable = [f for f in findings if f.classification in ("suspicious", "confirmed_rule_match")]
    # events per 10-minute bucket, split by severity
    buckets: dict[str, Counter] = {}
    for t in timeline:
        key = t.timestamp_utc.replace(minute=t.timestamp_utc.minute - t.timestamp_utc.minute % 10, second=0, microsecond=0).isoformat()
        buckets.setdefault(key, Counter())[t.severity] += 1
    activity = [{"bucket": k, **{s: c.get(s, 0) for s in SEV_RANK}} for k, c in sorted(buckets.items())]
    top = sorted(actionable, key=lambda f: (-SEV_RANK.get(f.severity, 0), f.event_time.isoformat() if f.event_time else "~"))[:8]
    return {
        "case": ser.case(case, _counts(db, case_id)),
        "evidence_total": len(evidence),
        "evidence_bytes": sum(e.size_bytes for e in evidence),
        "evidence_by_type": dict(Counter(e.artifact_type for e in evidence)),
        "evidence_integrity": dict(Counter(e.integrity_status for e in evidence)),
        "analysis_status": dict(Counter(e.analysis_status for e in evidence)),
        "findings_by_classification": dict(Counter(f.classification for f in findings)),
        "findings_by_severity": {s: sum(1 for f in actionable if f.severity == s) for s in SEV_RANK},
        "findings_by_source": dict(Counter(f.source for f in actionable)),
        "timeline_total": len(timeline),
        "timeline_range": [ser.timeline_event(timeline[0])["timestamp_utc"], ser.timeline_event(timeline[-1])["timestamp_utc"]] if timeline else None,
        "activity": activity,
        "correlations": [ser.correlation(c) for c in sorted(correlations, key=lambda c: -SEV_RANK.get(c.severity, 0))],
        "iocs_by_assessment": dict(Counter(i.assessment for i in iocs)),
        "iocs_by_type": dict(Counter(i.ioc_type for i in iocs)),
        "top_findings": [ser.finding(f) for f in top],
        "integrity_checks": db.scalar(select(func.count()).select_from(IntegrityCheck).join(Evidence).where(Evidence.case_id == case_id)),
    }


# ------------------------------------------------------------------ evidence

@router.get("/{case_id}/evidence")
def list_evidence(case_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    get_case(case_id, db)
    rows = db.execute(select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.acquired_at)).scalars().all()
    return [ser.evidence(e) for e in rows]


@router.post("/{case_id}/evidence", status_code=201)
def upload_evidence(
    case_id: int,
    files: list[UploadFile] = File(...),
    source_description: str = Form(default="", max_length=2000),
    source_host: str = Form(default="", max_length=128),
    auto_analyze: bool = Form(default=True),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(require_role("investigator")),
):
    case = get_case(case_id, db)
    if len(files) > settings.max_files_per_upload:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"at most {settings.max_files_per_upload} files per request")
    results = []
    for upload in files:
        try:
            ev = acquire(db, settings, case=case, user=user, stream=upload.file, filename=upload.filename or "",
                         declared_mime=upload.content_type or "", source_description=source_description,
                         source_host=source_host)
        except AcquisitionError as exc:
            results.append({"filename": upload.filename, "status": "rejected", "http_status": exc.status_code,
                            "error": str(exc), "existing_id": exc.existing_id})
            continue
        finally:
            upload.file.close()
        entry = {"filename": upload.filename, "status": "acquired", "evidence": ser.evidence(ev)}
        if auto_analyze:
            entry["analysis"] = analyze_evidence(db, settings, ev, user.username)
            entry["evidence"] = ser.evidence(db.get(Evidence, ev.id))
        results.append(entry)
    if auto_analyze and any(r["status"] == "acquired" for r in results):
        rebuild_case(db, settings, case, user.username)
    if all(r["status"] == "rejected" for r in results):
        code = results[0]["http_status"] if len(results) == 1 else 400
        raise HTTPException(code, {"message": results[0]["error"] if len(results) == 1 else "all files rejected", "results": results})
    return {"results": results}


@router.post("/{case_id}/verify-all")
def verify_all(case_id: int, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
               user: User = Depends(require_role("investigator"))):
    get_case(case_id, db)
    checks = [verify_evidence(db, settings, ev, user.username, trigger="manual", commit=False)
              for ev in db.execute(select(Evidence).where(Evidence.case_id == case_id)).scalars()]
    db.commit()
    return {"checked": len(checks), "results": [ser.integrity_check(c) for c in checks],
            "mismatches": sum(1 for c in checks if c.result != "match")}


@router.post("/{case_id}/rebuild")
def rebuild(case_id: int, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
            user: User = Depends(require_role("investigator"))):
    return rebuild_case(db, settings, get_case(case_id, db), user.username)


# ------------------------------------------------------------------ analysis views

@router.get("/{case_id}/findings")
def list_findings(case_id: int, source: str | None = None, classification: str | None = None,
                  min_severity: str | None = None, evidence_id: str | None = None,
                  db: Session = Depends(get_db), user: User = Depends(current_user)):
    get_case(case_id, db)
    q = select(Finding).where(Finding.case_id == case_id)
    if source:
        q = q.where(Finding.source.in_(source.split(",")))
    if classification:
        q = q.where(Finding.classification.in_(classification.split(",")))
    if evidence_id:
        q = q.where(Finding.evidence_id == evidence_id)
    rows = db.execute(q).scalars().all()
    if min_severity in SEV_RANK:
        rows = [f for f in rows if SEV_RANK.get(f.severity, 0) >= SEV_RANK[min_severity]]
    rows.sort(key=lambda f: (-SEV_RANK.get(f.severity, 0), f.event_time.isoformat() if f.event_time else "~", f.id))
    return [ser.finding(f) for f in rows]


@router.get("/{case_id}/windows-events")
def windows_events(case_id: int, event_id: int | None = None, evidence_id: str | None = None,
                   q: str | None = Query(default=None, max_length=200), flagged_only: bool = False,
                   page: int = Query(default=1, ge=1), page_size: int = Query(default=100, ge=1, le=500),
                   db: Session = Depends(get_db), user: User = Depends(current_user)):
    get_case(case_id, db)
    ev_ids = select(Evidence.id).where(Evidence.case_id == case_id)
    stmt = select(WindowsEvent).where(WindowsEvent.evidence_id.in_(ev_ids))
    if event_id is not None:
        stmt = stmt.where(WindowsEvent.event_id == event_id)
    if evidence_id:
        stmt = stmt.where(WindowsEvent.evidence_id == evidence_id)
    if q:
        like = f"%{q}%"  # bound parameter – never interpolated into SQL
        stmt = stmt.where(or_(WindowsEvent.description.ilike(like), WindowsEvent.computer.ilike(like),
                              WindowsEvent.provider.ilike(like)))
    rows = db.execute(stmt.order_by(WindowsEvent.timestamp_utc)).scalars().all()
    flagged: dict[int, list[dict]] = {}
    for f in db.execute(select(Finding).where(Finding.case_id == case_id, Finding.source == "evtx")).scalars():
        for wid in (f.source_ref or {}).get("windows_event_ids", []):
            flagged.setdefault(wid, []).append({"rule_id": f.rule_id, "severity": f.severity, "classification": f.classification, "title": f.title})
    if flagged_only:
        rows = [r for r in rows if any(x["classification"] != "informational" for x in flagged.get(r.id, []))]
    total = len(rows)
    page_rows = rows[(page - 1) * page_size: page * page_size]
    stats = Counter(r.event_id for r in db.execute(select(WindowsEvent).where(WindowsEvent.evidence_id.in_(ev_ids))).scalars())
    return {
        "total": total, "page": page, "page_size": page_size,
        "items": [{**ser.windows_event(r), "detections": flagged.get(r.id, [])} for r in page_rows],
        "event_id_stats": [{"event_id": k, "count": v, "description": EVENT_CATALOG.get(k, "")} for k, v in sorted(stats.items())],
    }


@router.get("/{case_id}/browser")
def browser(case_id: int, kind: Literal["visit", "download"] | None = None, q: str | None = Query(default=None, max_length=200),
            db: Session = Depends(get_db), user: User = Depends(current_user)):
    get_case(case_id, db)
    ev_ids = select(Evidence.id).where(Evidence.case_id == case_id)
    stmt = select(BrowserArtifact).where(BrowserArtifact.evidence_id.in_(ev_ids))
    if kind:
        stmt = stmt.where(BrowserArtifact.kind == kind)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(BrowserArtifact.url.ilike(like), BrowserArtifact.title.ilike(like), BrowserArtifact.target_path.ilike(like)))
    rows = db.execute(stmt.order_by(BrowserArtifact.timestamp_utc)).scalars().all()
    findings = db.execute(select(Finding).where(Finding.case_id == case_id, Finding.source == "browser")).scalars().all()
    by_artifact: dict[int, list] = {}
    for f in findings:
        by_artifact.setdefault((f.source_ref or {}).get("browser_artifact_id"), []).append(
            {"rule_id": f.rule_id, "severity": f.severity, "title": f.title, "classification": f.classification})
    return {"items": [{**ser.browser_artifact(r), "detections": by_artifact.get(r.id, [])} for r in rows],
            "findings": [ser.finding(f) for f in findings]}


@router.get("/{case_id}/timeline")
def timeline(case_id: int, source_type: str | None = None, min_severity: str | None = None, event_type: str | None = None,
             q: str | None = Query(default=None, max_length=200), db: Session = Depends(get_db), user: User = Depends(current_user)):
    get_case(case_id, db)
    stmt = select(TimelineEvent).where(TimelineEvent.case_id == case_id)
    if source_type:
        stmt = stmt.where(TimelineEvent.source_type.in_(source_type.split(",")))
    if event_type:
        stmt = stmt.where(TimelineEvent.event_type.in_(event_type.split(",")))
    if q:
        stmt = stmt.where(TimelineEvent.summary.ilike(f"%{q}%"))
    rows = db.execute(stmt.order_by(TimelineEvent.timestamp_utc, TimelineEvent.id)).scalars().all()
    if min_severity in SEV_RANK:
        rows = [r for r in rows if SEV_RANK.get(r.severity, 0) >= SEV_RANK[min_severity]]
    in_correlation: dict[int, list[str]] = {}
    for c in db.execute(select(Correlation).where(Correlation.case_id == case_id)).scalars():
        for s in c.steps:
            in_correlation.setdefault(s["timeline_event_id"], []).append(c.rule_id)
    names = {e.id: e.original_filename for e in db.execute(select(Evidence).where(Evidence.case_id == case_id)).scalars()}
    return {"items": [{**ser.timeline_event(r), "evidence_name": names.get(r.evidence_id, ""),
                       "correlations": in_correlation.get(r.id, [])} for r in rows],
            "source_types": sorted({r.source_type for r in db.execute(select(TimelineEvent).where(TimelineEvent.case_id == case_id)).scalars()})}


@router.get("/{case_id}/correlations")
def correlations(case_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    get_case(case_id, db)
    rows = db.execute(select(Correlation).where(Correlation.case_id == case_id)).scalars().all()
    return [ser.correlation(c) for c in sorted(rows, key=lambda c: (-SEV_RANK.get(c.severity, 0), c.start_time))]


@router.get("/{case_id}/iocs")
def iocs(case_id: int, ioc_type: str | None = None, assessment: str | None = None,
         q: str | None = Query(default=None, max_length=200), db: Session = Depends(get_db), user: User = Depends(current_user)):
    get_case(case_id, db)
    stmt = select(IOC).where(IOC.case_id == case_id)
    if ioc_type:
        stmt = stmt.where(IOC.ioc_type.in_(ioc_type.split(",")))
    if assessment:
        stmt = stmt.where(IOC.assessment.in_(assessment.split(",")))
    if q:
        stmt = stmt.where(IOC.normalized.ilike(f"%{q.lower()}%"))
    order = {"watchlist_match": 0, "suspicious": 1, "observed": 2, "benign_context": 3}
    rows = sorted(db.execute(stmt).scalars().all(), key=lambda i: (order.get(i.assessment, 9), i.ioc_type, i.normalized))
    return [ser.ioc(i) for i in rows]


@router.get("/{case_id}/integrity-checks")
def integrity_checks(case_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    get_case(case_id, db)
    rows = db.execute(select(IntegrityCheck).join(Evidence).where(Evidence.case_id == case_id)
                      .order_by(IntegrityCheck.id.desc()).limit(500)).scalars().all()
    return [ser.integrity_check(c) for c in rows]


# ------------------------------------------------------------------ reports

class ReportIn(BaseModel):
    format: Literal["pdf", "json"]


@router.get("/{case_id}/reports")
def list_reports(case_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    get_case(case_id, db)
    rows = db.execute(select(Report).where(Report.case_id == case_id).order_by(Report.generated_at.desc())).scalars().all()
    return [ser.report(r) for r in rows]


@router.post("/{case_id}/reports", status_code=201)
def create_report(case_id: int, body: ReportIn, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                  user: User = Depends(require_role("investigator"))):
    report = generate_report(db, settings, get_case(case_id, db), body.format, user.username)
    return ser.report(report)
