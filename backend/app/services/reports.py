"""Report generation and storage."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..forensics.hashing import sha256_bytes
from ..forensics.ledger import append_record
from ..models import Case, Evidence, Report
from ..reporting.builder import build_report
from ..reporting.pdf import render_pdf
from .integrity import verify_evidence

FORMATS = {"pdf": ("application/pdf", ".pdf"), "json": ("application/json", ".json")}


def generate_report(db: Session, settings: Settings, case: Case, fmt: str, actor: str) -> Report:
    if fmt not in FORMATS:
        raise ValueError("format must be 'pdf' or 'json'")
    for ev in db.execute(select(Evidence).where(Evidence.case_id == case.id)).scalars():
        verify_evidence(db, settings, ev, actor, trigger="report", commit=False)
    db.commit()
    report_id = f"RPT-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(3).upper()}"
    data = build_report(db, case, report_id, actor)
    if fmt == "json":
        payload = (json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n").encode("utf-8")
    else:
        payload = render_pdf(data)
    settings.ensure_dirs()
    storage = secrets.token_hex(16) + FORMATS[fmt][1]
    path = settings.reports_dir / storage
    path.write_bytes(payload)
    path.chmod(0o400)
    report = Report(id=report_id, case_id=case.id, report_format=fmt, generated_by=actor, storage_name=storage,
                    size_bytes=len(payload), sha256=sha256_bytes(payload), content_sha256=data["content_sha256"])
    db.add(report)
    append_record(db, actor=actor, action="report_generated", case_id=case.id,
                  details={"report_id": report_id, "format": fmt, "sha256": report.sha256,
                           "content_sha256": report.content_sha256, "size_bytes": len(payload)}, commit=False)
    db.commit()
    return report


def report_path(settings: Settings, report: Report) -> Path:
    path = (settings.reports_dir / report.storage_name).resolve()
    if settings.reports_dir.resolve() not in path.parents:
        raise ValueError("report path escapes the reports directory")
    return path
