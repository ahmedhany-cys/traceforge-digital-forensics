"""Evidence acquisition into the vault.

Flow for every uploaded file:

1. Stream the upload into a private temporary file, enforcing the size limit
   while hashing (never buffering the whole file in memory).
2. Identify the type from content; reject unsupported or mismatched files.
3. Reject duplicates within the case (same SHA-256); flag cross-case duplicates.
4. Move the temp file into the vault under a random name, set it read-only,
   and re-hash the stored copy to confirm it matches the acquisition hash.
5. Record metadata and append ``evidence_acquired`` to the audit ledger.

The vault directory is never served statically; evidence is only readable
through authenticated, audited API endpoints.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..forensics.filetype import check_extension, detect_file
from ..forensics.hashing import sha256_file
from ..forensics.ledger import append_record
from ..models import Case, Evidence, IntegrityCheck, User

READ_CHUNK = 1024 * 1024


class AcquisitionError(Exception):
    def __init__(self, message: str, status_code: int = 400, existing_id: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.existing_id = existing_id


def sanitize_display_filename(name: str) -> str:
    """Make a client-supplied filename safe for display/metadata. It is never used as a path."""
    name = unicodedata.normalize("NFC", name or "")
    name = name.replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable() and ch not in '<>:"|?*\x00')
    name = name.strip().strip(".")
    if not name:
        name = "unnamed"
    return name[:200]


def new_evidence_id() -> str:
    return f"EV-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(4).upper()}"


@dataclass
class StagedUpload:
    path: Path
    sha256: str
    sha1: str
    md5: str
    size: int


def stage_upload(stream: BinaryIO, settings: Settings) -> StagedUpload:
    """Copy an upload stream to a private temp file while hashing and enforcing the size limit."""
    settings.ensure_dirs()
    fd, tmp_name = tempfile.mkstemp(prefix="upload-", dir=settings.work_dir)
    tmp = Path(tmp_name)
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(usedforsecurity=False), hashlib.md5(usedforsecurity=False)
    size = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                block = stream.read(READ_CHUNK)
                if not block:
                    break
                size += len(block)
                if size > settings.max_upload_bytes:
                    raise AcquisitionError(
                        f"file exceeds the maximum evidence size of {settings.max_upload_bytes} bytes", 413)
                sha256.update(block)
                sha1.update(block)
                md5.update(block)
                out.write(block)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return StagedUpload(tmp, sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest(), size)


def acquire(
    db: Session,
    settings: Settings,
    *,
    case: Case,
    user: User,
    stream: BinaryIO,
    filename: str,
    declared_mime: str = "",
    source_description: str = "",
    source_host: str = "",
) -> Evidence:
    display_name = sanitize_display_filename(filename)
    staged = stage_upload(stream, settings)
    try:
        if staged.size == 0:
            raise AcquisitionError("empty files cannot be acquired as evidence", 400)
        detected = detect_file(staged.path)
        accepted, reason = check_extension(display_name, detected)
        if not accepted:
            append_record(db, actor=user.username, action="evidence_rejected", case_id=case.id, details={
                "filename": display_name, "sha256": staged.sha256, "size": staged.size,
                "detected_type": detected.description, "reason": reason})
            raise AcquisitionError(f"rejected: {reason}", 415)

        existing = db.execute(
            select(Evidence).where(Evidence.case_id == case.id, Evidence.sha256 == staged.sha256)
        ).scalar_one_or_none()
        if existing:
            append_record(db, actor=user.username, action="duplicate_evidence_rejected", case_id=case.id,
                          evidence_id=existing.id, details={"filename": display_name, "sha256": staged.sha256})
            raise AcquisitionError(
                f"duplicate evidence: identical SHA-256 already acquired as {existing.id} ('{existing.original_filename}')",
                409, existing.id)
        cross_case = db.execute(
            select(Evidence).where(Evidence.sha256 == staged.sha256).order_by(Evidence.acquired_at)
        ).scalars().first()

        evidence_id = new_evidence_id()
        storage_name = secrets.token_hex(16)
        case_dir = settings.evidence_dir / f"case-{case.id}"
        case_dir.mkdir(parents=True, exist_ok=True)
        case_dir.chmod(0o700)
        dest = case_dir / storage_name
        shutil.move(str(staged.path), dest)
        dest.chmod(0o400)
        stored_hash = sha256_file(dest)
        if stored_hash != staged.sha256:
            dest.chmod(0o600)
            dest.unlink(missing_ok=True)
            raise AcquisitionError("stored copy failed hash verification; acquisition aborted", 500)

        now = datetime.now(timezone.utc)
        evidence = Evidence(
            id=evidence_id, case_id=case.id, original_filename=display_name, storage_name=storage_name,
            size_bytes=staged.size, sha256=staged.sha256, sha1=staged.sha1, md5=staged.md5,
            declared_mime=(declared_mime or "")[:128], detected_type=detected.description,
            artifact_type=detected.artifact_type or "unknown", source_description=source_description[:2000],
            source_host=sanitize_display_filename(source_host)[:128] if source_host.strip() else "",
            acquired_at=now, acquired_by_id=user.id, duplicate_of=cross_case.id if cross_case else None,
            analysis_status="pending", integrity_status="verified", last_verified_at=now,
        )
        db.add(evidence)
        db.add(IntegrityCheck(evidence_id=evidence_id, checked_at=now, checked_by=user.username,
                              expected_sha256=staged.sha256, observed_sha256=stored_hash, result="match",
                              trigger="acquisition"))
        db.flush()
        append_record(db, actor=user.username, action="evidence_acquired", case_id=case.id, evidence_id=evidence_id,
                      details={"original_filename": display_name, "size_bytes": staged.size, "sha256": staged.sha256,
                               "sha1": staged.sha1, "md5": staged.md5, "detected_type": detected.description,
                               "artifact_type": detected.artifact_type, "declared_mime": declared_mime[:128],
                               "duplicate_of": evidence.duplicate_of, "type_check": reason},
                      commit=False)
        db.commit()
        return evidence
    finally:
        staged.path.unlink(missing_ok=True)


def evidence_path(settings: Settings, evidence: Evidence) -> Path:
    path = (settings.evidence_dir / f"case-{evidence.case_id}" / evidence.storage_name).resolve()
    root = settings.evidence_dir.resolve()
    if root not in path.parents:
        raise AcquisitionError("evidence path escapes the vault", 500)
    return path
