"""Command-line administration.

    python -m app.cli init-db
    python -m app.cli create-user --username alice --role investigator --display-name "Alice Analyst"
    python -m app.cli load-demo            # synthetic Meridian Financial Services case
    python -m app.cli verify-ledger
"""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import os
import secrets
import string
import sys
from pathlib import Path

from sqlalchemy import select

from .config import REPO_DIR, get_settings
from .core.security import ROLES, hash_password, password_policy_error
from .database import SessionLocal, init_engine
from .forensics.ledger import append_record, verify_ledger
from .models import Case, Evidence, User, WatchlistEntry
from .services.acquisition import AcquisitionError, acquire
from .services.analysis import analyze_evidence
from .services.case_analysis import rebuild_case

DEMO_DIR = REPO_DIR / "dataset" / "meridian"
DEMO_CASE = "MFS-IR-2026-0147"
DEMO_USERS = [
    ("admin", "Morgan Lee (Platform Admin)", "admin"),
    ("arivera", "Alex Rivera (DFIR Investigator)", "investigator"),
    ("viewer", "Jamie Chen (Read-only Reviewer)", "viewer"),
]


def _generate_password() -> str:
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(14)) + secrets.choice("!@#%^*-_") + secrets.choice(string.digits)
        if password_policy_error(pw) is None:
            return pw


def _init():
    settings = get_settings()
    settings.ensure_dirs()
    init_engine(settings.sqlalchemy_url)
    return settings


def create_user(db, username: str, display: str, role: str, password: str) -> User:
    if role not in ROLES:
        raise SystemExit(f"role must be one of {ROLES}")
    err = password_policy_error(password)
    if err:
        raise SystemExit(err)
    user = User(username=username, display_name=display, role=role, password_hash=hash_password(password))
    db.add(user)
    db.flush()
    append_record(db, actor="cli", action="user_created", details={"username": username, "role": role}, commit=False)
    db.commit()
    return user


def cmd_create_user(args) -> int:
    _init()
    password = os.environ.get("TRACEFORGE_NEW_PASSWORD") or getpass.getpass("Password: ")
    with SessionLocal() as db:
        if db.execute(select(User).where(User.username == args.username)).scalar_one_or_none():
            raise SystemExit("user already exists")
        create_user(db, args.username, args.display_name or args.username, args.role, password)
    print(f"created {args.role} '{args.username}'")
    return 0


def import_watchlist(db, path: Path, actor: str) -> int:
    added = 0
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            indicator = (row.get("indicator") or "").strip().lower()
            if not indicator:
                continue
            if db.execute(select(WatchlistEntry).where(WatchlistEntry.indicator == indicator)).scalar_one_or_none():
                continue
            db.add(WatchlistEntry(indicator=indicator, ioc_type=(row.get("type") or "").strip().lower(),
                                  confidence=(row.get("confidence") or "low").strip().lower(),
                                  source=(row.get("source") or "local").strip()[:128],
                                  description=(row.get("description") or "").strip()[:1000]))
            added += 1
    append_record(db, actor=actor, action="watchlist_imported", details={"file": path.name, "entries_added": added}, commit=False)
    db.commit()
    return added


DEMO_CONCLUSIONS = """[Demonstration analyst notes for the SIMULATED Meridian case]

Confirmed (directly supported by evidence):
- Q3_Vendor_Invoice.pdf.exe was downloaded through the webmail session on WS-FIN-042 and its SHA-256 matches the acquired sample and the EDR file-creation record.
- The same image was executed by jmorales; its process lineage (PID/parent PID) includes PowerShell, msync.exe, a scheduled task, a service and a new local administrator account.
- Files in Documents\\Confidential were read by processes in that lineage, an archive was created, and 48 MB were sent to 203.0.113.77:443.
- The 'Windows PowerShell' event log was cleared by jmorales' session.

Hypotheses (require validation):
- The outbound transfer contained the archived confidential documents (content not captured; supported by timing, archive size and script block text).
- The failed logons from WS-HR-015 at 12:58 UTC are unrelated (no shared entity with the sequence).

Recommended next steps: isolate WS-FIN-042, acquire memory and full disk image, review proxy content logs for upload.meridian-sync.example, reset jmorales credentials and remove svc_msync."""


def cmd_load_demo(args) -> int:
    settings = _init()
    manifest = json.loads((DEMO_DIR / "manifest.json").read_text())
    credentials: list[tuple[str, str, str]] = []
    with SessionLocal() as db:
        users = {}
        for username, display, role in DEMO_USERS:
            existing = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
            if existing:
                users[username] = existing
                continue
            pw = os.environ.get("TRACEFORGE_DEMO_PASSWORD") or _generate_password()
            users[username] = create_user(db, username, display, role, pw)
            credentials.append((username, role, pw))
        investigator = users["arivera"]

        case = db.execute(select(Case).where(Case.case_number == DEMO_CASE)).scalar_one_or_none()
        if case is None:
            case = Case(case_number=DEMO_CASE, title="Suspected workstation compromise – WS-FIN-042",
                        organization="Meridian Financial Services (fictional)", priority="high", status="analysis",
                        is_synthetic=True, lead_investigator_id=investigator.id,
                        description=("SIMULATED SCENARIO. The security team received an alert about unusual activity on "
                                     "finance workstation WS-FIN-042 (user jmorales) on 2026-10-14: a suspicious e-mail "
                                     "attachment was downloaded, an executable appeared, unusual process execution and "
                                     "access to confidential documents were recorded, and an unusual outbound connection "
                                     "appeared in firewall logs. Possible information exfiltration is suspected."),
                        conclusions=DEMO_CONCLUSIONS)
            db.add(case)
            db.flush()
            append_record(db, actor=investigator.username, action="case_created", case_id=case.id,
                          details={"case_number": DEMO_CASE, "synthetic": True}, commit=False)
            db.commit()

        added = import_watchlist(db, DEMO_DIR / "intel" / "meridian_ioc_watchlist.csv", investigator.username)
        print(f"watchlist entries added: {added}")

        for item in manifest["files"]:
            path = DEMO_DIR / "evidence" / item["filename"]
            with open(path, "rb") as fh:
                try:
                    ev = acquire(db, settings, case=case, user=investigator, stream=fh, filename=item["filename"],
                                 declared_mime="application/octet-stream",
                                 source_description=f"{item['description']} (SIMULATED – Meridian training dataset)",
                                 source_host="WS-FIN-042")
                except AcquisitionError as exc:
                    if exc.status_code == 409:
                        print(f"skip (already acquired): {item['filename']}")
                        continue
                    raise
            if ev.sha256 != item["sha256"]:
                raise SystemExit(f"manifest hash mismatch for {item['filename']}")
            result = analyze_evidence(db, settings, ev, investigator.username)
            print(f"{ev.id}  {item['filename']:<40} {result['status']}")
        stats = rebuild_case(db, settings, case, investigator.username)
        print(f"reconstruction: {stats}")

    if credentials:
        cred_file = settings.data_dir / "demo-credentials.txt"
        with open(cred_file, "w", encoding="utf-8") as fh:
            fh.write("# Demo accounts for the local TraceForge instance (generated; do not commit)\n")
            for username, role, pw in credentials:
                fh.write(f"{username}\t{role}\t{pw}\n")
        cred_file.chmod(0o600)
        print(f"demo credentials written to {cred_file}")
    return 0


def cmd_verify_ledger(args) -> int:
    _init()
    with SessionLocal() as db:
        res = verify_ledger(db)
    print(json.dumps(res.as_dict(), indent=2))
    return 0 if res.valid else 1


def cmd_init_db(args) -> int:
    _init()
    print("database initialised")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="traceforge")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db").set_defaults(fn=cmd_init_db)
    cu = sub.add_parser("create-user")
    cu.add_argument("--username", required=True)
    cu.add_argument("--role", choices=ROLES, required=True)
    cu.add_argument("--display-name")
    cu.set_defaults(fn=cmd_create_user)
    sub.add_parser("load-demo").set_defaults(fn=cmd_load_demo)
    sub.add_parser("verify-ledger").set_defaults(fn=cmd_verify_ledger)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
