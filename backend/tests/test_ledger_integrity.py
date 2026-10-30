"""Hash-linked ledger verification and evidence tamper detection."""

from __future__ import annotations

import json

from sqlalchemy import select, text

from app.forensics.ledger import GENESIS_HASH, append_record, compute_record_hash, verify_ledger
from app.models import AuditRecord, Evidence
from app.services.acquisition import evidence_path
from conftest import EVIDENCE


def _seed(env, n=5):
    with env.db() as db:
        for i in range(n):
            append_record(db, actor="tester", action=f"action_{i}", case_id=env.case_id, details={"i": i})


def test_chain_links_and_verifies(env):
    _seed(env)
    with env.db() as db:
        records = db.execute(select(AuditRecord).order_by(AuditRecord.seq)).scalars().all()
        assert records[0].prev_hash == GENESIS_HASH
        for prev, cur in zip(records, records[1:]):
            assert cur.prev_hash == prev.record_hash
        r = records[2]
        assert compute_record_hash(seq=r.seq, record_id=r.record_id, timestamp=r.timestamp, actor=r.actor, action=r.action,
                                   case_id=r.case_id, evidence_id=r.evidence_id, details=r.details,
                                   prev_hash=r.prev_hash) == r.record_hash
        result = verify_ledger(db)
        assert result.valid and result.records_checked == 5 and result.head_hash == records[-1].record_hash


def test_modified_record_detected(env):
    _seed(env)
    with env.db() as db:
        db.execute(text("UPDATE audit_ledger SET details = :d WHERE seq = 3"), {"d": json.dumps({"i": 999})})
        db.commit()
        result = verify_ledger(db)
    assert not result.valid
    assert result.first_invalid_seq == 3
    assert any(p["issue"] == "content_modified" and p["seq"] == 3 for p in result.problems)


def test_deleted_record_detected(env):
    _seed(env)
    with env.db() as db:
        db.execute(text("DELETE FROM audit_ledger WHERE seq = 2"))
        db.commit()
        result = verify_ledger(db)
    issues = {p["issue"] for p in result.problems}
    assert not result.valid and {"sequence_gap", "broken_link"} <= issues


def test_rewritten_hash_breaks_next_link(env):
    """Recomputing one record's hash after editing it still breaks the following record's prev_hash."""
    _seed(env)
    with env.db() as db:
        r = db.execute(select(AuditRecord).where(AuditRecord.seq == 2)).scalar_one()
        r.actor = "mallory"
        r.record_hash = compute_record_hash(seq=r.seq, record_id=r.record_id, timestamp=r.timestamp, actor=r.actor,
                                            action=r.action, case_id=r.case_id, evidence_id=r.evidence_id,
                                            details=r.details, prev_hash=r.prev_hash)
        db.commit()
        result = verify_ledger(db)
    assert not result.valid
    assert any(p["issue"] == "broken_link" and p["seq"] == 3 for p in result.problems)


def test_ledger_verify_api_reports_tampering(env):
    _seed(env)
    env.login("investigator")
    assert env.client.post("/api/custody/verify").json()["valid"] is True
    with env.db() as db:
        db.execute(text("UPDATE audit_ledger SET action = 'nothing_to_see' WHERE seq = 1"))
        db.commit()
    body = env.client.post("/api/custody/verify").json()
    assert body["valid"] is False and body["first_invalid_seq"] == 1


def test_evidence_tampering_detected_and_analysis_refused(env):
    env.login("investigator")
    data = (EVIDENCE / "fw-edge-01_connections.csv").read_bytes()
    ev = env.upload("fw.csv", data).json()["results"][0]["evidence"]
    assert ev["integrity_status"] == "verified"

    ok = env.client.post(f"/api/evidence/{ev['id']}/verify").json()
    assert ok["check"]["result"] == "match"

    with env.db() as db:
        path = evidence_path(env.settings, db.get(Evidence, ev["id"]))
    assert oct(path.stat().st_mode & 0o777) == "0o400"  # vault copy stored read-only
    path.chmod(0o600)
    path.write_bytes(data.replace(b"203.0.113.77", b"203.0.113.78"))  # simulate tampering

    bad = env.client.post(f"/api/evidence/{ev['id']}/verify").json()
    assert bad["check"]["result"] == "mismatch"
    assert bad["check"]["observed_sha256"] != bad["check"]["expected_sha256"]
    assert bad["evidence"]["integrity_status"] == "mismatch"

    refused = env.client.post(f"/api/evidence/{ev['id']}/analyze").json()
    assert refused["analysis"]["status"] == "refused"

    path.unlink()
    missing = env.client.post(f"/api/evidence/{ev['id']}/verify").json()
    assert missing["check"]["result"] == "missing"

    ledger = env.client.get(f"/api/custody/ledger?evidence_id={ev['id']}&action=integrity_failure").json()
    assert ledger["total"] == 3  # manual mismatch, pre-analysis mismatch, missing


def test_analysis_does_not_modify_evidence(env):
    env.login("investigator")
    for name in ("Chrome_History_jmorales.sqlite", "WS-FIN-042_System.evtx", "MFS_ReportViewer.exe"):
        ev = env.upload(name, (EVIDENCE / name).read_bytes()).json()["results"][0]["evidence"]
        detail = env.client.get(f"/api/evidence/{ev['id']}").json()
        triggers = {c["trigger"]: c["result"] for c in detail["integrity_checks"]}
        assert triggers["pre_analysis"] == "match" and triggers["post_analysis"] == "match"
