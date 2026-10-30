"""Authentication, authorisation, CSRF, upload validation and API error handling."""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from app.models import Evidence, UserSession
from app.services.acquisition import evidence_path
from conftest import EVIDENCE, PASSWORD, make_env


# ---------------------------------------------------------------- authentication

def test_login_sets_hardened_cookie_and_me_works(env):
    r = env.client.post("/api/auth/login", json={"username": "investigator", "password": PASSWORD})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "tf_session=" in cookie
    me = env.client.get("/api/auth/me").json()
    assert me["user"]["role"] == "investigator" and me["csrf_token"] == r.json()["csrf_token"]
    assert "password_hash" not in me["user"]


def test_login_failure_is_generic_and_audited(env):
    r1 = env.client.post("/api/auth/login", json={"username": "investigator", "password": "wrong-password"})
    r2 = env.client.post("/api/auth/login", json={"username": "nobody", "password": "wrong-password"})
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json()  # no username enumeration via messages
    env.login("admin")
    actions = [i["action"] for i in env.client.get("/api/custody/ledger?action=login_failed").json()["items"]]
    assert actions.count("login_failed") == 2


def test_lockout_after_repeated_failures(env):
    for _ in range(5):
        assert env.client.post("/api/auth/login", json={"username": "viewer", "password": "nope-nope-nope"}).status_code == 401
    r = env.client.post("/api/auth/login", json={"username": "viewer", "password": PASSWORD})
    assert r.status_code == 429  # locked even with the right password


def test_unauthenticated_requests_rejected(env):
    for path in ("/api/cases", f"/api/cases/{env.case_id}/dashboard", "/api/custody/ledger", "/api/settings"):
        assert env.client.get(path).status_code == 401


def test_logout_invalidates_session(env):
    env.login("investigator")
    assert env.client.post("/api/auth/logout").status_code == 200
    assert env.client.get("/api/cases").status_code == 401


def test_expired_and_idle_sessions_rejected(env):
    env.login("investigator")
    with env.db() as db:
        db.execute(update(UserSession).values(last_seen_at=datetime.now(timezone.utc) - timedelta(hours=3)))
        db.commit()
    assert env.client.get("/api/cases").status_code == 401


def test_csrf_required_for_state_changes(env):
    env.login("investigator")
    token = env.client.headers.pop("X-CSRF-Token")
    assert env.client.post(f"/api/cases/{env.case_id}/verify-all").status_code == 403
    env.client.headers["X-CSRF-Token"] = "forged-token"
    assert env.client.post(f"/api/cases/{env.case_id}/verify-all").status_code == 403
    env.client.headers["X-CSRF-Token"] = token
    assert env.client.post(f"/api/cases/{env.case_id}/verify-all").status_code == 200


# ---------------------------------------------------------------- authorisation

def test_viewer_is_read_only(env):
    env.login("viewer")
    assert env.client.get(f"/api/cases/{env.case_id}").status_code == 200
    assert env.client.patch(f"/api/cases/{env.case_id}", json={"status": "closed"}).status_code == 403
    assert env.upload("fw.csv", b"timestamp,dst_ip\n2026-10-14T10:00:00Z,8.8.8.8\n").status_code == 403
    assert env.client.post(f"/api/cases/{env.case_id}/reports", json={"format": "json"}).status_code == 403
    assert env.client.post("/api/custody/verify").status_code == 403


def test_only_admin_changes_settings_and_users(env):
    env.login("investigator")
    assert env.client.put("/api/settings", json={"values": {"assumed_timezone": "UTC"}}).status_code == 403
    assert env.client.get("/api/users").status_code == 403
    env.login("admin")
    r = env.client.put("/api/settings", json={"values": {"assumed_timezone": "America/New_York", "large_transfer_bytes": 2048}})
    assert r.status_code == 200 and r.json()["values"]["assumed_timezone"] == "America/New_York"
    assert env.client.put("/api/settings", json={"values": {"assumed_timezone": "Not/AZone"}}).status_code == 422
    assert env.client.put("/api/settings", json={"values": {"unknown_key": 1}}).status_code == 422
    weak = env.client.post("/api/users", json={"username": "newbie", "display_name": "N", "role": "viewer", "password": "aaaaaaaaaaaa"})
    assert weak.status_code == 422
    ok = env.client.post("/api/users", json={"username": "newbie", "display_name": "N", "role": "viewer", "password": "Str0ng-Enough!"})
    assert ok.status_code == 201
    me = env.client.get("/api/auth/me").json()["user"]["id"]
    assert env.client.patch(f"/api/users/{me}", json={"is_active": False}).status_code == 400


# ---------------------------------------------------------------- acquisition validation

def test_acquisition_records_metadata_and_ledger(env):
    env.login("investigator")
    data = (EVIDENCE / "resolver_queries.log").read_bytes()
    r = env.upload("../../etc/resolver_queries.log", data, source_host="WS-FIN-042", source_description="DNS log")
    assert r.status_code == 201
    ev = r.json()["results"][0]["evidence"]
    assert ev["original_filename"] == "resolver_queries.log"  # path components stripped
    assert ev["id"].startswith("EV-") and ev["size_bytes"] == len(data)
    assert ev["artifact_type"] == "text_log" and ev["analysis_status"] == "complete"
    with env.db() as db:
        stored = evidence_path(env.settings, db.get(Evidence, ev["id"]))
    assert stored.parent.parent == env.settings.evidence_dir
    assert "resolver" not in stored.name  # random storage name, never the client filename
    acquired = env.client.get(f"/api/custody/ledger?evidence_id={ev['id']}&action=evidence_acquired").json()["items"]
    assert acquired[0]["details"]["sha256"] == ev["sha256"]
    assert acquired[0]["actor"] == "investigator"


def test_duplicate_rejected_with_reference(env):
    env.login("investigator")
    data = (EVIDENCE / "fw-edge-01_connections.csv").read_bytes()
    first = env.upload("fw.csv", data).json()["results"][0]["evidence"]
    dup = env.upload("renamed.csv", data)
    assert dup.status_code == 409
    assert dup.json()["detail"]["results"][0]["existing_id"] == first["id"]


def test_invalid_files_rejected(env):
    env.login("investigator")
    cases = [
        ("invoice.exe", b"this is plain text, not a PE file\n" * 3, 415),
        ("logs.evtx", b"timestamp,a\n2026-01-01,1\n", 415),
        ("archive.zip", b"PK\x03\x04" + b"\x00" * 100, 415),
        ("script.ps1", b"Write-Host hi\n", 415),
        ("empty.log", b"", 400),
    ]
    for name, data, code in cases:
        r = env.upload(name, data)
        assert r.status_code == code, (name, r.text)
    env.login("admin")
    rejected = env.client.get("/api/custody/ledger?action=evidence_rejected").json()["total"]
    assert rejected == 4


def test_oversized_upload_rejected(tmp_path):
    small = make_env(tmp_path, max_upload_bytes=4096)
    small.login("investigator")
    big = b"timestamp,dst_ip\n" + b"2026-10-14T10:00:00Z,10.0.0.1\n" * 400  # ~12 KB
    r = small.upload("big.csv", big)
    assert r.status_code == 413
    assert not list(small.settings.work_dir.iterdir())  # staged temp file cleaned up


def test_request_body_limit_on_json_endpoints(env):
    env.login("investigator")
    r = env.client.post("/api/rules/yara/validate", content=b"{" + b" " * (5 * 1024 * 1024) + b"}",
                        headers={"content-type": "application/json"})
    assert r.status_code == 413


# ---------------------------------------------------------------- errors & headers

def test_not_found_and_validation_errors(env):
    env.login("investigator")
    assert env.client.get("/api/cases/9999").status_code == 404
    assert env.client.get("/api/evidence/../../etc/passwd").status_code == 404
    assert env.client.get("/api/evidence/EV-00000000-DEADBEEF").status_code == 404
    assert env.client.get("/api/reports/RPT-1/download").status_code == 404
    r = env.client.post("/api/cases", json={"case_number": "bad number!", "title": "x"})
    assert r.status_code == 422 and r.json()["detail"] == "invalid request"
    assert {"loc", "msg"} <= set(r.json()["errors"][0])


def test_unhandled_errors_do_not_leak_details(env):
    @env.client.app.get("/api/boom")
    def boom():
        raise RuntimeError("secret internal path /var/lib/x and token abc123")

    from fastapi.testclient import TestClient
    r = TestClient(env.client.app, raise_server_exceptions=False).get("/api/boom")
    assert r.status_code == 500 and r.json() == {"detail": "internal server error"}
    assert "secret" not in r.text


def test_security_headers(env):
    r = env.client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_evidence_export_is_audited_attachment(env):
    env.login("investigator")
    data = (EVIDENCE / "MFS_ReportViewer.exe").read_bytes()
    ev = env.upload("MFS_ReportViewer.exe", data).json()["results"][0]["evidence"]
    r = env.client.get(f"/api/evidence/{ev['id']}/download")
    assert r.status_code == 200 and r.content == data
    assert r.headers["content-type"] == "application/octet-stream"
    assert "attachment" in r.headers["content-disposition"] and r.headers["x-evidence-sha256"] == ev["sha256"]
    env.login("viewer")
    assert env.client.get(f"/api/evidence/{ev['id']}/download").status_code == 403
    env.login("investigator")
    actions = [i["action"] for i in env.client.get(f"/api/custody/ledger?evidence_id={ev['id']}").json()["items"]]
    assert "evidence_exported" in actions


def test_yara_validate_endpoint(env):
    env.login("investigator")
    bad = env.client.post("/api/rules/yara/validate", json={"source": "rule x { condition: nope }"}).json()
    assert bad["valid"] is False and bad["error"]
    good = env.client.post("/api/rules/yara/validate", json={"source":
        'rule t { meta: id="T-1" description="d" severity="low" explanation="e" strings: $a = "x" condition: $a }'}).json()
    assert good["valid"] is True and good["rules"][0]["name"] == "t"


def test_watchlist_import_validates_rows(env):
    env.login("investigator")
    csv_data = "indicator,type,confidence,source,description\n203.0.113.9,ipv4,high,t,d\nnot-an-ip,ipv4,low,t,d\nevil.example,domain,medium,t,d\n"
    r = env.client.post("/api/watchlist/import", files={"file": ("w.csv", io.BytesIO(csv_data.encode()), "text/csv")})
    body = r.json()
    assert r.status_code == 200 and body["added"] == 2 and body["rejected"][0]["line"] == 3
    assert {w["indicator"] for w in env.client.get("/api/watchlist").json()} == {"203.0.113.9", "evil.example"}
