from __future__ import annotations

import io
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(REPO / "dataset" / "generator"))

from app.cli import import_watchlist  # noqa: E402
from app.config import Settings  # noqa: E402
from app.core.security import hash_password, throttle  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Case, User  # noqa: E402

DATASET = REPO / "dataset" / "meridian"
EVIDENCE = DATASET / "evidence"
PASSWORD = "Test-Passw0rd!x"  # test-only credential for throwaway databases created per test


@dataclass
class Env:
    settings: Settings
    client: TestClient
    case_id: int

    def db(self):
        return self.client.app.state.sessionmaker()

    def login(self, username: str = "investigator") -> str:
        r = self.client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
        assert r.status_code == 200, r.text
        token = r.json()["csrf_token"]
        self.client.headers["X-CSRF-Token"] = token
        return token

    def upload(self, name: str, data: bytes, **form):
        return self.client.post(f"/api/cases/{self.case_id}/evidence",
                                files={"files": (name, io.BytesIO(data), "application/octet-stream")},
                                data={"auto_analyze": "true", **form})


def make_env(tmp_path: Path, **overrides) -> Env:
    settings = Settings(data_dir=tmp_path / "data", static_dir=tmp_path / "no-static", **overrides)
    app = create_app(settings)
    with SessionLocal() as db:
        for username, role in (("admin", "admin"), ("investigator", "investigator"), ("viewer", "viewer")):
            db.add(User(username=username, display_name=username.title(), role=role, password_hash=hash_password(PASSWORD)))
        db.flush()
        case = Case(case_number="TEST-001", title="Test case", organization="Test org", lead_investigator_id=2)
        db.add(case)
        db.commit()
        case_id = case.id
    throttle._failures.clear()
    return Env(settings, TestClient(app), case_id)


@pytest.fixture
def env(tmp_path) -> Env:
    return make_env(tmp_path)


@pytest.fixture(scope="session")
def demo(tmp_path_factory) -> Env:
    """Full Meridian scenario ingested through the real API (acquire -> analyze -> reconstruct)."""
    e = make_env(tmp_path_factory.mktemp("demo"))
    with SessionLocal() as db:
        import_watchlist(db, DATASET / "intel" / "meridian_ioc_watchlist.csv", "investigator")
    e.login("investigator")
    for path in sorted(EVIDENCE.iterdir()):
        r = e.upload(path.name, path.read_bytes(), source_host="WS-FIN-042")
        assert r.status_code == 201, (path.name, r.text)
    return e
