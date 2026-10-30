"""The documented CLI path: load-demo, verify-ledger, create-user."""

from __future__ import annotations

import stat

import pytest

from app import cli
from app.config import get_settings


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACEFORGE_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    yield tmp_path / "data"
    get_settings.cache_clear()


def test_load_demo_is_idempotent_and_writes_private_credentials(cli_env, capsys):
    assert cli.main(["load-demo"]) == 0
    out = capsys.readouterr().out
    assert "reconstruction: {'timeline_events': 79, 'correlations': 5" in out
    creds = cli_env / "demo-credentials.txt"
    assert stat.S_IMODE(creds.stat().st_mode) == 0o600
    users = [line.split("\t")[0] for line in creds.read_text().splitlines() if not line.startswith("#")]
    assert users == ["admin", "arivera", "viewer"]

    assert cli.main(["load-demo"]) == 0  # second run: duplicates are detected, nothing re-acquired
    assert capsys.readouterr().out.count("skip (already acquired)") == 9
    assert cli.main(["verify-ledger"]) == 0


def test_create_user_enforces_policy(cli_env, monkeypatch):
    monkeypatch.setenv("TRACEFORGE_NEW_PASSWORD", "short")
    with pytest.raises(SystemExit, match="at least 12"):
        cli.main(["create-user", "--username", "alice", "--role", "investigator"])
    monkeypatch.setenv("TRACEFORGE_NEW_PASSWORD", "Correct-Horse-9")
    assert cli.main(["create-user", "--username", "alice", "--role", "investigator"]) == 0
    with pytest.raises(SystemExit, match="already exists"):
        cli.main(["create-user", "--username", "alice", "--role", "viewer"])
