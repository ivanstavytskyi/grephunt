"""HTTP contract without launching scanners."""
from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from grephunt.web_console import scans as scan_service
from grephunt.web_console.app import app


def test_tools_and_missing_path(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GREPHUNT_DATABASE_URL", f"sqlite:///{(tmp_path / 't.db').as_posix()}")
    scan_service.reset_session_factory()
    client = TestClient(app)
    tools = client.get("/api/tools")
    assert tools.status_code == 200
    assert {item["name"] for item in tools.json()} == {"semgrep", "trivy"}
    assert all(item["version"] != "latest" for item in tools.json())

    missing = client.post("/api/scans", data={"path": str(tmp_path / "nope"), "scanners": "semgrep"})
    assert missing.status_code == 400

    health = client.get("/api/health")
    assert health.status_code == 200
