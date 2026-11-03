"""Source view: lines around a finding, marks from the map, and path safety."""
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from grephunt.config import DEFAULT_TENANT
from grephunt.database.tables import ScanRow
from grephunt.web_console import app as console
from grephunt.web_console import scans as scan_service
from grephunt.web_console.source_view import relative_path

ROOT = Path(__file__).resolve().parents[1]


def _setup(tmp_path: Path, monkeypatch, target: Path) -> TestClient:
    monkeypatch.setenv("GREPHUNT_DATABASE_URL", f"sqlite:///{(tmp_path / 'src.db').as_posix()}")
    monkeypatch.setattr(scan_service, "DATA_DIR", tmp_path / "data")
    scan_service.reset_session_factory()
    with scan_service.session_factory()() as session:
        session.add(ScanRow(id="s1", tenant_id=DEFAULT_TENANT, target_label=target.name, target_path=str(target), status="success"))
        session.commit()
    asyncio.run(scan_service._build_map("s1", target, lambda event: None))
    return TestClient(console.app)


def test_source_around_a_finding_with_map_marks(tmp_path: Path, monkeypatch):
    client = _setup(tmp_path, monkeypatch, ROOT / "samples" / "vuln_flask")
    finding = {"location": {"path": "/src/app.py", "start_line": 17}, "severity": "high", "title": "SQL injection", "fingerprint": "f", "correlation_key": "c"}
    monkeypatch.setattr(scan_service, "get_findings", lambda scan_id: [finding])
    body = client.get("/api/scans/s1/source", params={"path": "/src/app.py", "line": 17, "context": 3}).json()
    assert body["path"] == "app.py" and body["language"] == "python"
    assert body["start"] == 14 and len(body["lines"]) == 7
    assert "conn.execute" in body["lines"][17 - body["start"]]
    kinds = {(mark["line"], mark["kind"]) for mark in body["marks"]}
    assert {(15, "input"), (17, "sink"), (17, "finding")} <= kinds
    sink = next(mark for mark in body["marks"] if mark["kind"] == "sink")
    assert "built from variables" in sink["label"]
    whole = client.get("/api/scans/s1/source", params={"path": "app.py", "line": 17, "context": 0}).json()
    assert whole["start"] == 1 and len(whole["lines"]) == whole["total_lines"]


def test_source_refuses_paths_outside_the_scan(tmp_path: Path, monkeypatch):
    client = _setup(tmp_path, monkeypatch, ROOT / "samples" / "vuln_flask")
    assert client.get("/api/scans/s1/source", params={"path": "../vuln_go/main.go"}).status_code == 409
    assert client.get("/api/scans/s1/source", params={"path": "missing.py"}).status_code == 409
    assert client.get("/api/scans/nope/source", params={"path": "app.py"}).status_code == 404


def test_relative_path_forms(tmp_path: Path):
    assert relative_path(tmp_path, "/src/a/b.py") == "a/b.py"
    assert relative_path(tmp_path, "./a/b.py") == "a/b.py"
    assert relative_path(tmp_path, f"{tmp_path.resolve().as_posix()}/a/b.py") == "a/b.py"
    assert relative_path(tmp_path, "a\\b.py") == "a/b.py"
