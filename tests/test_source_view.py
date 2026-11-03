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
    assert relative_path(tmp_path, "../../src/docker/backend/Dockerfile") == "docker/backend/Dockerfile"  # KICS


def test_findings_carry_route_and_database_context(tmp_path: Path, monkeypatch):
    import json

    from grephunt.database.tables import FindingRow

    client = _setup(tmp_path, monkeypatch, ROOT / "samples" / "vuln_flask")
    with scan_service.session_factory()() as session:
        for line, rule in ((17, "sqli"), (23, "cmdi"), (1, "header")):
            body = {"location": {"path": "/src/app.py", "start_line": line}, "rule_id": rule, "fingerprint": rule, "correlation_key": rule}
            session.add(FindingRow(scan_id="s1", fingerprint=rule, correlation_key=rule, severity="high", category="code", tool="semgrep", body=json.dumps(body)))
        session.commit()
    by_rule = {item["rule_id"]: item for item in client.get("/api/scans/s1/findings").json()}
    sqli = by_rule["sqli"]["context"]
    assert sqli["routes"][0]["label"] == "GET /user" and sqli["routes"][0]["params"] == ["query.id"]
    assert sqli["database"] == {"target": "SQLite", "dynamic": True, "line": 17}
    assert by_rule["cmdi"]["context"]["routes"][0]["label"] == "GET /ping"
    assert "database" not in by_rule["cmdi"]["context"]
    assert "context" not in by_rule["header"] or "routes" not in by_rule["header"]["context"]


def test_map_overlay_is_saved_apart_from_the_map(tmp_path: Path, monkeypatch):
    client = _setup(tmp_path, monkeypatch, ROOT / "samples" / "vuln_flask")
    assert client.get("/api/scans/s1/map/overlay").json() == {"version": 1, "views": {}}
    overlay = {"version": 1, "views": {"architecture": {
        "positions": {"f:app.py": {"x": 10, "y": 20}},
        "labels": {"f:app.py": "Main app"},
        "notes": {"r:GET /user": "SQL injection here"},
        "blocks": [{"id": "n:1", "label": "WAF", "x": 0, "y": 0}],
        "links": [{"id": "l:1", "source": "n:1", "target": "r:GET /user", "label": "filters"}],
    }}}
    assert client.put("/api/scans/s1/map/overlay", json=overlay).status_code == 200
    assert client.get("/api/scans/s1/map/overlay").json()["views"]["architecture"]["labels"]["f:app.py"] == "Main app"
    assert client.post("/api/scans/s1/map").status_code == 200  # a rebuild keeps the edits
    assert client.get("/api/scans/s1/map/overlay").json()["views"]["architecture"]["notes"]["r:GET /user"] == "SQL injection here"
    assert client.put("/api/scans/nope/map/overlay", json=overlay).status_code == 404


def test_running_scan_shows_correlated_findings(tmp_path: Path, monkeypatch):
    import json

    from grephunt.database.tables import FindingRow
    from grephunt.finding_model.record import Category, Finding, Location, Severity

    client = _setup(tmp_path, monkeypatch, ROOT / "samples" / "vuln_flask")
    with scan_service.session_factory()() as session:
        session.add(ScanRow(id="live", tenant_id=DEFAULT_TENANT, target_label="numberlink", target_path=str(tmp_path), status="running"))
        for line in (36, 55, 80):
            finding = Finding(category=Category.MISCONFIG, tool="trivy", rule_id="AWS-0104", severity=Severity.CRITICAL,
                              title="A security group rule should not allow unrestricted egress to any IP address.",
                              location=Location(path="terraform/modules/network/main.tf", start_line=line))
            body = finding.model_dump(mode="json")
            session.add(FindingRow(scan_id="live", fingerprint=body["fingerprint"], correlation_key=body["correlation_key"],
                                   severity="critical", category="misconfig", tool="trivy", body=json.dumps(body)))
        session.commit()
    live = client.get("/api/scans/live/findings").json()
    assert len(live) == 1
    assert live[0]["lines"] == [36, 55, 80]
    with scan_service.session_factory()() as session:
        session.get(ScanRow, "live").status = "success"
        session.commit()
    assert len(client.get("/api/scans/live/findings").json()) == 3  # a finished scan shows what the pipeline stored


def test_findings_carry_an_exploitability_score(tmp_path: Path, monkeypatch):
    import json

    from grephunt.database.tables import FindingRow

    client = _setup(tmp_path, monkeypatch, ROOT / "samples" / "vuln_flask")
    with scan_service.session_factory()() as session:
        body = {"severity": "high", "category": "code", "rule_id": "sqli", "title": "SQL injection",
                "cwe": ["CWE-89"], "location": {"path": "/src/app.py", "start_line": 17}, "fingerprint": "x", "correlation_key": "x"}
        session.add(FindingRow(scan_id="s1", fingerprint="x", correlation_key="x", severity="high", category="code", tool="semgrep", body=json.dumps(body)))
        session.commit()
    finding = client.get("/api/scans/s1/findings").json()[0]
    assert "exploitability" in finding
    assert 1 <= finding["exploitability"]["score"] <= 99
    # app.py line 17 is reached by GET /user and the query is built from variables, so confidence is high.
    assert finding["exploitability"]["score"] >= 70


def test_poc_endpoint_rejects_secret_and_dependency(tmp_path: Path, monkeypatch):
    client = _setup(tmp_path, monkeypatch, ROOT / "samples" / "vuln_flask")
    payload = {"provider": "gemini", "api_key": "k", "model": "gemini-2.5-flash", "finding": {"category": "dependency", "title": "lodash"}}
    assert client.post("/api/ai/poc", json=payload).status_code == 400
    assert client.post("/api/ai/poc", json={**payload, "finding": {}}).status_code == 400
