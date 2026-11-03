"""Removed findings stay out of the list, including when the scan is saved again."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from grephunt.config import DEFAULT_TENANT
from grephunt.database.tables import FindingRow, ScanRow
from grephunt.finding_model.record import Category, Finding, Location, ScanResult, Severity
from grephunt.web_console import scans as scan_service
from grephunt.web_console.app import app


def _use_db(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GREPHUNT_DATABASE_URL", f"sqlite:///{(tmp_path / 'dismiss.db').as_posix()}")
    scan_service.reset_session_factory()


def _finding(rule: str) -> Finding:
    return Finding(
        tool="betterleaks",
        category=Category.SECRET,
        rule_id=rule,
        title=rule,
        severity=Severity.MEDIUM,
        location=Location(path="data/static/users.yml", start_line=150),
    )


def test_dismiss_removes_findings_and_blocks_restore(tmp_path: Path, monkeypatch):
    _use_db(tmp_path, monkeypatch)
    keep = _finding("keep-me")
    drop = _finding("drop-me")
    with scan_service.session_factory()() as session:
        session.add(
            ScanRow(id="scan1", tenant_id=DEFAULT_TENANT, target_label="sample", target_path="C:/sample", status="success", finding_count=2)
        )
        for finding in (keep, drop):
            session.add(
                FindingRow(
                    scan_id="scan1",
                    tenant_id=DEFAULT_TENANT,
                    fingerprint=finding.fingerprint,
                    correlation_key=finding.correlation_key,
                    severity=finding.severity.value,
                    category=finding.category.value,
                    tool=finding.tool,
                    body=json.dumps(finding.model_dump(mode="json")),
                )
            )
        session.commit()

    client = TestClient(app)
    response = client.post(
        "/api/scans/scan1/findings/dismiss",
        json={"findings": [{"fingerprint": drop.fingerprint, "correlation_key": drop.correlation_key}]},
    )
    assert response.status_code == 200
    assert response.json()["removed"] == 1
    listed = client.get("/api/scans/scan1/findings").json()
    assert [item["rule_id"] for item in listed] == ["keep-me"]

    scan_service._save_result("scan1", ScanResult(id="scan1", target="C:/sample", runs=[], findings=[keep, drop]), False)
    listed = client.get("/api/scans/scan1/findings").json()
    assert [item["rule_id"] for item in listed] == ["keep-me"]
    assert client.get("/api/scans/scan1").json()["finding_count"] == 1
