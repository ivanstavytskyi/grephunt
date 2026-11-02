"""Event writes stay off the caller, and a finished scan keeps one task row."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from fastapi.testclient import TestClient

from grephunt.config import DEFAULT_TENANT
from grephunt.database.tables import ScanRow, TaskRow
from grephunt.finding_model.record import ScanResult, TaskRun, TaskStatus
from grephunt.scan_pipeline.events import EventType, ScanEvent
from grephunt.web_console import scans as scan_service
from grephunt.web_console.app import _fail_interrupted, app
from grephunt.web_console.event_sink import EventSink


def _use_db(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GREPHUNT_DATABASE_URL", f"sqlite:///{(tmp_path / 'sink.db').as_posix()}")
    scan_service.reset_session_factory()


def _scan(scan_id: str, status: str = "running") -> None:
    with scan_service.session_factory()() as session:
        session.add(
            ScanRow(
                id=scan_id,
                tenant_id=DEFAULT_TENANT,
                target_label="sample",
                target_path="C:/sample",
                status=status,
            )
        )
        session.commit()


def test_sink_returns_before_the_database_write(tmp_path: Path, monkeypatch):
    _use_db(tmp_path, monkeypatch)
    _scan("sink1")
    original = EventSink._flush

    def slow(self, batch):
        time.sleep(0.2)
        original(self, batch)

    monkeypatch.setattr(EventSink, "_flush", slow)
    sink = EventSink("sink1", scan_service.session_factory())
    started = time.perf_counter()
    for index in range(25):
        sink(
            ScanEvent(
                type=EventType.TASK_HEARTBEAT,
                tool="semgrep",
                message=f"running {index}s",
                data={"elapsed_sec": index},
            )
        )
    queued_sec = time.perf_counter() - started
    sink(
        ScanEvent(
            type=EventType.TASK_FINISHED,
            tool="semgrep",
            message="done, 0 findings",
            data={"status": "success", "version": "1.180.0"},
        )
    )
    assert queued_sec < 0.15
    sink.close()
    events = scan_service.get_events("sink1", 0)
    assert events is not None
    assert [event["seq"] for event in events] == list(range(1, 27))
    tasks = scan_service.get_scan("sink1")["tasks"]
    assert len(tasks) == 1
    assert tasks[0]["status"] == "success"
    assert tasks[0]["tool_version"] == "1.180.0"
    assert tasks[0]["duration_sec"] == 24


def test_final_save_updates_the_queued_task(tmp_path: Path, monkeypatch):
    _use_db(tmp_path, monkeypatch)
    _scan("sink2")
    with scan_service.session_factory()() as session:
        session.add(TaskRow(scan_id="sink2", tenant_id=DEFAULT_TENANT, tool="trivy", status="queued", duration_sec=0))
        session.commit()
    result = ScanResult(
        id="sink2",
        target="C:/sample",
        runs=[
            TaskRun(
                tool="trivy",
                status=TaskStatus.SUCCESS,
                duration_sec=9.5,
                tool_version="0.76.0",
                image="aquasec/trivy:0.76.0",
            )
        ],
    )
    scan_service._save_result("sink2", result, False)
    scan_service._save_result("missing-row", result, False)
    saved = scan_service.get_scan("sink2")
    assert saved["status"] == "success"
    assert saved["finished_at"]
    assert len(saved["tasks"]) == 1
    assert saved["tasks"][0]["duration_sec"] == 9.5
    assert saved["tasks"][0]["image"] == "aquasec/trivy:0.76.0"


def test_interrupted_scan_records_an_end_time(tmp_path: Path, monkeypatch):
    _use_db(tmp_path, monkeypatch)
    _scan("sink3")
    with scan_service.session_factory()() as session:
        session.add(TaskRow(scan_id="sink3", tenant_id=DEFAULT_TENANT, tool="semgrep", status="running", duration_sec=3))
        session.commit()
    _fail_interrupted()
    saved = scan_service.get_scan("sink3")
    assert saved["status"] == "failed"
    assert saved["finished_at"]
    assert saved["error"] == "the server stopped while a scan was running"
    assert saved["tasks"][0]["status"] == "failed"


def test_websocket_is_only_for_a_running_scan(tmp_path: Path, monkeypatch):
    _use_db(tmp_path, monkeypatch)
    client = TestClient(app)
    _scan("sink4", status="failed")
    sink = EventSink("sink4", scan_service.session_factory())
    sink(ScanEvent(type=EventType.TASK_QUEUED, tool="semgrep", message="task queued"))
    sink.close()
    with client.websocket_connect("/api/scans/sink4/events") as socket:
        with pytest.raises(Exception):
            socket.receive_json()
    saved = client.get("/api/scans/sink4/log")
    assert saved.status_code == 200
    assert saved.json()[0]["type"] == "task.queued"

    _scan("sink5", status="running")
    live = EventSink("sink5", scan_service.session_factory())
    live(ScanEvent(type=EventType.TASK_QUEUED, tool="semgrep", message="task queued"))
    live.close()
    with client.websocket_connect("/api/scans/sink5/events") as socket:
        message = socket.receive_json()
    assert message["type"] == "task.queued"
    assert message["seq"] == 1
    missing = client.get("/api/scans/does-not-exist/log")
    assert missing.status_code == 404
