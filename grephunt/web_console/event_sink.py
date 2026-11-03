"""Persist scan events off the asyncio loop.

The scan, the HTTP handlers, and the WebSocket share one event loop. A
commit inside the event callback stalls every browser request. This sink
only queues the event for the caller, then a background thread writes short
batches.
"""
from __future__ import annotations

import json
import queue
import threading

from grephunt.config import DEFAULT_TENANT
from grephunt.database.tables import DismissedFindingRow, EventRow, FindingRow, ScanRow, TaskRow
from grephunt.scan_pipeline.events import EventType, ScanEvent

_TASK_STATUS = {
    EventType.TASK_QUEUED: "queued",
    EventType.IMAGE_READY: "running",
    EventType.TASK_HEARTBEAT: "running",
}


class EventSink:
    def __init__(self, scan_id: str, factory) -> None:
        self.scan_id = scan_id
        self._factory = factory
        self._seq = 0
        self._closed = False
        self._lock = threading.Lock()
        self._queue: queue.Queue = queue.Queue()
        self._thread = threading.Thread(target=self._loop, name=f"grephunt-events-{scan_id}", daemon=True)
        self._thread.start()

    def __call__(self, event: ScanEvent) -> None:
        with self._lock:
            if self._closed:
                return
            self._seq += 1
            seq = self._seq
        self._queue.put((seq, event))

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._queue.put(None)
        self._thread.join(timeout=30)

    def _loop(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            batch = [item]
            while len(batch) < 40:
                try:
                    nxt = self._queue.get_nowait()
                except queue.Empty:
                    break
                if nxt is None:
                    self._flush(batch)
                    return
                batch.append(nxt)
            self._flush(batch)

    def _flush(self, batch: list[tuple[int, ScanEvent]]) -> None:
        if not batch:
            return
        with self._factory() as session:
            for seq, event in batch:
                payload = event.model_dump(mode="json")
                session.add(
                    EventRow(
                        scan_id=self.scan_id,
                        tenant_id=DEFAULT_TENANT,
                        seq=seq,
                        type=event.type.value,
                        payload=json.dumps(payload, ensure_ascii=False),
                    )
                )
                _apply_task(session, self.scan_id, event)
                _apply_finding(session, self.scan_id, event)
            session.commit()


def _apply_task(session, scan_id: str, event: ScanEvent) -> None:
    if not event.tool or event.type not in {*_TASK_STATUS, EventType.TASK_FINISHED}:
        return
    status = _TASK_STATUS.get(event.type)
    if event.type == EventType.TASK_FINISHED:
        status = str(event.data.get("status") or "failed")
    row = session.query(TaskRow).filter(TaskRow.scan_id == scan_id, TaskRow.tool == event.tool).one_or_none()
    if row is None:
        row = TaskRow(
            scan_id=scan_id,
            tenant_id=DEFAULT_TENANT,
            tool=event.tool,
            status=status or "queued",
            duration_sec=0.0,
        )
        session.add(row)
    else:
        row.status = status or row.status
    elapsed = event.data.get("elapsed_sec")
    if isinstance(elapsed, (int, float)):
        row.duration_sec = float(elapsed)
    version = event.data.get("version")
    if isinstance(version, str) and version:
        row.tool_version = version
    if event.type == EventType.TASK_FINISHED and status not in {"success", "skipped"} and event.message:
        row.error = event.message[:2000]
    elif event.type == EventType.TASK_FINISHED and status == "success":
        row.error = None


def _apply_finding(session, scan_id: str, event: ScanEvent) -> None:
    if event.type is not EventType.FINDING_ACCEPTED:
        return
    payload = event.data.get("finding")
    if not isinstance(payload, dict):
        return
    fingerprint = str(payload.get("fingerprint") or "")
    correlation_key = str(payload.get("correlation_key") or "")
    if not fingerprint:
        return
    dismissed = (
        session.query(DismissedFindingRow.id)
        .filter(
            DismissedFindingRow.scan_id == scan_id,
            DismissedFindingRow.fingerprint == fingerprint,
            DismissedFindingRow.correlation_key == correlation_key,
        )
        .first()
    )
    if dismissed is not None:
        return
    exists = (
        session.query(FindingRow.id)
        .filter(
            FindingRow.scan_id == scan_id,
            FindingRow.fingerprint == fingerprint,
            FindingRow.correlation_key == correlation_key,
        )
        .first()
    )
    if exists is not None:
        return
    severity = str(payload.get("severity") or event.data.get("severity") or "info")
    category = str(payload.get("category") or "code")
    tool = str(payload.get("tool") or event.tool or "unknown")
    session.add(
        FindingRow(
            scan_id=scan_id,
            tenant_id=DEFAULT_TENANT,
            fingerprint=fingerprint,
            correlation_key=correlation_key,
            severity=severity,
            category=category,
            tool=tool,
            body=json.dumps(payload, ensure_ascii=False),
        )
    )
    scan = session.get(ScanRow, scan_id)
    if scan is not None:
        scan.finding_count = (
            session.query(FindingRow).filter(FindingRow.scan_id == scan_id).count()
        )
