"""Scan progress events. The core publishes them. The CLI and the web console display them."""
from __future__ import annotations

import contextlib
import contextvars
from enum import Enum
from typing import Any, Callable, Iterator

from pydantic import BaseModel, Field

_SCAN_HANDLER: contextvars.ContextVar[EventHandler | None] = contextvars.ContextVar(
    "grephunt_scan_handler",
    default=None,
)


class EventType(str, Enum):
    TASK_QUEUED = "task.queued"
    IMAGE_READY = "image.ready"
    TASK_HEARTBEAT = "task.heartbeat"
    TASK_FINISHED = "task.finished"
    FINDING_ACCEPTED = "finding.accepted"
    SCAN_FINISHED = "scan.finished"
    MAP_READY = "map.ready"


class ScanEvent(BaseModel):
    type: EventType
    message: str = ""
    tool: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


EventHandler = Callable[[ScanEvent], None]


@contextlib.contextmanager
def scan_event_scope(handler: EventHandler | None) -> Iterator[None]:
    token = _SCAN_HANDLER.set(handler)
    try:
        yield
    finally:
        _SCAN_HANDLER.reset(token)


def emit(handler: EventHandler | None, event: ScanEvent) -> None:
    target = handler if handler is not None else _SCAN_HANDLER.get()
    if target is not None:
        target(event)
