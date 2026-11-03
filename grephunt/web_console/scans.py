"""Start a scan from the console: a folder on this machine, or an uploaded archive."""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from grephunt.config import DATA_DIR, DEFAULT_TENANT
from grephunt.scan_pipeline.events import EventType, ScanEvent
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.excludes import collect_excludes
from grephunt.scan_pipeline.pipeline import run_scan
from grephunt.report_output.json_export import write_findings_json
from grephunt.database.tables import EventRow, FindingRow, ScanRow, TaskRow, make_session_factory
from grephunt.finding_model.record import ScanResult
from grephunt.scanner_catalog.parameter_schema import validate_scan_params
from grephunt.scanner_catalog.registry import load_tools, load_ui_meta
from grephunt.execution.docker import purge_stale_grephunt_containers
from grephunt.web_console.event_sink import EventSink

_SESSION = None
_TASKS: dict[str, asyncio.Task] = {}


def session_factory():
    global _SESSION
    if _SESSION is None:
        _SESSION = make_session_factory()
    return _SESSION


def reset_session_factory(factory=None) -> None:
    global _SESSION
    _SESSION = factory


def list_tools() -> list[dict]:
    ui = load_ui_meta()
    rows: list[dict] = []
    for tool in load_tools().values():
        meta = ui.get(tool.name, {})
        category = tool.descriptor.category.value if tool.descriptor.category else None
        rows.append(
            {
                "name": tool.name,
                "module": tool.descriptor.module.value,
                "image": tool.descriptor.image,
                "version": tool.descriptor.version,
                "network": tool.descriptor.network,
                "prepare_network": tool.descriptor.prepare_network,
                "scans_images": bool(getattr(tool.hook, "supports_image", lambda: False)()),
                "default_enabled": tool.descriptor.default_enabled,
                "cloud": tool.descriptor.cloud,
                "finding_category": category,
                "group": meta.get("group") or ("secret" if category == "secret" else "code"),
                "languages": meta.get("languages") or "",
                "purpose": meta.get("purpose") or "",
                "parameters": [item.model_dump(mode="json") for item in tool.descriptor.parameters],
            }
        )
    return rows


def _scan_dir(scan_id: str) -> Path:
    path = DATA_DIR / "scans" / scan_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def create_scan(
    target: Path,
    label: str,
    scanners: list[str],
    use_docker: bool,
    params: dict[str, dict] | None = None,
    target_kind: str = "source",
    image_format: str = "docker",
) -> str:
    known = load_tools()
    unknown = [name for name in scanners if name not in known]
    if unknown:
        raise ValueError(f"unknown scanner: {', '.join(unknown)}")
    descriptors = {name: tool.descriptor for name, tool in known.items()}
    validated = validate_scan_params(scanners, descriptors, params)
    scan_id = uuid.uuid4().hex[:12]
    params_json = json.dumps(validated, ensure_ascii=False)
    row = ScanRow(
        id=scan_id,
        tenant_id=DEFAULT_TENANT,
        target_label=label,
        target_path=str(target),
        status="running",
        run_params=params_json,
    )
    scan_root = _scan_dir(scan_id)
    meta = {
        "id": scan_id,
        "target_label": label,
        "target_path": str(target),
        "target_kind": target_kind,
        "scanners": scanners,
        "params": validated,
        "status": "running",
    }
    (scan_root / "scan.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    with session_factory()() as session:
        session.add(row)
        for name in scanners:
            session.add(
                TaskRow(
                    scan_id=scan_id,
                    tenant_id=DEFAULT_TENANT,
                    tool=name,
                    status="queued",
                    duration_sec=0.0,
                )
            )
        session.commit()
    task = asyncio.get_running_loop().create_task(
        _execute(
            scan_id,
            target,
            scanners,
            validated,
            use_docker,
            target_kind,
            image_format,
        )
    )
    _TASKS[scan_id] = task
    return scan_id


async def _execute(
    scan_id: str,
    target: Path,
    scanners: list[str],
    params: dict[str, dict],
    use_docker: bool,
    target_kind: str = "source",
    image_format: str = "docker",
) -> None:
    if use_docker:
        await asyncio.to_thread(purge_stale_grephunt_containers)
    sink = EventSink(scan_id, session_factory())
    tools = load_tools()
    selected = [tools[name] for name in scanners]
    # Default excludes (tests, build, dist, out) are about source trees. In an image they would hide packages.
    excludes = collect_excludes(target, None, use_defaults=True) if target_kind == "source" else []
    options = ScanOptions(
        params=params,
        excludes=excludes,
        use_docker=use_docker,
        tenant_id=DEFAULT_TENANT,
        target_kind=target_kind,
        image_format=image_format,
    )
    try:
        result = await run_scan(target, _scan_dir(scan_id), selected, options, on_event=sink, scan_id=scan_id)
        await asyncio.to_thread(sink.close)
        partial = any(run.status.value != "success" for run in result.runs)
        await asyncio.to_thread(write_findings_json, result, _scan_dir(scan_id), params=params, scanners=scanners)
        await asyncio.to_thread(_save_result, scan_id, result, partial)
    except Exception as exc:
        sink(
            ScanEvent(
                type=EventType.SCAN_FINISHED,
                message="scan failed",
                data={"status": "failed"},
            )
        )
        await asyncio.to_thread(sink.close)
        await asyncio.to_thread(_mark_failed, scan_id, repr(exc))
    finally:
        _TASKS.pop(scan_id, None)


def _save_result(scan_id: str, result: ScanResult, partial: bool) -> None:
    with session_factory()() as session:
        row = session.get(ScanRow, scan_id)
        if row is None:
            return
        row.status = "success"
        row.finished_at = datetime.now(timezone.utc)
        row.raw_total = result.raw_total
        row.excluded = result.excluded
        row.finding_count = len(result.findings)
        row.partial = 1 if partial else 0
        existing = {
            task.tool: task
            for task in session.query(TaskRow).filter(TaskRow.scan_id == scan_id).all()
        }
        for run in result.runs:
            task = existing.get(run.tool)
            if task is None:
                task = TaskRow(scan_id=scan_id, tenant_id=DEFAULT_TENANT, tool=run.tool, status=run.status.value)
                session.add(task)
            task.status = run.status.value
            task.duration_sec = run.duration_sec
            task.tool_version = run.tool_version
            task.image = run.image
            task.error = run.error
        session.query(FindingRow).filter(FindingRow.scan_id == scan_id).delete(synchronize_session=False)
        for finding in result.findings:
            body = finding.model_dump(mode="json")
            session.add(
                FindingRow(
                    scan_id=scan_id,
                    tenant_id=DEFAULT_TENANT,
                    fingerprint=finding.fingerprint,
                    correlation_key=finding.correlation_key,
                    severity=finding.severity.value,
                    category=finding.category.value,
                    tool=finding.tool,
                    body=json.dumps(body, ensure_ascii=False),
                )
            )
        session.commit()


def _mark_failed(scan_id: str, error: str) -> None:
    with session_factory()() as session:
        row = session.get(ScanRow, scan_id)
        if row is None:
            return
        row.status = "failed"
        row.error = error
        row.finished_at = datetime.now(timezone.utc)
        _fail_open_tasks(session, scan_id, error)
        session.commit()


def _fail_open_tasks(session, scan_id: str, error: str) -> None:
    tasks = session.query(TaskRow).filter(TaskRow.scan_id == scan_id, TaskRow.status.in_(("queued", "running"))).all()
    for task in tasks:
        task.status = "failed"
        if not task.error:
            task.error = error


def list_scans() -> list[dict]:
    with session_factory()() as session:
        rows = session.query(ScanRow).filter(ScanRow.tenant_id == DEFAULT_TENANT).order_by(ScanRow.created_at.desc()).all()
        return [_scan_dict(row) for row in rows]


def get_scan(scan_id: str) -> dict | None:
    with session_factory()() as session:
        row = session.get(ScanRow, scan_id)
        if row is None or row.tenant_id != DEFAULT_TENANT:
            return None
        tasks = session.query(TaskRow).filter(TaskRow.scan_id == scan_id).all()
        payload = _scan_dict(row)
        payload["tasks"] = [
            {
                "tool": task.tool,
                "status": task.status,
                "duration_sec": task.duration_sec,
                "tool_version": task.tool_version,
                "image": task.image,
                "error": task.error,
            }
            for task in tasks
        ]
        return payload


def get_findings(scan_id: str) -> list[dict] | None:
    with session_factory()() as session:
        row = session.get(ScanRow, scan_id)
        if row is None or row.tenant_id != DEFAULT_TENANT:
            return None
        findings = session.query(FindingRow).filter(FindingRow.scan_id == scan_id).all()
        return [json.loads(item.body) for item in findings]


def get_events(scan_id: str, after: int = 0) -> list[dict] | None:
    with session_factory()() as session:
        row = session.get(ScanRow, scan_id)
        if row is None or row.tenant_id != DEFAULT_TENANT:
            return None
        events = (
            session.query(EventRow)
            .filter(EventRow.scan_id == scan_id, EventRow.seq > after)
            .order_by(EventRow.seq)
            .all()
        )
        return [{"seq": event.seq, **json.loads(event.payload)} for event in events]


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _aware(value).isoformat()


def _duration_sec(row: ScanRow) -> float | None:
    """Wall-clock time of the scan. Tools run in parallel, so this is not the sum of task times."""
    if row.created_at is None:
        return None
    if row.finished_at is not None:
        end = _aware(row.finished_at)
    elif row.status == "running":
        end = datetime.now(timezone.utc)
    else:
        return None
    return round(max(0.0, (end - _aware(row.created_at)).total_seconds()), 1)


def _load_run_params(row: ScanRow) -> dict:
    if row.run_params:
        try:
            payload = json.loads(row.run_params)
            return payload if isinstance(payload, dict) else {}
        except json.JSONDecodeError:
            pass
    path = DATA_DIR / "scans" / row.id / "scan.json"
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            params = payload.get("params")
            return params if isinstance(params, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _scan_dict(row: ScanRow) -> dict:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "target_label": row.target_label,
        "target_path": row.target_path,
        "status": row.status,
        "partial": bool(row.partial),
        "created_at": _iso(row.created_at),
        "finished_at": _iso(row.finished_at),
        "duration_sec": _duration_sec(row),
        "raw_total": row.raw_total,
        "excluded": row.excluded,
        "finding_count": row.finding_count,
        "error": row.error,
        "run_params": _load_run_params(row),
    }
