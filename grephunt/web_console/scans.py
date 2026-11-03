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
from grephunt.database.tables import DismissedFindingRow, EventRow, FindingRow, ScanRow, TaskRow, make_session_factory
from grephunt.finding_model.record import ScanResult
from grephunt.scanner_catalog.parameter_schema import validate_scan_params
from grephunt.web_console.scan_source_context import infer_github_from_label
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
    source_repo_url: str | None = None,
    source_ref: str | None = None,
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
        source_repo_url=source_repo_url,
        source_ref=source_ref,
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
        "source_repo_url": source_repo_url,
        "source_ref": source_ref,
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
    if target_kind == "source":
        await _build_map(scan_id, target, sink)
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


async def _build_map(scan_id: str, target: Path, sink) -> None:
    """Reconnaissance before the scanners: the project map. A failure here never stops the scan."""
    from grephunt.project_map import build_project_map, write_project_map

    try:
        project_map = await asyncio.to_thread(build_project_map, target)
        await asyncio.to_thread(write_project_map, project_map, _scan_dir(scan_id))
    except Exception as exc:  # noqa: BLE001 - the map is optional, the scan is not.
        sink(ScanEvent(type=EventType.MAP_READY, message=f"project map failed: {exc}"[:400], data={"ok": False}))
        return
    stats = project_map.stats
    stack = ", ".join(project_map.stack.get("frameworks") or []) or "no known framework"
    sink(
        ScanEvent(
            type=EventType.MAP_READY,
            message=(
                f"project map: {stats.get('files', 0)} files, {stats.get('import_edges', 0)} imports, "
                f"{len(project_map.architecture.nodes)} architecture nodes ({stack})"
            ),
            data={"ok": True, "files": stats.get("files", 0)},
        )
    )


def get_project_map(scan_id: str) -> dict | None:
    """The saved map of a scan. None when the scan is unknown; {} when it has no map yet."""
    if get_scan(scan_id) is None:
        return None
    path = DATA_DIR / "scans" / scan_id / "project_map.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def get_source(scan_id: str, path: str, line: int | None, end_line: int | None, context: int) -> dict | None:
    """Lines of a scanned file around a finding, with marks from the map and other findings."""
    from grephunt.web_console.source_view import load_map, read_source

    found = get_scan(scan_id)
    if found is None:
        return None
    target = Path(found.get("target_path") or "")
    return read_source(target, path, line, end_line, context, get_findings(scan_id) or [], load_map(_scan_dir(scan_id)))


def rebuild_project_map(scan_id: str) -> dict | None:
    """Build the map again from the scan's target, for scans made before the map existed."""
    from grephunt.project_map import build_project_map, write_project_map

    found = get_scan(scan_id)
    if found is None:
        return None
    target = Path(found.get("target_path") or "")
    if not target.is_dir():
        raise ValueError("the scanned folder is no longer on this machine")
    project_map = build_project_map(target, label=found.get("target_label"))
    write_project_map(project_map, _scan_dir(scan_id))
    return project_map.model_dump(mode="json")


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
        dismissed = _dismissed_keys(session, scan_id)
        kept = 0
        for finding in result.findings:
            if (finding.fingerprint, finding.correlation_key) in dismissed:
                continue
            kept += 1
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
        row.finding_count = kept
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
        dismissed = _dismissed_keys(session, scan_id)
        visible = [
            item
            for item in findings
            if (item.fingerprint, item.correlation_key) not in dismissed
        ]
        return [json.loads(item.body) for item in visible]


def dismiss_findings(scan_id: str, keys: list[tuple[str, str]]) -> int | None:
    """Remove findings from this scan. Returns how many rows were deleted, or None if the scan is missing."""
    unique = list(dict.fromkeys((fingerprint, correlation_key) for fingerprint, correlation_key in keys if fingerprint))
    with session_factory()() as session:
        row = session.get(ScanRow, scan_id)
        if row is None or row.tenant_id != DEFAULT_TENANT:
            return None
        already = _dismissed_keys(session, scan_id)
        removed = 0
        for fingerprint, correlation_key in unique:
            if (fingerprint, correlation_key) not in already:
                session.add(
                    DismissedFindingRow(
                        scan_id=scan_id,
                        tenant_id=DEFAULT_TENANT,
                        fingerprint=fingerprint,
                        correlation_key=correlation_key,
                    )
                )
                already.add((fingerprint, correlation_key))
            deleted = (
                session.query(FindingRow)
                .filter(
                    FindingRow.scan_id == scan_id,
                    FindingRow.fingerprint == fingerprint,
                    FindingRow.correlation_key == correlation_key,
                )
                .delete(synchronize_session=False)
            )
            removed += int(deleted or 0)
        row.finding_count = session.query(FindingRow).filter(FindingRow.scan_id == scan_id).count()
        session.commit()
    _drop_dismissed_from_files(scan_id, set(unique))
    return removed


def _dismissed_keys(session, scan_id: str) -> set[tuple[str, str]]:
    rows = session.query(DismissedFindingRow).filter(DismissedFindingRow.scan_id == scan_id).all()
    return {(item.fingerprint, item.correlation_key) for item in rows}


def _drop_dismissed_from_files(scan_id: str, keys: set[tuple[str, str]]) -> None:
    directory = DATA_DIR / "scans" / scan_id
    findings_path = directory / "findings.json"
    if findings_path.is_file():
        try:
            payload = json.loads(findings_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            payload = None
        if isinstance(payload, list):
            kept = [
                item
                for item in payload
                if isinstance(item, dict)
                and (str(item.get("fingerprint") or ""), str(item.get("correlation_key") or "")) not in keys
            ]
            findings_path.write_text(json.dumps(kept, indent=2, ensure_ascii=False), encoding="utf-8")
            meta_path = directory / "scan.json"
            if meta_path.is_file():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    meta = None
                if isinstance(meta, dict):
                    meta["findings"] = len(kept)
                    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")


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
        "source_repo_url": (
            row.source_repo_url
            or _source_from_meta(row.id, "source_repo_url")
            or infer_github_from_label(row.target_label)
        ),
        "source_ref": row.source_ref or _source_from_meta(row.id, "source_ref") or "main",
    }


def _source_from_meta(scan_id: str, key: str) -> str | None:
    path = DATA_DIR / "scans" / scan_id / "scan.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        value = payload.get(key)
        return value if isinstance(value, str) and value.strip() else None
    except (json.JSONDecodeError, OSError):
        return None
