"""Pipeline: tool tasks, parse, filter, correlate, events."""
from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

from grephunt.finding_model.correlation import correlate
from grephunt.finding_model.record import Finding, ScanResult, TaskRun, TaskStatus
from grephunt.scan_pipeline.dependency_scope import is_unreferenced_dependency, suppressed_packages
from grephunt.scan_pipeline.events import EventHandler, EventType, ScanEvent, emit
from grephunt.scan_pipeline.noise import is_noise
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.excludes import SECRET_KEPT_PATTERNS, is_excluded
from grephunt.scan_pipeline.scan_view import needs_full_project
from grephunt.report_output.sarif_export import merge_sarif_files


def accept_finding(finding: Finding, options: ScanOptions, suppressed: set[str]) -> bool:
    """False for ignored paths, known-noisy rules, and npm packages the app does not use."""
    patterns = options.excludes
    if getattr(finding.category, "value", finding.category) == "secret":
        # A key in a bundle under dist or build ships to every visitor: keep those findings.
        patterns = [pattern for pattern in patterns if pattern not in SECRET_KEPT_PATTERNS]
    if is_excluded(finding.location.path or "", patterns):
        return False
    if is_noise(finding):
        return False
    if is_unreferenced_dependency(finding, suppressed):
        return False
    return True


def emit_tool_findings(
    on_event: EventHandler | None,
    run: TaskRun,
    options: ScanOptions,
    project: Path | None = None,
) -> dict[str, int]:
    """Publish the findings that pass the filters. Returns how many were accepted, by severity."""
    accepted: dict[str, int] = {}
    if run.status is not TaskStatus.SUCCESS or not run.findings:
        return accepted
    suppressed = suppressed_packages(project)
    for finding in run.findings:
        if not accept_finding(finding, options, suppressed):
            continue
        accepted[finding.severity.value] = accepted.get(finding.severity.value, 0) + 1
        where = finding.location.label or finding.rule_id
        emit(
            on_event,
            ScanEvent(
                type=EventType.FINDING_ACCEPTED,
                tool=finding.tool,
                message=f"{finding.severity.value} {where}",
                data={
                    "severity": finding.severity.value,
                    "fingerprint": finding.fingerprint,
                    "finding": finding.model_dump(mode="json"),
                },
            ),
        )
    return accepted


def _map_anchors(out_dir: Path) -> dict[str, set[int]]:
    """Database call lines from the project map built before the scanners, if there is one."""
    path = out_dir / "project_map.json"
    if not path.is_file():
        return {}
    try:
        from grephunt.project_map.finding_context import database_anchors

        return database_anchors(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return {}


async def _scan_view(project: Path, options: ScanOptions, on_event: EventHandler | None):
    """The project without build and dependency folders, when the rule is on and there is something to skip."""
    skip = options.effective_skip_dirs
    if not skip or options.target_kind != "source" or not project.is_dir():
        return None
    from grephunt.config import DATA_DIR
    from grephunt.scan_pipeline.scan_view import make_scan_view

    try:
        view = await asyncio.to_thread(make_scan_view, project, DATA_DIR / "tmp" / "scan-views", frozenset(skip))
    except OSError as exc:
        emit(on_event, ScanEvent(type=EventType.TASK_HEARTBEAT, message=f"could not prepare the filtered copy, scanning everything: {exc}"))
        return None
    if not view.skipped:
        await asyncio.to_thread(view.remove)
        return None
    shown = ", ".join(view.skipped[:8]) + (f" and {len(view.skipped) - 8} more" if len(view.skipped) > 8 else "")
    emit(
        on_event,
        ScanEvent(
            type=EventType.TASK_HEARTBEAT,
            message=f"skipping build and dependency folders ({view.skipped_files} files): {shown}",
            data={"skipped_dirs": view.skipped, "skipped_files": view.skipped_files, "kept_files": view.copied_files},
        ),
    )
    return view


async def run_scan(
    project: Path,
    out_dir: Path,
    tools: list,
    options: ScanOptions | None = None,
    on_event: EventHandler | None = None,
    scan_id: str | None = None,
) -> ScanResult:
    options = options or ScanOptions()
    scan_id = scan_id or uuid.uuid4().hex[:12]
    out_dir.mkdir(parents=True, exist_ok=True)
    view = await _scan_view(project, options, on_event)

    async def one(tool) -> TaskRun:
        target = project
        if view is not None and not needs_full_project(getattr(tool, "descriptor", None)):
            target = view.root
        try:
            return await tool.execute(target, out_dir, options, on_event)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            emit(
                on_event,
                ScanEvent(
                    type=EventType.TASK_FINISHED,
                    tool=getattr(tool, "name", "unknown"),
                    message=str(exc),
                    data={"status": TaskStatus.FAILED.value},
                ),
            )
            return TaskRun(tool=getattr(tool, "name", "unknown"), status=TaskStatus.FAILED, error=repr(exc))

    try:
        runs = list(await asyncio.gather(*(one(tool) for tool in tools)))
    finally:
        if view is not None:
            await asyncio.to_thread(view.remove)
    raw: list[Finding] = [finding for run in runs for finding in run.findings]
    suppressed = suppressed_packages(project)
    kept = [finding for finding in raw if accept_finding(finding, options, suppressed)]
    findings = correlate(kept, _map_anchors(out_dir))

    sarif_files = [run.sarif_path for run in runs if run.sarif_path and run.sarif_path.exists()]
    merged = merge_sarif_files(sarif_files, out_dir / "merged.sarif") if sarif_files else None
    result = ScanResult(
        id=scan_id,
        target=str(project),
        runs=runs,
        findings=findings,
        excluded=len(raw) - len(kept),
        raw_total=len(raw),
        merged_sarif=merged,
    )
    emit(
        on_event,
        ScanEvent(
            type=EventType.SCAN_FINISHED,
            message=f"{len(findings)} findings, {result.excluded} excluded",
            data={"findings": len(findings), "excluded": result.excluded, "raw_total": result.raw_total},
        ),
    )
    return result
