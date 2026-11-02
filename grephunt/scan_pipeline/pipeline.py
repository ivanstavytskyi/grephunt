"""Pipeline: tool tasks, parse, filter, correlate, events."""
from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from grephunt.finding_model.correlation import correlate
from grephunt.finding_model.record import Finding, ScanResult, TaskRun, TaskStatus
from grephunt.scan_pipeline.events import EventHandler, EventType, ScanEvent, emit
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.excludes import is_excluded
from grephunt.report_output.sarif_export import merge_sarif_files


def emit_tool_findings(on_event: EventHandler | None, run: TaskRun, options: ScanOptions) -> None:
    if run.status is not TaskStatus.SUCCESS or not run.findings:
        return
    for finding in run.findings:
        if is_excluded(finding.location.path or "", options.excludes):
            continue
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

    async def one(tool) -> TaskRun:
        try:
            return await tool.execute(project, out_dir, options, on_event)
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

    runs = list(await asyncio.gather(*(one(tool) for tool in tools)))
    raw: list[Finding] = [finding for run in runs for finding in run.findings]
    kept = [finding for finding in raw if not is_excluded(finding.location.path or "", options.excludes)]
    findings = correlate(kept)

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
