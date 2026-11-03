"""A scanner is a descriptor plus a hook. The core calls execute and does not branch on the tool name."""
from __future__ import annotations

import contextlib
import json
import os
import time
import uuid
from pathlib import Path

from grephunt.finding_model.record import Category, Module, TaskRun, TaskStatus
from grephunt.finding_model.redaction import redact_sarif_file, secret_result_refs
from grephunt.scan_pipeline.image_archive import IMAGE_MOUNT
from grephunt.scan_pipeline.events import EventHandler, EventType, ScanEvent, emit, scan_event_scope
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.pipeline import emit_tool_findings
from grephunt.scan_pipeline.sarif import parse_sarif
from grephunt.execution.docker import DockerRunner
from grephunt.execution.local import LocalRunner, resolve_binary
from grephunt.execution.request import RunRequest
from grephunt.scanner_catalog.descriptor import ToolDescriptor

_HEARTBEAT_SEC = 15


class ScannerTool:
    def __init__(self, descriptor: ToolDescriptor, hook) -> None:
        self.descriptor = descriptor
        self.hook = hook
        self.docker = DockerRunner()
        self.local = LocalRunner()

    @property
    def name(self) -> str:
        return self.descriptor.name

    def _extra_environment(self, options: ScanOptions, use_docker: bool) -> dict[str, str]:
        extra = getattr(self.hook, "extra_environment", None)
        return dict(extra(options, use_docker)) if extra is not None else {}

    def is_applicable(self, project: Path) -> bool:
        return self.hook.is_applicable(project)

    def _available(self, options: ScanOptions) -> bool:
        if options.use_docker:
            return self.docker.available()
        return resolve_binary(self.descriptor.binary) is not None

    async def _heartbeat(
        self,
        started: float,
        on_event: EventHandler | None,
        *,
        phase: str,
        label: str,
    ) -> None:
        import asyncio

        while True:
            await asyncio.sleep(_HEARTBEAT_SEC)
            elapsed = time.monotonic() - started
            emit(
                on_event,
                ScanEvent(
                    type=EventType.TASK_HEARTBEAT,
                    tool=self.name,
                    message=f"{label} — {elapsed:.0f}s",
                    data={"elapsed_sec": round(elapsed, 1), "phase": phase},
                ),
            )

    async def execute(
        self,
        project: Path,
        out_dir: Path,
        options: ScanOptions,
        on_event: EventHandler | None = None,
    ) -> TaskRun:
        import asyncio

        with scan_event_scope(on_event):
            return await self._execute(project, out_dir, options, on_event)

    async def _execute(
        self,
        project: Path,
        out_dir: Path,
        options: ScanOptions,
        on_event: EventHandler | None,
    ) -> TaskRun:
        import asyncio

        emit(on_event, ScanEvent(type=EventType.TASK_QUEUED, tool=self.name, message="queued, waiting to start"))
        image_scan = options.target_kind == "image"
        if image_scan and not getattr(self.hook, "supports_image", lambda: False)():
            message = "does not scan container images"
            emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=message, data={"status": "skipped"}))
            return TaskRun(tool=self.name, status=TaskStatus.SKIPPED, error=message, image=self.descriptor.image)
        if not image_scan and not self.is_applicable(project):
            emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message="not applicable", data={"status": "skipped"}))
            return TaskRun(tool=self.name, status=TaskStatus.SKIPPED, error="not applicable", image=self.descriptor.image)

        if not self._available(options):
            hint = "install Docker Desktop, or run with --local" if options.use_docker else (
                f"install {self.descriptor.binary}, or omit --local"
            )
            emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=hint, data={"status": "failed"}))
            return TaskRun(tool=self.name, status=TaskStatus.FAILED, error=hint, image=self.descriptor.image)

        if options.use_docker:
            image_error = await self.docker.ensure_image(self.descriptor.image)
            if image_error:
                emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=image_error, data={"status": "failed"}))
                return TaskRun(tool=self.name, status=TaskStatus.FAILED, error=image_error, image=self.descriptor.image)
            emit(
                on_event,
                ScanEvent(
                    type=EventType.IMAGE_READY,
                    tool=self.name,
                    message=f"image {self.descriptor.image} is ready",
                    data={"image": self.descriptor.image, "version": self.descriptor.version},
                ),
            )
        else:
            emit(
                on_event,
                ScanEvent(type=EventType.IMAGE_READY, tool=self.name, message="local binary, no container image"),
            )

        prepare = getattr(self.hook, "prepare", None)
        if prepare is not None:
            prepare_started = time.monotonic()
            prepare_pulse = asyncio.create_task(
                self._heartbeat(
                    prepare_started,
                    on_event,
                    phase="prepare",
                    label=getattr(self.hook, "prepare_label", "preparing scanner data (cached when possible)"),
                )
            )
            try:
                prepare_error = await prepare(
                    self.descriptor,
                    self.docker if options.use_docker else self.local,
                    options.use_docker,
                )
            finally:
                prepare_pulse.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await prepare_pulse
            if prepare_error:
                emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=prepare_error, data={"status": "failed"}))
                return TaskRun(tool=self.name, status=TaskStatus.FAILED, error=prepare_error, image=self.descriptor.image)

        out_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(out_dir, 0o777)
        sarif_path = out_dir / self.descriptor.output_filename
        sarif_path.unlink(missing_ok=True)
        raw_path = out_dir / self.descriptor.raw_output_filename if self.descriptor.raw_output_filename else None
        if raw_path is not None:
            raw_path.unlink(missing_ok=True)
        container_name = f"grephunt-{self.name}-{uuid.uuid4().hex[:8]}"
        network = self.hook.wants_network(self.descriptor, options)

        if options.use_docker:
            src = IMAGE_MOUNT if image_scan else self.descriptor.target_mount
            output = f"{self.descriptor.output_mount}/{self.descriptor.output_filename}"
            binds: list[tuple[str, str, bool]] = [
                (str(project.resolve()), src, True),
                (str(out_dir.resolve()), self.descriptor.output_mount, False),
            ]
            for host, container in self.hook.extra_mounts(options, use_docker=True):
                binds.append((str(host.resolve()), container, True))
            from grephunt.execution.cache import cache_binds

            binds.extend(cache_binds(self.descriptor))
            request = RunRequest(
                image=self.descriptor.image,
                binary=self.descriptor.container_binary or self.descriptor.binary,
                args=self.hook.build_args(self.descriptor, src, output, options, True),
                container_name=container_name,
                network=network,
                user=self.descriptor.user,
                cpus=self.descriptor.cpus,
                memory=self.descriptor.memory,
                pids_limit=self.descriptor.pids_limit,
                binds=binds,
                environment={**self.descriptor.environment, **self._extra_environment(options, True)},
                timeout_sec=self.descriptor.timeout_sec,
                cap_drop=self.descriptor.cap_drop,
                no_new_privileges=self.descriptor.no_new_privileges,
                progress_tool=self.name,
            )
            emit(
                on_event,
                ScanEvent(
                    type=EventType.TASK_HEARTBEAT,
                    tool=self.name,
                    message="starting scan in Docker (large projects can take several minutes)",
                    data={"phase": "start"},
                ),
            )
            started = time.monotonic()
            heartbeat = asyncio.create_task(
                self._heartbeat(started, on_event, phase="scan", label="scanning project")
            )
            try:
                outcome = await self.docker.run(request)
            finally:
                heartbeat.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await heartbeat
        else:
            binary = resolve_binary(self.descriptor.binary) or self.descriptor.binary
            request = RunRequest(
                binary=binary,
                args=self.hook.build_args(self.descriptor, str(project), str(sarif_path), options, False),
                timeout_sec=self.descriptor.timeout_sec,
                network=network,
                environment=self._extra_environment(options, False),
            )
            started = time.monotonic()
            heartbeat = asyncio.create_task(
                self._heartbeat(started, on_event, phase="scan", label="scanning project")
            )
            try:
                outcome = await self.local.run(request)
            finally:
                heartbeat.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await heartbeat

        duration = time.monotonic() - started
        version = self.descriptor.version
        if outcome.timed_out:
            emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=outcome.error or "timeout", data={"status": "timeout"}))
            return TaskRun(
                tool=self.name, status=TaskStatus.TIMEOUT, duration_sec=duration,
                tool_version=version, image=self.descriptor.image, error=outcome.error,
            )
        if outcome.returncode in self.descriptor.skip_exit_codes and not sarif_path.exists() and not (raw_path and raw_path.exists()):
            message = "nothing to scan for this tool in the project"
            emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=message, data={"status": "skipped"}))
            return TaskRun(tool=self.name, status=TaskStatus.SKIPPED, duration_sec=duration, tool_version=version,
                           image=self.descriptor.image, error=message)

        allowed = self.descriptor.ok_exit_codes
        if allowed is not None and outcome.returncode not in allowed:
            raw_tail = outcome.stderr or outcome.stdout or outcome.error or ""
            ascii_lines = [line.strip() for line in raw_tail.splitlines() if line.strip() and line.strip().isascii()]
            tail = "\n".join(ascii_lines)[-2000:] or f"exit code {outcome.returncode}"
            message = f"exit code {outcome.returncode}: {tail.splitlines()[-1][:400]}"
            emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=message, data={"status": "failed"}))
            return TaskRun(
                tool=self.name, status=TaskStatus.FAILED, duration_sec=duration,
                tool_version=version, image=self.descriptor.image, error=tail,
            )

        if self.descriptor.output_source == "stdout" and outcome.stdout.strip():
            # Tools that print the report exit non-zero when they find something. The report still counts.
            (raw_path or sarif_path).write_text(outcome.stdout, encoding="utf-8")

        if not sarif_path.exists() and self.descriptor.produced_output:
            produced = out_dir / self.descriptor.produced_output
            if produced.is_file():
                produced.replace(sarif_path)

        convert = getattr(self.hook, "convert_output", None)
        if convert is not None and raw_path is not None and raw_path.exists():
            try:
                convert(raw_path, sarif_path, self.descriptor)
            except (OSError, ValueError) as exc:
                message = f"could not convert {raw_path.name} to SARIF: {exc}"
                emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=message, data={"status": "failed"}))
                return TaskRun(
                    tool=self.name, status=TaskStatus.FAILED, duration_sec=duration,
                    tool_version=version, image=self.descriptor.image, error=message,
                )

        if not sarif_path.exists():
            raw_tail = outcome.stderr or outcome.stdout or outcome.error or ""
            ascii_lines = [line.strip() for line in raw_tail.splitlines() if line.strip() and line.strip().isascii()]
            tail = "\n".join(ascii_lines)[-2000:] or (outcome.error or "SARIF was not created")
            summary = tail.splitlines()[-1][:500] if tail else "SARIF was not created"
            emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=summary, data={"status": "failed"}))
            return TaskRun(
                tool=self.name, status=TaskStatus.FAILED, duration_sec=duration,
                tool_version=version, image=self.descriptor.image, error=tail,
            )

        try:
            findings = parse_sarif(
                sarif_path,
                tool=self.name,
                project_root=project,
                module=Module(self.descriptor.module),
                fallback_version=version,
                refine=self.hook.refine_finding,
                trust_reported_version=self.descriptor.trust_reported_version,
            )
        except json.JSONDecodeError as exc:
            size = sarif_path.stat().st_size if sarif_path.is_file() else 0
            preview = sarif_path.read_text(encoding="utf-8", errors="replace")[:200].strip() if size else ""
            hint = "The scanner wrote an empty or non-JSON report file."
            if size == 0:
                hint = "The scanner did not write a SARIF report (empty output file)."
            message = f"{hint} ({exc.msg})"
            emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=message, data={"status": "failed"}))
            return TaskRun(
                tool=self.name,
                status=TaskStatus.FAILED,
                duration_sec=duration,
                tool_version=version,
                image=self.descriptor.image,
                error=f"{message}\n{preview}".strip(),
            )
        redact_sarif_file(sarif_path, secret_result_refs(findings))
        if raw_path is not None and self.descriptor.category is Category.SECRET:
            # The tool's own report holds the values. The converted, masked SARIF replaces it.
            raw_path.unlink(missing_ok=True)
        parsed_version = next((item.tool_version for item in findings if item.tool_version), version)
        finished = TaskRun(
            tool=self.name,
            status=TaskStatus.SUCCESS,
            duration_sec=duration,
            tool_version=parsed_version,
            image=self.descriptor.image,
            sarif_path=sarif_path,
            findings=findings,
        )
        emit_tool_findings(on_event, finished, options)
        emit(
            on_event,
            ScanEvent(
                type=EventType.TASK_FINISHED,
                tool=self.name,
                message=f"done, {len(findings)} findings",
                data={"status": "success", "findings": len(findings), "version": parsed_version},
            ),
        )
        return finished
