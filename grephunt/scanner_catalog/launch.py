"""A scanner is a descriptor plus a hook. The core calls execute and does not branch on the tool name."""
from __future__ import annotations

import contextlib
import json
import os
import re
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
from grephunt.execution.docker import DockerRunner, container_probe
from grephunt.execution.local import LocalRunner, resolve_binary
from grephunt.execution.request import RunRequest
from grephunt.scanner_catalog.descriptor import ToolDescriptor

_HEARTBEAT_SEC = 10
# The first container probe comes sooner, so the console shows the container state quickly.
_FIRST_PROBE_SEC = 4

_SNYK_CODE_DISABLED = (
    "Snyk Code is turned off for this Snyk organization (SNYK-CODE-0005). "
    "Enable Snyk Code in the organization settings, then scan again. "
    "GrepHunt still runs its own JavaScript rules for Angular XSS, XXE, zip slip, NoSQL $where, and unsafe YAML."
)


_HEAD_CHARS = 1500
_TAIL_CHARS = 2000
_KEY_LINE = re.compile(r"\b(fatal|panic|error|exception|killed|out of memory|failed|denied|timed? ?out)\b", re.IGNORECASE)


def _failure_text(raw: str, fallback: str) -> str:
    """The start and the end of a tool's output.

    Crashes put the cause first (a Go panic, a Java exception) and thousands of stack lines
    after it, so the end alone hides the reason.
    """
    lines = [line.strip() for line in (raw or "").splitlines() if line.strip() and line.strip().isascii()]
    text = "\n".join(lines)
    if not text:
        return fallback
    if len(text) <= _HEAD_CHARS + _TAIL_CHARS + 200:
        return text
    head = text[:_HEAD_CHARS].rsplit("\n", 1)[0]
    tail = text[-_TAIL_CHARS:].split("\n", 1)[-1]
    skipped = len(lines) - head.count("\n") - tail.count("\n") - 2
    return f"{head}\n… {max(skipped, 0)} lines skipped …\n{tail}"


def _failure_summary(text: str) -> str:
    """One line for the console: the first line that names the problem, else the last line."""
    lines = [line for line in text.splitlines() if line and not line.startswith("…")]
    for line in lines[:60]:
        if _KEY_LINE.search(line):
            return line[:400]
    return (lines[-1] if lines else text)[:400]


def _save_output(out_dir: Path, tool: str, outcome) -> None:
    """Full stdout and stderr of a failed run, next to the reports."""
    body = (outcome.stderr or "") + ("\n--- stdout ---\n" + outcome.stdout if outcome.stdout else "")
    if not body.strip():
        return
    with contextlib.suppress(OSError):
        (out_dir / f"{tool}.log").write_text(body[:20_000_000], encoding="utf-8", errors="replace")


def _explain_tool_failure(tool: str, tail: str) -> str:
    if tool == "snyk-code" and "SNYK-CODE-0005" in tail:
        return f"{_SNYK_CODE_DISABLED}\n{tail}"
    return tail


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
        container: str | None = None,
    ) -> None:
        import asyncio

        delay = _FIRST_PROBE_SEC if container else _HEARTBEAT_SEC
        while True:
            await asyncio.sleep(delay)
            delay = _HEARTBEAT_SEC
            elapsed = time.monotonic() - started
            data: dict = {"elapsed_sec": round(elapsed, 1), "phase": phase}
            message = f"{label} — {elapsed:.0f}s"
            if container:
                probe = await container_probe(container)
                if probe:
                    data["container"] = probe
                    usage = ", ".join(
                        part for part in (
                            probe.get("status"),
                            f"CPU {probe['cpu']}" if probe.get("cpu") else "",
                            f"mem {probe['memory']}" if probe.get("memory") else "",
                        ) if part
                    )
                    message = f"{message} (container {usage})"
            emit(
                on_event,
                ScanEvent(type=EventType.TASK_HEARTBEAT, tool=self.name, message=message, data=data),
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

        emit(
            on_event,
            ScanEvent(
                type=EventType.TASK_QUEUED,
                tool=self.name,
                message="queued, waiting to start",
                data={
                    "phase": "queued",
                    "mode": "docker" if options.use_docker else "local",
                    "cloud": self.descriptor.cloud,
                    "timeout_sec": self.descriptor.timeout_sec,
                },
            ),
        )
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
            emit(
                on_event,
                ScanEvent(
                    type=EventType.TASK_HEARTBEAT,
                    tool=self.name,
                    message=f"checking image {self.descriptor.image}",
                    data={"phase": "image", "image": self.descriptor.image},
                ),
            )
            image_error = await self.docker.ensure_image(self.descriptor.image)
            if image_error:
                emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=image_error, data={"status": "failed"}))
                return TaskRun(tool=self.name, status=TaskStatus.FAILED, error=image_error, image=self.descriptor.image)
            emit(
                on_event,
                ScanEvent(
                    type=EventType.IMAGE_READY,
                    tool=self.name,
                    message=(
                        f"image {self.descriptor.image} pulled in {self.docker.pulled[self.descriptor.image]:.0f}s"
                        if self.descriptor.image in self.docker.pulled
                        else f"image {self.descriptor.image} is ready (cached)"
                    ),
                    data={
                        "phase": "image",
                        "image": self.descriptor.image,
                        "version": self.descriptor.version,
                        "pulled": self.descriptor.image in self.docker.pulled,
                        "pull_sec": self.docker.pulled.get(self.descriptor.image),
                    },
                ),
            )
        else:
            emit(
                on_event,
                ScanEvent(
                    type=EventType.IMAGE_READY,
                    tool=self.name,
                    message="local binary, no container image",
                    data={"phase": "image", "version": self.descriptor.version},
                ),
            )

        prepare = getattr(self.hook, "prepare", None)
        if prepare is not None:
            prepare_started = time.monotonic()
            emit(
                on_event,
                ScanEvent(
                    type=EventType.TASK_HEARTBEAT,
                    tool=self.name,
                    message=getattr(self.hook, "prepare_label", "preparing scanner data (cached when possible)"),
                    data={"phase": "prepare"},
                ),
            )
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
                    message=f"starting container {container_name} (large projects can take several minutes)",
                    data={
                        "phase": "start",
                        "container": {
                            "name": container_name,
                            "status": "starting",
                            "image": self.descriptor.image,
                            "cpus_limit": self.descriptor.cpus,
                            "memory_limit": self.descriptor.memory,
                            "pids_limit": self.descriptor.pids_limit,
                            "network": "bridge" if network else "none",
                            "user": self.descriptor.user,
                        },
                    },
                ),
            )
            started = time.monotonic()
            heartbeat = asyncio.create_task(
                self._heartbeat(started, on_event, phase="scan", label="scanning project", container=container_name)
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
            emit(
                on_event,
                ScanEvent(
                    type=EventType.TASK_HEARTBEAT,
                    tool=self.name,
                    message=f"starting {binary}",
                    data={"phase": "start", "binary": str(binary)},
                ),
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
        exited: dict = {
            "phase": "parse",
            "exit_code": outcome.returncode,
            "run_sec": round(duration, 1),
            "stdout_bytes": len(outcome.stdout or ""),
            "stderr_bytes": len(outcome.stderr or ""),
        }
        if options.use_docker:
            exited["container"] = {
                "status": "killed" if outcome.timed_out else ("exited" if outcome.returncode is not None else "failed"),
                "exit_code": outcome.returncode,
            }
        emit(
            on_event,
            ScanEvent(
                type=EventType.TASK_HEARTBEAT,
                tool=self.name,
                message=(
                    f"timed out after {duration:.0f}s"
                    if outcome.timed_out
                    else f"scanner exited with code {outcome.returncode} after {duration:.0f}s, reading the report"
                ),
                data=exited,
            ),
        )
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
            _save_output(out_dir, self.name, outcome)
            tail = _failure_text(outcome.stderr or outcome.stdout or outcome.error or "", f"exit code {outcome.returncode}")
            tail = _explain_tool_failure(self.name, tail)
            report_ready = self.name == "snyk-code" and sarif_path.is_file() and sarif_path.stat().st_size > 2
            if not report_ready:
                message = f"exit code {outcome.returncode}: {_failure_summary(tail)}"
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
            _save_output(out_dir, self.name, outcome)
            tail = _failure_text(outcome.stderr or outcome.stdout or outcome.error or "", outcome.error or "SARIF was not created")
            summary = _failure_summary(tail)
            emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=summary, data={"status": "failed"}))
            return TaskRun(
                tool=self.name, status=TaskStatus.FAILED, duration_sec=duration,
                tool_version=version, image=self.descriptor.image, error=tail,
            )

        if (
            self.descriptor.empty_output_skips
            and sarif_path.is_file()
            and not sarif_path.read_bytes().strip()
        ):
            sarif_path.unlink(missing_ok=True)
            message = "nothing to scan for this tool in the project"
            emit(on_event, ScanEvent(type=EventType.TASK_FINISHED, tool=self.name, message=message, data={"status": "skipped"}))
            return TaskRun(tool=self.name, status=TaskStatus.SKIPPED, duration_sec=duration, tool_version=version,
                           image=self.descriptor.image, error=message)

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
        accepted = emit_tool_findings(on_event, finished, options, project)
        raw_severities: dict[str, int] = {}
        for item in findings:
            raw_severities[item.severity.value] = raw_severities.get(item.severity.value, 0) + 1
        accepted_total = sum(accepted.values())
        emit(
            on_event,
            ScanEvent(
                type=EventType.TASK_FINISHED,
                tool=self.name,
                message=f"done, {len(findings)} findings ({accepted_total} after filters)",
                data={
                    "status": "success",
                    "phase": "done",
                    "findings": len(findings),
                    "raw_findings": len(findings),
                    "raw_severities": raw_severities,
                    "accepted": accepted_total,
                    "severities": accepted,
                    "rules": len({item.rule_id for item in findings if item.rule_id}),
                    "files": len({item.location.path for item in findings if item.location.path}),
                    "sarif_bytes": sarif_path.stat().st_size if sarif_path.is_file() else 0,
                    "version": parsed_version,
                    "elapsed_sec": round(duration, 1),
                },
            ),
        )
        return finished
