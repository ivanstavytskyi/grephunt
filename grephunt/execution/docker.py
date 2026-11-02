"""Run one tool in its own container.

Project code is mounted read-only. Network, user, and limits come from
the RunRequest built from the tool descriptor.
"""
from __future__ import annotations

import asyncio
import contextlib
import shutil
import subprocess
import time

from grephunt.execution.request import RunOutcome, RunRequest

# Windows Docker Desktop sometimes leaves scanner containers in Created forever.
_STARTUP_STUCK_SEC = 90
_DOCKER_CMD_TIMEOUT = 15
_PURGE_RM_TIMEOUT = 15


class _StartupFailed(Exception):
    pass


def _ascii_tail(text: str, limit: int = 500) -> str:
    """Keep daemon text that is ASCII. Localized OS errors must not reach the UI."""
    lines = [line.strip() for line in text.splitlines() if line.strip() and line.strip().isascii()]
    return "\n".join(lines)[-limit:]


def docker_daemon_ready(timeout_sec: float = _DOCKER_CMD_TIMEOUT) -> tuple[bool, str]:
    """Quick ping. Returns (ok, detail)."""
    if not shutil.which("docker"):
        return False, "docker CLI not found on PATH"
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "Docker did not respond in time (daemon may be wedged; restart Docker Desktop)"
    except OSError as exc:
        return False, str(exc)
    if proc.returncode != 0:
        tail = _ascii_tail(proc.stderr or proc.stdout or "docker info failed")
        return False, tail or "Docker is not running"
    version = (proc.stdout or "").strip()
    return True, version or "ok"


def purge_stale_grephunt_containers() -> int:
    """Drop leftover grephunt-* containers from interrupted or wedged runs."""
    if not shutil.which("docker"):
        return 0
    try:
        listed = subprocess.run(
            ["docker", "ps", "-aq", "--filter", "name=grephunt-"],
            capture_output=True,
            text=True,
            timeout=_DOCKER_CMD_TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return 0
    ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    removed = 0
    for container_id in ids:
        try:
            proc = subprocess.run(
                ["docker", "rm", "-f", container_id],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_PURGE_RM_TIMEOUT,
                check=False,
            )
            if proc.returncode == 0:
                removed += 1
        except (subprocess.TimeoutExpired, OSError):
            continue
    return removed


def _startup_failure(status: str | None) -> str:
    if status == "created":
        hint = "stuck in Created"
    elif status is None:
        hint = "never reported Running (Docker may be wedged)"
    else:
        hint = f"state was {status!r}"
    return (
        f"Docker did not start the scanner container in {_STARTUP_STUCK_SEC}s ({hint}). "
        "Restart Docker Desktop, then run: grephunt doctor"
    )


async def _container_status(name: str) -> str | None:
    try:
        process = await asyncio.create_subprocess_exec(
            "docker",
            "inspect",
            "-f",
            "{{.State.Status}}",
            name,
            stdout=asyncio.subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=15)
    except (asyncio.TimeoutError, OSError):
        return None
    if process.returncode != 0:
        return None
    return stdout.decode(errors="replace").strip().lower() or None


async def _watch_container_startup(name: str, run_started: float) -> str | None:
    while True:
        await asyncio.sleep(3)
        status = await _container_status(name)
        if status == "running":
            return None
        if status in {"exited", "dead"}:
            return "scanner container exited before the run finished"
        if time.monotonic() - run_started >= _STARTUP_STUCK_SEC:
            return _startup_failure(status)


class DockerRunner:
    def __init__(self) -> None:
        self._ready: set[str] = set()

    def available(self) -> bool:
        return shutil.which("docker") is not None

    async def ensure_image(self, image: str) -> str | None:
        if image in self._ready:
            return None
        if ":" not in image or image.endswith(":latest"):
            return f"image {image} is not pinned to a version"
        check = await asyncio.create_subprocess_exec(
            "docker", "image", "inspect", image,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, err = await check.communicate()
        if check.returncode == 0:
            self._ready.add(image)
            return None
        err_text = err.decode(errors="replace")
        if "No such image" not in err_text and "not found" not in err_text.lower():
            return "Docker is not running, or the daemon is not reachable."
        pull = await asyncio.create_subprocess_exec(
            "docker", "pull", image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        output, _ = await pull.communicate()
        if pull.returncode != 0:
            tail = _ascii_tail(output.decode(errors="replace"))
            detail = f"\n{tail}" if tail else ""
            return f"failed to pull image {image} (exit {pull.returncode}){detail}"
        self._ready.add(image)
        return None

    async def image_version(self, image: str) -> str | None:
        """Version from the image tag. The latest tag is rejected."""
        tag = image.rsplit(":", 1)[-1]
        if tag and tag != "latest":
            return tag
        return None

    def _command(self, request: RunRequest) -> list[str]:
        command = ["docker", "run", "--rm", "--name", request.container_name, "--entrypoint", request.binary]
        if request.network:
            command += ["--network", "bridge"]
        else:
            command += ["--network", "none"]
        if request.user:
            user = request.user if ":" in request.user else f"{request.user}:{request.user}"
            command += ["--user", user]
        command += [
            "--cpus", request.cpus,
            "--memory", request.memory,
            "--pids-limit", str(request.pids_limit),
            "--tmpfs", "/tmp:rw,exec,nosuid,size=512m",
        ]
        for cap in request.cap_drop:
            command += ["--cap-drop", cap]
        if request.no_new_privileges:
            command += ["--security-opt", "no-new-privileges:true"]
        for key, value in request.environment.items():
            command += ["-e", f"{key}={value}"]
        for host, container, read_only in request.binds:
            mode = "ro" if read_only else "rw"
            command += ["-v", f"{host}:{container}:{mode}"]
        for volume, container in request.volumes:
            command += ["-v", f"{volume}:{container}"]
        if request.workdir:
            command += ["-w", request.workdir]
        command.append(request.image or "")
        command.extend(request.args)
        return command

    def stop(self, container_name: str) -> None:
        if not container_name:
            return
        try:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_PURGE_RM_TIMEOUT,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            return

    async def run(self, request: RunRequest) -> RunOutcome:
        if not request.image:
            return RunOutcome(returncode=None, error="Docker run has no image")
        ok, detail = await asyncio.to_thread(docker_daemon_ready)
        if not ok:
            return RunOutcome(returncode=None, error=detail)
        if error := await self.ensure_image(request.image):
            return RunOutcome(returncode=None, error=error)

        command = self._command(request)
        run_started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        communicate = asyncio.create_task(process.communicate())
        startup = asyncio.create_task(_watch_container_startup(request.container_name, run_started))
        return await self._finish_run(request, process, communicate, startup, run_started)

    async def _finish_run(
        self,
        request: RunRequest,
        process: asyncio.subprocess.Process,
        communicate: asyncio.Task,
        startup: asyncio.Task,
        started: float,
    ) -> RunOutcome:

        async def _wait_run() -> tuple[bytes, bytes]:
            finished, _pending = await asyncio.wait(
                {communicate, startup},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if startup in finished:
                message = startup.result()
                if message:
                    communicate.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await communicate
                    if process.returncode is None:
                        process.kill()
                    self.stop(request.container_name)
                    await process.wait()
                    raise _StartupFailed(message)
                return await communicate
            startup.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await startup
            return communicate.result()

        try:
            stdout, stderr = await asyncio.wait_for(_wait_run(), timeout=request.timeout_sec)
        except _StartupFailed as exc:
            return RunOutcome(returncode=None, error=str(exc))
        except asyncio.TimeoutError:
            communicate.cancel()
            startup.cancel()
            process.kill()
            self.stop(request.container_name)
            await process.wait()
            return RunOutcome(
                returncode=None,
                timed_out=True,
                error=f"timed out after {request.timeout_sec}s",
            )
        except asyncio.CancelledError:
            communicate.cancel()
            startup.cancel()
            if process.returncode is None:
                process.kill()
            self.stop(request.container_name)
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except BaseException:
                pass
            raise

        text_out = stdout.decode(errors="replace")
        text_err = stderr.decode(errors="replace")
        return RunOutcome(
            returncode=process.returncode,
            stdout=text_out,
            stderr=text_err,
            error=None if process.returncode == 0 else f"exit code {process.returncode} after {time.monotonic() - started:.0f}s",
        )
