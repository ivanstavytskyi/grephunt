"""Run a process on the machine where the scanner CLI is installed."""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import sysconfig
import time
from pathlib import Path

from grephunt.execution.request import RunOutcome, RunRequest


def resolve_binary(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    dirs = {Path(sys.executable).parent, Path(sys.executable).parent / "Scripts"}
    for scheme in (None, f"{os.name}_user"):
        try:
            scripts = sysconfig.get_path("scripts", scheme) if scheme else sysconfig.get_path("scripts")
            dirs.add(Path(scripts))
        except (KeyError, TypeError):
            pass
    return shutil.which(name, path=os.pathsep.join(str(directory) for directory in dirs if directory.is_dir()))


class LocalRunner:
    def available(self, binary: str) -> bool:
        return resolve_binary(binary) is not None

    async def run(self, request: RunRequest) -> RunOutcome:
        binary = resolve_binary(request.binary) or request.binary
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            binary,
            *request.args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=request.timeout_sec)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return RunOutcome(returncode=None, timed_out=True, error=f"timed out after {request.timeout_sec}s")
        except asyncio.CancelledError:
            if process.returncode is None:
                process.kill()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except BaseException:
                pass
            raise
        return RunOutcome(
            returncode=process.returncode,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            error=None if process.returncode == 0 else f"exit code {process.returncode} after {time.monotonic() - started:.0f}s",
        )
