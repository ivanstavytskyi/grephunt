"""Recover Docker and stale scanner containers on the local machine."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from grephunt.execution.docker import docker_daemon_ready, purge_stale_grephunt_containers


def _docker_desktop_paths() -> list[Path]:
    roots = [
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ]
    paths: list[Path] = []
    for root in roots:
        if not root:
            continue
        candidate = Path(root) / "Docker" / "Docker" / "Docker Desktop.exe"
        if candidate.is_file():
            paths.append(candidate)
    return paths


def restart_docker_desktop_windows() -> tuple[bool, str]:
    if os.name != "nt":
        return False, "automatic Docker restart is only supported on Windows"
    try:
        subprocess.run(
            ["wsl", "--shutdown"],
            capture_output=True,
            timeout=45,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        pass
    for image in ("Docker Desktop.exe", "com.docker.backend.exe", "com.docker.service"):
        subprocess.run(
            ["taskkill", "/F", "/IM", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
    launched = False
    for exe in _docker_desktop_paths():
        try:
            subprocess.Popen([str(exe)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            launched = True
            break
        except OSError:
            continue
    if not launched:
        return False, "Docker Desktop.exe was not found; start it manually from the Start menu"
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        ok, detail = docker_daemon_ready(timeout_sec=10)
        if ok:
            return True, f"Docker is up (server {detail})"
        time.sleep(5)
    return False, "Docker Desktop was started but the daemon did not respond within 3 minutes"


def run_doctor(*, restart_docker: bool = False) -> int:
    if restart_docker:
        if os.name != "nt":
            print("Use --restart-docker only on Windows.", file=sys.stderr)
            return 2
        print("Restarting Docker Desktop...")
        ok, detail = restart_docker_desktop_windows()
        print(detail)
        if not ok:
            return 1

    ok, detail = docker_daemon_ready(timeout_sec=10)
    print(f"Docker daemon: {'OK' if ok else 'NOT READY'} — {detail}")
    removed = purge_stale_grephunt_containers()
    print(f"Removed {removed} stale grephunt-* container(s)")
    if not ok:
        print("\nIf scans hang with 'running 15s' forever, restart Docker Desktop, then run:")
        print("  python -m grephunt doctor")
        return 1
    return 0
