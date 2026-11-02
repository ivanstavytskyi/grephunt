"""A run description executed by a runner. The tool does not know where it runs."""
from __future__ import annotations

from pydantic import BaseModel, Field


class RunRequest(BaseModel):
    image: str | None = None
    binary: str
    args: list[str]
    container_name: str = ""
    network: bool = False
    user: str | None = None
    cpus: str = "1"
    memory: str = "1g"
    pids_limit: int = 512
    binds: list[tuple[str, str, bool]] = Field(default_factory=list)
    """(host path, container path, read-only)."""
    volumes: list[tuple[str, str]] = Field(default_factory=list)
    """(volume name, container path)."""
    environment: dict[str, str] = Field(default_factory=dict)
    timeout_sec: int = 1200
    progress_tool: str | None = None
    cap_drop: list[str] = Field(default_factory=lambda: ["ALL"])
    no_new_privileges: bool = True
    workdir: str | None = None


class RunOutcome(BaseModel):
    returncode: int | None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
