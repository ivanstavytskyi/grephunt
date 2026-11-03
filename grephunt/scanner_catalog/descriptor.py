"""YAML descriptor schema. The core reads it and does not know which scanner it is."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from grephunt.finding_model.record import Module


class CacheVolume(BaseModel):
    name: str
    path: str
    read_only: bool = False
    """The scan only reads it. A prepare step on the host fills it."""


class ToolDescriptor(BaseModel):
    name: str
    module: Module = Module.SAST
    binary: str
    image: str
    version: str
    timeout_sec: int = 1200
    network: bool = False
    prepare_network: bool = False
    user: str | None = None
    cpus: str = "1"
    memory: str = "1g"
    pids_limit: int = 512
    output_filename: str
    raw_output_filename: str | None = None
    """The file the tool writes when it cannot write SARIF itself. The hook converts it to output_filename."""
    rules_version: str | None = None
    """Pinned version of a rule pack that the hook downloads before the scan."""
    target_mount: str = "/src"
    output_mount: str = "/out"
    cache_volumes: list[CacheVolume] = Field(default_factory=list)
    environment: dict[str, str] = Field(default_factory=dict)
    cap_drop: list[str] = Field(default_factory=lambda: ["ALL"])
    no_new_privileges: bool = True

    @field_validator("image")
    @classmethod
    def image_is_pinned(cls, value: str) -> str:
        tag = value.rsplit(":", 1)[-1] if ":" in value else ""
        if not tag or tag.startswith("latest"):
            raise ValueError(f"image {value} must be pinned to a version tag, not latest")
        return value

    @field_validator("version")
    @classmethod
    def version_is_pinned(cls, value: str) -> str:
        if not value or value.lower() == "latest":
            raise ValueError("version cannot be latest")
        return value

    @field_validator("rules_version")
    @classmethod
    def rules_version_is_pinned(cls, value: str | None) -> str | None:
        if value is not None and (not value or value.lower().startswith("latest")):
            raise ValueError("rules_version must be a release tag, not latest")
        return value
