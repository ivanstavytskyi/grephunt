"""YAML descriptor schema. The core reads it and does not know which scanner it is."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from grephunt.finding_model.record import Module


class CacheVolume(BaseModel):
    name: str
    path: str


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
    target_mount: str = "/src"
    output_mount: str = "/out"
    cache_volumes: list[CacheVolume] = Field(default_factory=list)
    environment: dict[str, str] = Field(default_factory=dict)
    cap_drop: list[str] = Field(default_factory=lambda: ["ALL"])
    no_new_privileges: bool = True

    @field_validator("image")
    @classmethod
    def image_is_pinned(cls, value: str) -> str:
        if ":" not in value or value.endswith(":latest"):
            raise ValueError(f"image {value} must be pinned to a version tag, not latest")
        return value

    @field_validator("version")
    @classmethod
    def version_is_pinned(cls, value: str) -> str:
        if not value or value.lower() == "latest":
            raise ValueError("version cannot be latest")
        return value
