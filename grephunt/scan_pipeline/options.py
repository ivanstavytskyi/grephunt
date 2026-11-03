"""Options for one scan, shared by every tool."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ScanOptions(BaseModel):
    configs: list[str] = Field(default_factory=lambda: ["p/default"])
    excludes: list[str] = Field(default_factory=list)
    trivy_scanners: list[str] = Field(default_factory=lambda: ["vuln", "secret", "misconfig"])
    use_docker: bool = True
    tenant_id: str = "local"
    target_kind: Literal["source", "image"] = "source"
    """image: the target is a container image tar (docker save or OCI layout), not a folder."""
    image_format: Literal["docker", "oci"] = "docker"
