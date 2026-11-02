"""Options for one scan, shared by every tool."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ScanOptions(BaseModel):
    configs: list[str] = Field(default_factory=lambda: ["p/default"])
    excludes: list[str] = Field(default_factory=list)
    trivy_scanners: list[str] = Field(default_factory=lambda: ["vuln", "secret", "misconfig"])
    use_docker: bool = True
    tenant_id: str = "local"
