"""Options for one scan, shared by every tool."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class ScanOptions(BaseModel):
    params: dict[str, dict[str, Any]] = Field(default_factory=dict)
    excludes: list[str] = Field(default_factory=list)
    use_docker: bool = True
    tenant_id: str = "local"
    target_kind: Literal["source", "image"] = "source"
    """image: the target is a container image tar (docker save or OCI layout), not a folder."""
    image_format: Literal["docker", "oci"] = "docker"

    @model_validator(mode="before")
    @classmethod
    def _lift_legacy_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        params = dict(data.get("params") or {})
        if "configs" in data and data["configs"] is not None:
            semgrep = dict(params.get("semgrep") or {})
            semgrep["configs"] = data.pop("configs")
            params["semgrep"] = semgrep
        if "trivy_scanners" in data and data["trivy_scanners"] is not None:
            trivy = dict(params.get("trivy") or {})
            trivy["scanners"] = data.pop("trivy_scanners")
            params["trivy"] = trivy
        data["params"] = params
        return data

    @property
    def configs(self) -> list[str]:
        value = (self.params.get("semgrep") or {}).get("configs")
        if isinstance(value, list):
            cleaned = [str(item).strip() for item in value if str(item).strip()]
            if cleaned:
                return cleaned
        return ["p/default"]

    @property
    def trivy_scanners(self) -> list[str]:
        value = (self.params.get("trivy") or {}).get("scanners")
        if isinstance(value, list):
            cleaned = [str(item).strip().lower() for item in value if str(item).strip()]
            if cleaned:
                return cleaned
        return ["vuln", "secret", "misconfig"]
