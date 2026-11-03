"""YAML descriptor schema. The core reads it and does not know which scanner it is."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from grephunt.finding_model.record import Category, Module


class CacheVolume(BaseModel):
    name: str
    path: str
    read_only: bool = False
    """The scan only reads it. A prepare step fills it."""


class PrepareStep(BaseModel):
    """A run before the scan that fills a cache: a vulnerability database, a rule pack, a tool install.

    It runs in the scanner image with the cache volumes writable. A marker in
    the cache records the run, so later scans skip it until ttl_hours passes.
    """

    args: list[str]
    binary: str | None = None
    """Entrypoint for this step. Defaults to the scan entrypoint."""
    cache: str
    """Name of the cache volume that holds the marker."""
    network: bool = True
    ttl_hours: int | None = None
    """Refresh period. None means the data never goes stale (a pinned install)."""
    docker_only: bool = False
    """Skip in --local mode, where the tool and its data are already installed."""
    timeout_sec: int = 900


class ToolDescriptor(BaseModel):
    name: str
    module: Module = Module.SAST
    binary: str
    container_binary: str | None = None
    """Entrypoint in the image when it differs from the binary name on a local machine."""
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
    produced_output: str | None = None
    """File name under the scan output directory when the tool does not write output_filename directly."""
    raw_output_filename: str | None = None
    """The file the tool writes when it cannot write SARIF itself. The hook converts it to output_filename."""
    rules_version: str | None = None
    """Pinned version of a rule pack that the hook downloads before the scan."""
    args: list[str] | None = None
    """Argument template for tools without a Python hook.

    Placeholders: {src} project, {output} the file the tool writes, {out_dir},
    {cache:NAME} a cache volume, {catalog} this directory (read-only).
    """
    image_args: list[str] | None = None
    """Argument template for a container image tar. {src} is the tar file, {image_ref} is
    docker-archive:<tar> or oci-archive:<tar>. Without it the tool skips image scans."""
    output_source: Literal["file", "stdout"] = "file"
    """stdout: the core saves the tool output to the file instead of the tool."""
    output_format: str = "sarif"
    """sarif, or the name of a converter in scan_pipeline/converters.py."""
    applies_to: list[str] = Field(default_factory=list)
    """File name globs. The tool is skipped when no file in the project matches. Empty means always."""
    prepare: PrepareStep | None = None
    category: Category | None = None
    """Category for every finding of this tool, when its rules do not say (secret scanners)."""
    trust_reported_version: bool = True
    """False when the tool writes a fixed version into SARIF (Gitleaks and Betterleaks write v8.0.0)."""
    skip_exit_codes: list[int] = Field(default_factory=list)
    """Exit codes that mean "nothing here to scan" (Snyk: 3). The task is skipped, not failed."""
    default_enabled: bool = True
    """False: the scanner runs only when it is selected by name (CLI -s, or the console)."""
    cloud: bool = False
    """True: the scan sends project data to the vendor's service. Shown in the console."""
    ok_exit_codes: list[int] | None = None
    """Exit codes of a finished scan. Any other code fails the task even if a report was written,
    because some tools write an empty report when they could not load their database."""
    severity_property: str | None = None
    """SARIF property (on the result or its rule) that holds the tool's own severity word."""
    severity_map: dict[str, str] = Field(default_factory=dict)
    """Tool severity word (any case) -> critical, high, medium, low, or info."""
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

    @model_validator(mode="after")
    def converted_output_has_a_raw_file(self) -> "ToolDescriptor":
        from grephunt.scan_pipeline.converters import CONVERTERS

        if self.output_format != "sarif" and self.output_format not in CONVERTERS:
            raise ValueError(f"{self.name}: unknown output_format {self.output_format}")
        if self.output_format != "sarif" and not self.raw_output_filename:
            raise ValueError(f"{self.name}: output_format {self.output_format} needs raw_output_filename")
        unified = {"critical", "high", "medium", "low", "info"}
        bad = sorted(value for value in self.severity_map.values() if value not in unified)
        if bad:
            raise ValueError(f"{self.name}: severity_map values must be one of {sorted(unified)}, not {bad}")
        names = {volume.name for volume in self.cache_volumes}
        if self.prepare is not None and self.prepare.cache not in names:
            raise ValueError(f"{self.name}: prepare.cache {self.prepare.cache} is not in cache_volumes")
        return self

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
