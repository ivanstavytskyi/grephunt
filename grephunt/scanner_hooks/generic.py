"""Behavior read from the descriptor. A tool with this hook needs only a YAML file.

The YAML gives the argument template, where the output goes (a file or
stdout), its format (SARIF or a converter name), which projects the tool
applies to, and an optional prepare step that fills a cache.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import time
import uuid
from pathlib import Path, PurePosixPath

from grephunt.execution.cache import cache_dir
from grephunt.execution.request import RunRequest
from grephunt.finding_model.record import Finding, Severity
from grephunt.scan_pipeline.converters import convert
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scanner_catalog.descriptor import ToolDescriptor

CATALOG_DIR = Path(__file__).resolve().parents[1] / "scanner_catalog"
CATALOG_MOUNT = "/grephunt-catalog"
_PLACEHOLDER = re.compile(r"\{([a-z_]+)(?::([A-Za-z0-9_.-]+))?\}")
_SKIP_DIRS = {".git", "node_modules", "vendor", "bower_components", ".yarn", "__pycache__", ".venv", "venv", ".tox"}
_WALK_LIMIT = 200_000


def expand(template: list[str], values: dict[str, str], caches: dict[str, str]) -> list[str]:
    """Fill {name} and {cache:NAME} placeholders. An unknown placeholder is an error, not an empty string."""

    def one(match: re.Match) -> str:
        key, arg = match.group(1), match.group(2)
        if key == "cache":
            if arg not in caches:
                raise ValueError(f"unknown cache volume in arguments: {arg}")
            return caches[arg]
        if key not in values or arg is not None:
            raise ValueError(f"unknown placeholder in arguments: {match.group(0)}")
        return values[key]

    return [_PLACEHOLDER.sub(one, item) for item in template]


def project_matches(project: Path, globs: list[str]) -> bool:
    """True when a file name in the project matches one of the globs (case-insensitive)."""
    if not globs:
        return True
    patterns = [glob.lower() for glob in globs]
    seen = 0
    for root, dirs, files in os.walk(project):
        dirs[:] = [name for name in dirs if name not in _SKIP_DIRS]
        relative = Path(root).relative_to(project)
        for name in files:
            lowered = name.lower()
            path = (relative / name).as_posix().lower()
            if any(fnmatch.fnmatch(lowered, pattern) or fnmatch.fnmatch(path, pattern) for pattern in patterns):
                return True
            seen += 1
            if seen >= _WALK_LIMIT:
                return True
    return False


def _uses_catalog(template: list[str] | None) -> bool:
    return bool(template) and any("{catalog}" in item for item in template)


def _marker(descriptor: ToolDescriptor) -> Path:
    assert descriptor.prepare is not None
    return cache_dir(descriptor.prepare.cache) / f".grephunt-{descriptor.name}-{descriptor.version}.json"


def prepared_recently(descriptor: ToolDescriptor, now: float | None = None) -> bool:
    marker = _marker(descriptor)
    if not marker.is_file():
        return False
    ttl = descriptor.prepare.ttl_hours if descriptor.prepare else None
    if ttl is None:
        return True
    try:
        stamp = float(json.loads(marker.read_text(encoding="utf-8")).get("at", 0))
    except (OSError, ValueError, AttributeError):
        return False
    return (now or time.time()) - stamp < ttl * 3600


class GenericHook:
    prepare_label = "preparing scanner data (cached when possible)"

    def __init__(self, descriptor: ToolDescriptor) -> None:
        self.descriptor = descriptor
        self.name = descriptor.name

    def is_applicable(self, project: Path) -> bool:
        return project_matches(project, self.descriptor.applies_to)

    def wants_network(self, descriptor: ToolDescriptor, options: ScanOptions) -> bool:
        return descriptor.network

    def extra_mounts(self, options: ScanOptions, use_docker: bool) -> list[tuple[Path, str]]:
        if use_docker and _uses_catalog(self.descriptor.args):
            return [(CATALOG_DIR, CATALOG_MOUNT)]
        return []

    def _caches(self, descriptor: ToolDescriptor, use_docker: bool) -> dict[str, str]:
        if use_docker:
            return {volume.name: volume.path for volume in descriptor.cache_volumes}
        return {volume.name: str(cache_dir(volume.name)) for volume in descriptor.cache_volumes}

    def build_args(self, descriptor: ToolDescriptor, src: str, output: str, options: ScanOptions, use_docker: bool) -> list[str]:
        if descriptor.args is None:
            raise ValueError(f"{descriptor.name}.yaml has no args and no Python hook")
        path_type = PurePosixPath if use_docker else Path
        written = output
        if descriptor.raw_output_filename:
            written = str(path_type(output).with_name(descriptor.raw_output_filename))
        values = {
            "src": src,
            "output": written,
            "out_dir": str(path_type(output).parent),
            "catalog": CATALOG_MOUNT if use_docker else str(CATALOG_DIR),
        }
        return expand(descriptor.args, values, self._caches(descriptor, use_docker))

    async def prepare(self, descriptor: ToolDescriptor, runner, use_docker: bool) -> str | None:
        step = descriptor.prepare
        if step is None or (step.docker_only and not use_docker):
            return None
        if prepared_recently(descriptor):
            return None
        marker = _marker(descriptor)
        values = {"catalog": CATALOG_MOUNT if use_docker else str(CATALOG_DIR)}
        try:
            args = expand(step.args, values, self._caches(descriptor, use_docker))
        except ValueError as exc:
            return str(exc)
        if use_docker:
            binds: list[tuple[str, str, bool]] = []
            for volume in descriptor.cache_volumes:
                host = cache_dir(volume.name)
                if os.name != "nt":
                    os.chmod(host, 0o777)
                binds.append((str(host.resolve()), volume.path, False))
            if _uses_catalog(step.args):
                binds.append((str(CATALOG_DIR), CATALOG_MOUNT, True))
            request = RunRequest(
                image=descriptor.image,
                binary=step.binary or descriptor.container_binary or descriptor.binary,
                args=args,
                container_name=f"grephunt-{descriptor.name}-prepare-{uuid.uuid4().hex[:8]}",
                network=step.network,
                user=descriptor.user,
                cpus=descriptor.cpus,
                memory=descriptor.memory,
                pids_limit=descriptor.pids_limit,
                binds=binds,
                environment=descriptor.environment,
                timeout_sec=step.timeout_sec,
                cap_drop=descriptor.cap_drop,
                no_new_privileges=descriptor.no_new_privileges,
                progress_tool=descriptor.name,
            )
        else:
            from grephunt.execution.local import resolve_binary

            request = RunRequest(
                binary=resolve_binary(descriptor.binary) or descriptor.binary,
                args=args,
                timeout_sec=step.timeout_sec,
                network=step.network,
            )
        outcome = await runner.run(request)
        if outcome.returncode == 0:
            marker.write_text(json.dumps({"at": time.time(), "version": descriptor.version}), encoding="utf-8")
            return None
        if marker.is_file():
            # The refresh failed, but data from an earlier run is there. A stale database beats no scan.
            return None
        tail = (outcome.stderr or outcome.stdout or outcome.error or "prepare step failed")[-1500:]
        return f"{descriptor.name}: prepare step failed\n{tail}".strip()

    def convert_output(self, raw_path: Path, sarif_path: Path, descriptor: ToolDescriptor) -> None:
        sarif = convert(descriptor.output_format, raw_path.read_text(encoding="utf-8", errors="replace"), descriptor)
        sarif_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")

    def refine_finding(self, finding: Finding, result: dict, rule: dict) -> Finding:
        prop = self.descriptor.severity_property
        if prop:
            value = (result.get("properties") or {}).get(prop) or (rule.get("properties") or {}).get(prop)
            if isinstance(value, str) and value:
                mapping = {key.lower(): target for key, target in self.descriptor.severity_map.items()}
                update: dict = {"severity_original": value}
                if value.lower() in mapping:
                    update["severity"] = Severity(mapping[value.lower()])
                return finding.model_copy(update=update)
        original = (result.get("properties") or {}).get("tool-severity")
        if isinstance(original, str) and original:
            return finding.model_copy(update={"severity_original": original})
        return finding
