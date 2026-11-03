"""Bearer-specific behavior: a pinned rule pack, offline scans, and JSON to SARIF.

Bearer looks up the newest rule pack on GitHub at every scan. That needs the
network and makes results depend on the day of the scan. Here the pack version
is pinned in bearer.yaml, downloaded once on the host, and mounted read-only.
The scan runs with --disable-default-rules and --external-rule-dir.

Bearer SARIF has no CWE, severity, or code snippet. The JSON report has all
three, so the scan writes JSON and convert_output turns it into SARIF.
"""
from __future__ import annotations

import io
import json
import os
import shutil
import tarfile
import urllib.error
import urllib.request
import uuid
from pathlib import Path, PurePosixPath

from grephunt.execution.cache import cache_dir
from grephunt.finding_model.record import Finding
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scanner_catalog.descriptor import ToolDescriptor

RULES_CACHE = "grephunt-bearer-rules"
RULES_URL = "https://github.com/Bearer/bearer-rules/releases/download/{version}/{language}.tar.gz"
LANGUAGES = ("go", "java", "javascript", "php", "python", "ruby")
EXTENSIONS = {
    ".go", ".java",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".php", ".py", ".rb", ".erb",
}
_COMPLETE = ".complete"
_MAX_PACK_BYTES = 20_000_000
_MAX_RULE_BYTES = 1_000_000
_WALK_LIMIT = 200_000
_SKIP_DIRS = {".git", "node_modules", "vendor", "bower_components", ".yarn", "__pycache__", ".venv", "venv"}
# Bearer still parses these trees and runs out of memory on large JS apps. Trivy covers dependencies.
_ALWAYS_SKIP = ("node_modules", "vendor", "bower_components", ".yarn")

# Bearer severity -> (unified severity, SARIF level, security-severity).
_SEVERITY = {
    "critical": ("critical", "error", "9.5"),
    "high": ("high", "error", "8.0"),
    "medium": ("medium", "warning", "5.5"),
    "low": ("low", "note", "3.0"),
    "warning": ("info", "none", "0.0"),
}


def rules_dir(descriptor: ToolDescriptor) -> Path:
    """Host directory of the pinned rule pack."""
    return cache_dir(RULES_CACHE) / str(descriptor.rules_version)


def _rules_mount(descriptor: ToolDescriptor) -> str | None:
    for volume in descriptor.cache_volumes:
        if volume.name == RULES_CACHE:
            return volume.path
    return None


def _safe_members(archive: tarfile.TarFile) -> list[tuple[tarfile.TarInfo, PurePosixPath]]:
    members: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
    for info in archive.getmembers():
        if info.isdir():
            continue
        name = PurePosixPath(info.name.replace("\\", "/"))
        if not info.isfile() or name.is_absolute() or ".." in name.parts:
            raise ValueError(f"unexpected entry in the rule pack: {info.name}")
        if name.suffix not in {".yml", ".yaml"}:
            continue
        if info.size > _MAX_RULE_BYTES:
            raise ValueError(f"rule file is too large: {info.name}")
        members.append((info, name))
    return members


def _download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "GrepHunt"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(_MAX_PACK_BYTES + 1)
    if len(data) > _MAX_PACK_BYTES:
        raise ValueError(f"rule pack is larger than {_MAX_PACK_BYTES // 1_000_000} MB: {url}")
    return data


def install_rules(descriptor: ToolDescriptor, fetch=_download) -> Path:
    """Download and unpack the pinned rule pack once. Later scans reuse it without the network."""
    target = rules_dir(descriptor)
    if (target / _COMPLETE).is_file():
        return target
    staging = target.parent / f".{target.name}-{uuid.uuid4().hex[:8]}"
    staging.mkdir(parents=True)
    try:
        for language in LANGUAGES:
            url = RULES_URL.format(version=descriptor.rules_version, language=language)
            blob = fetch(url)
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
                for info, name in _safe_members(archive):
                    destination = staging.joinpath(*name.parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(info)
                    if source is None:
                        continue
                    with source, destination.open("wb") as sink:
                        shutil.copyfileobj(source, sink)
        (staging / _COMPLETE).write_text(str(descriptor.rules_version), encoding="utf-8")
        try:
            os.replace(staging, target)
        except OSError:
            # Another scan finished the same download first.
            if not (target / _COMPLETE).is_file():
                if target.exists():
                    shutil.rmtree(target, ignore_errors=True)
                os.replace(staging, target)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    return target


def has_supported_files(project: Path) -> bool:
    seen = 0
    for _root, dirs, files in os.walk(project):
        dirs[:] = [name for name in dirs if name not in _SKIP_DIRS]
        for name in files:
            if Path(name).suffix.lower() in EXTENSIONS:
                return True
            seen += 1
            if seen >= _WALK_LIMIT:
                return True
    return False


def _region(item: dict) -> dict:
    source = item.get("source") if isinstance(item.get("source"), dict) else {}
    column = source.get("column") if isinstance(source.get("column"), dict) else {}
    start = source.get("start") or item.get("line_number")
    region: dict = {}
    if isinstance(start, int):
        region["startLine"] = start
        end = source.get("end")
        region["endLine"] = end if isinstance(end, int) and end >= start else start
    if isinstance(column.get("start"), int):
        region["startColumn"] = column["start"]
    if isinstance(column.get("end"), int):
        region["endColumn"] = column["end"]
    extract = item.get("code_extract")
    if isinstance(extract, str) and extract.strip():
        region["snippet"] = {"text": extract.strip()}
    return region


def bearer_json_to_sarif(report: object, version: str) -> dict:
    """Convert a Bearer security report (findings grouped by severity) to SARIF 2.1.0."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    groups = report if isinstance(report, dict) else {}
    for bearer_severity, items in groups.items():
        if bearer_severity not in _SEVERITY or not isinstance(items, list):
            continue
        unified, level, score = _SEVERITY[bearer_severity]
        for item in items:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            rule_id = str(item["id"])
            title = str(item.get("title") or rule_id)
            cwe = [f"CWE-{str(value).strip()}" for value in item.get("cwe_ids") or [] if str(value).strip()]
            if rule_id not in rules:
                description = item.get("description") if isinstance(item.get("description"), str) else ""
                rule = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": title},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "tags": [*cwe, "security", unified],
                        "security-severity": score,
                    },
                }
                if description:
                    rule["help"] = {"text": description, "markdown": description}
                if isinstance(item.get("documentation_url"), str):
                    rule["helpUri"] = item["documentation_url"]
                rules[rule_id] = rule
            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(item.get("filename") or "")},
                            "region": _region(item),
                        }
                    }
                ],
                "properties": {"bearer-severity": bearer_severity},
            }
            if item.get("fingerprint"):
                result["partialFingerprints"] = {"bearer/v1": str(item["fingerprint"])}
            results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Bearer",
                        "semanticVersion": version,
                        "informationUri": "https://docs.bearer.com",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


class BearerHook:
    name = "bearer"
    prepare_label = "downloading the Bearer rule pack (cached after the first scan)"

    def is_applicable(self, project: Path) -> bool:
        return has_supported_files(project)

    def wants_network(self, descriptor: ToolDescriptor, options: ScanOptions) -> bool:
        return descriptor.network

    def extra_mounts(self, options: ScanOptions, use_docker: bool) -> list[tuple[Path, str]]:
        return []

    async def prepare(self, descriptor: ToolDescriptor, runner, use_docker: bool) -> str | None:
        import asyncio

        if not descriptor.rules_version:
            return "bearer.yaml has no rules_version"
        if use_docker and _rules_mount(descriptor) is None:
            return f"bearer.yaml has no cache volume named {RULES_CACHE}"
        try:
            await asyncio.to_thread(install_rules, descriptor)
        except urllib.error.HTTPError as exc:
            return f"could not download the Bearer rule pack {descriptor.rules_version}: HTTP {exc.code}"
        except urllib.error.URLError as exc:
            return f"could not download the Bearer rule pack {descriptor.rules_version}: {exc.reason}"
        except (OSError, ValueError, tarfile.TarError) as exc:
            return f"could not install the Bearer rule pack {descriptor.rules_version}: {exc}"
        return None

    def build_args(self, descriptor: ToolDescriptor, src: str, output: str, options: ScanOptions, use_docker: bool) -> list[str]:
        raw_name = descriptor.raw_output_filename or "bearer.json"
        if use_docker:
            raw_output = str(PurePosixPath(output).with_name(raw_name))
            rules = f"{_rules_mount(descriptor)}/{descriptor.rules_version}"
        else:
            raw_output = str(Path(output).with_name(raw_name))
            rules = str(rules_dir(descriptor))
        skip = [pattern for pattern in options.excludes if "," not in pattern]
        skip += [pattern for pattern in _ALWAYS_SKIP if pattern not in skip]
        return [
            "scan", src,
            "--report", "security",
            "--format", "json",
            "--output", raw_output,
            "--exit-code", "0",
            "--disable-version-check",
            "--disable-default-rules",
            "--external-rule-dir", rules,
            "--skip-path", ",".join(skip),
            "--hide-progress-bar",
            "--no-color",
            "--quiet",
        ]

    def convert_output(self, raw_path: Path, sarif_path: Path, descriptor: ToolDescriptor) -> None:
        text = raw_path.read_text(encoding="utf-8").strip()
        report = json.loads(text) if text and text != "null" else {}
        if not isinstance(report, dict):
            raise ValueError("the Bearer report is not a JSON object")
        sarif = bearer_json_to_sarif(report, descriptor.version)
        sarif_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")

    def refine_finding(self, finding: Finding, result: dict, rule: dict) -> Finding:
        original = (result.get("properties") or {}).get("bearer-severity")
        if isinstance(original, str) and original:
            return finding.model_copy(update={"severity_original": original})
        return finding
