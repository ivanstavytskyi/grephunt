"""Trivy-specific behavior: warm the CVE database and read package fields from SARIF text."""
from __future__ import annotations

import re
import uuid
from pathlib import Path

from grephunt.finding_model.record import Category, Finding
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.execution.request import RunRequest
from grephunt.scanner_catalog.descriptor import ToolDescriptor

_PKG_FIELDS = {
    "package": "Package",
    "installed_version": "Installed Version",
    "fixed_version": "Fixed Version",
}

def _package_info(message: str) -> dict[str, str]:
    info: dict[str, str] = {}
    for field, label in _PKG_FIELDS.items():
        match = re.search(rf"^{re.escape(label)}:\s*(.+)$", message, re.MULTILINE)
        if match:
            info[field] = match.group(1).strip()
    return info


class TrivyHook:
    name = "trivy"
    prepare_label = "warming CVE database (cached when possible)"

    def is_applicable(self, project: Path) -> bool:
        return True

    def supports_image(self) -> bool:
        return True

    def wants_network(self, descriptor: ToolDescriptor, options: ScanOptions) -> bool:
        return descriptor.network

    def extra_mounts(self, options: ScanOptions, use_docker: bool) -> list[tuple[Path, str]]:
        return []

    def build_args(self, descriptor: ToolDescriptor, src: str, output: str, options: ScanOptions, use_docker: bool) -> list[str]:
        scanners = options.trivy_scanners or ["vuln", "secret", "misconfig"]
        if options.target_kind == "image":
            # misconfig checks Dockerfiles and IaC, which an image does not contain.
            scanners = [item for item in scanners if item != "misconfig"] or ["vuln"]
            args = ["image", "--input", src, "--scanners", ",".join(scanners)]
            if use_docker:
                args.append("--skip-db-update")
            return [*args, "--format", "sarif", "--output", output, "--quiet"]
        args = ["fs", "--scanners", ",".join(scanners)]
        if use_docker:
            args.append("--skip-db-update")
        return [*args, "--format", "sarif", "--output", output, "--quiet", src]

    async def prepare(self, descriptor: ToolDescriptor, runner, use_docker: bool) -> str | None:
        if not use_docker:
            return None
        from grephunt.execution.cache import cache_binds

        request = RunRequest(
            image=descriptor.image,
            binary=descriptor.binary,
            args=["image", "--download-db-only", "--no-progress"],
            container_name=f"grephunt-trivy-db-{uuid.uuid4().hex[:8]}",
            network=descriptor.prepare_network,
            user=descriptor.user,
            cpus=descriptor.cpus,
            memory=descriptor.memory,
            pids_limit=descriptor.pids_limit,
            binds=cache_binds(descriptor),
            environment=descriptor.environment,
            timeout_sec=min(descriptor.timeout_sec, 600),
            cap_drop=descriptor.cap_drop,
            no_new_privileges=descriptor.no_new_privileges,
            progress_tool=self.name,
        )
        outcome = await runner.run(request)
        if outcome.returncode == 0:
            return None
        tail = (outcome.stderr or outcome.stdout or outcome.error or "database download failed")[-1500:]
        return f"failed to update the Trivy CVE database\n{tail}".strip()

    def refine_finding(self, finding: Finding, result: dict, rule: dict) -> Finding:
        info = _package_info(finding.message)
        name = (rule.get("name") or "").lower()
        tags = {str(tag).lower() for tag in rule.get("properties", {}).get("tags", [])}
        category = finding.category
        if "misconfiguration" in tags or name == "misconfiguration":
            category = Category.MISCONFIG
        elif "secret" in tags or name == "secret":
            category = Category.SECRET
        elif finding.cve or info.get("package"):
            category = Category.DEPENDENCY
        if not info and category is finding.category:
            return finding
        return finding.model_copy(update={**info, "category": category})
