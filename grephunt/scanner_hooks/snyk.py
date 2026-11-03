"""Snyk Code and Snyk Open Source through the official Snyk CLI.

The CLI binary is downloaded and hash-checked on this machine
(integrations/snyk.py), then mounted read-only into a pinned Python image.
Before each scan the CLI on this machine refreshes the OAuth token, and the
container gets it in INTERNAL_OAUTH_TOKEN_STORAGE.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from grephunt.finding_model.record import Category, Finding, Severity
from grephunt.integrations import snyk
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scanner_catalog.descriptor import ToolDescriptor
from grephunt.scanner_hooks.generic import GenericHook

CLI_MOUNT = "/opt/snyk/snyk"
_SEVERITY_WORD = re.compile(r"^(critical|high|medium|low) severity\b", re.IGNORECASE)
_PACKAGE = re.compile(r"(?:\((?P<cves>[^)]*)\)\s*)?(?P<name>\S+)@(?P<version>\S+)\s*$")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class SnykHook(GenericHook):
    prepare_label = "checking the Snyk login and the Snyk CLI"

    def extra_mounts(self, options: ScanOptions, use_docker: bool) -> list[tuple[Path, str]]:
        if not use_docker:
            return []
        return [(snyk.cli_path(snyk.container_platform_key()), CLI_MOUNT)]

    def extra_environment(self, options: ScanOptions, use_docker: bool) -> dict[str, str]:
        if use_docker:
            return snyk.scan_environment()
        # A local Snyk CLI reads the login from the same isolated home the console wrote.
        home = str(snyk.home_dir())
        return {"HOME": home, "USERPROFILE": home, "SNYK_DISABLE_ANALYTICS": "1"}

    async def prepare(self, descriptor: ToolDescriptor, runner, use_docker: bool) -> str | None:
        if not snyk.is_connected():
            return "Snyk is not connected. Use Connect Snyk on the New scan page, then start the scan again."
        try:
            host_cli = await asyncio.to_thread(snyk.ensure_cli, snyk.platform_key())
            await asyncio.to_thread(snyk.refresh_token, host_cli)
            if use_docker:
                await asyncio.to_thread(snyk.ensure_cli, snyk.container_platform_key())
        except snyk.SnykError as exc:
            return str(exc)
        except OSError as exc:
            return f"could not get the Snyk CLI: {exc}"
        return None

    def refine_finding(self, finding: Finding, result: dict, rule: dict) -> Finding:
        finding = super().refine_finding(finding, result, rule)
        short = str((rule.get("shortDescription") or {}).get("text") or "")
        full = str((rule.get("fullDescription") or {}).get("text") or "")
        update: dict = {}
        word = _SEVERITY_WORD.match(short)
        if word:
            update["severity"] = Severity(word.group(1).lower())
            update["severity_original"] = word.group(1).lower()
        if finding.rule_id.upper().startswith("SNYK-"):
            update["category"] = Category.DEPENDENCY
            package = _PACKAGE.search(full)
            if package:
                update["package"] = package.group("name")
                update["installed_version"] = package.group("version")
                cves = sorted({match.upper() for match in _CVE.findall(package.group("cves") or "")})
                if cves:
                    update["cve"] = cves
        return finding.model_copy(update=update) if update else finding
