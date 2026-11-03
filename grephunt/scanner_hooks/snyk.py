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
# Older Snyk advisories: npm:jsonwebtoken:20150331, pip:django:20190730. They carry no CVE.
_LEGACY_ID = re.compile(r"^(?:npm|pip|maven|golang|nuget|composer|rubygems|cocoapods|hex|cargo):(?P<name>.+):\d{8}$", re.IGNORECASE)
_UPGRADE = re.compile(r"Upgrade to (?P<name>\S+)@(?P<version>\S+)", re.IGNORECASE)


def _package_at_version(value: str) -> tuple[str, str] | None:
    """'jsonwebtoken@0.1.0' or '@scope/name@1.2.3' -> (name, version)."""
    value = value.strip()
    if "@" not in value.lstrip("@"):
        return None
    name, _, version = value.rpartition("@")
    return (name, version) if name and version else None


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
        legacy = _LEGACY_ID.match(finding.rule_id)
        if finding.rule_id.upper().startswith("SNYK-") or legacy:
            update["category"] = Category.DEPENDENCY
            package = _PACKAGE.search(full)
            if package:
                update["package"] = package.group("name")
                update["installed_version"] = package.group("version")
                cves = sorted({match.upper() for match in _CVE.findall(package.group("cves") or "")})
                if cves:
                    update["cve"] = cves
            # The result names the vulnerable package and version: logicalLocations "jsonwebtoken@0.1.0".
            for location in result.get("locations") or []:
                for logical in location.get("logicalLocations") or []:
                    parsed = _package_at_version(str(logical.get("fullyQualifiedName") or ""))
                    if parsed:
                        update.setdefault("package", parsed[0])
                        update.setdefault("installed_version", parsed[1])
            if legacy and "package" not in update:
                update["package"] = legacy.group("name")
            # fixes: "Upgrade to express-jwt@3.0.0" upgrades the package itself or the one that pulls it in.
            for fix in result.get("fixes") or []:
                upgrade = _UPGRADE.search(str((fix.get("description") or {}).get("text") or ""))
                if not upgrade:
                    continue
                if upgrade.group("name") == update.get("package", finding.package):
                    update["fixed_version"] = upgrade.group("version")
                else:
                    update["evidence"] = f"Fix: upgrade {upgrade.group('name')} to {upgrade.group('version')}"
                break
        return finding.model_copy(update=update) if update else finding
