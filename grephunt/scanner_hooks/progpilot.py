"""Progpilot SARIF uses rule id taint-style and writes CWE as CWE_79."""
from __future__ import annotations

import re

from grephunt.finding_model.record import Finding
from grephunt.scanner_hooks.generic import GenericHook

_CWE = re.compile(r"CWE[_-](\d+)", re.IGNORECASE)


class ProgpilotHook(GenericHook):
    def refine_finding(self, finding: Finding, result: dict, rule: dict) -> Finding:
        props = result.get("properties") or {}
        name = props.get("vuln_name") or props.get("vuln_rule")
        cwes = sorted({f"CWE-{match.group(1)}" for match in _CWE.finditer(str(props.get("vuln_cwe") or ""))})
        update: dict = {}
        if isinstance(name, str) and name and name not in {"taint-style", "custom"}:
            update["rule_id"] = name
            update["title"] = name.replace("_", " ")
        if cwes:
            update["cwe"] = cwes
        if not update:
            return finding
        return finding.model_copy(update=update)
