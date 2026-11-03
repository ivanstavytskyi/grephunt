"""Which list a finding belongs in. Nothing is deleted: every finding keeps one tier and a reason.

main          what to look at first
review        reported, but the strongest available check did not back it
not_executed  code the application never loads (answer variants, unreferenced copies)
hygiene       informational notes that are not vulnerabilities (TODO comments, localhost)
infra         infrastructure as code and CI pipeline findings, a different audience

On the DVWA and Juice Shop benchmarks none of the known vulnerabilities came from the
hygiene, infra or not_executed groups, so moving them off the main list loses nothing.
The first rule that applies wins.
"""
from __future__ import annotations

import re

MAIN = "main"
REVIEW = "review"
NOT_EXECUTED = "not_executed"
HYGIENE = "hygiene"
INFRA = "infra"
TIERS = (MAIN, REVIEW, NOT_EXECUTED, HYGIENE, INFRA)

_INFRA_TOOLS = {"zizmor", "checkov", "kics", "hadolint", "kubescape"}
_CI_PATH = re.compile(
    r"(^|/)(\.github/workflows/|\.gitlab-ci\.ya?ml$|\.circleci/|azure-pipelines\.ya?ml$|bitbucket-pipelines\.ya?ml$|jenkinsfile$)",
    re.IGNORECASE,
)
# Infrastructure files, whatever tool or category reported them (Semgrep files Terraform rules as code).
_IAC_PATH = re.compile(
    r"\.(tf|tfvars|hcl)$|(^|/)dockerfile[^/]*$|\.dockerfile$|(^|/)(docker-)?compose[^/]*\.ya?ml$"
    r"|(^|/)(k8s|kubernetes|helm|charts|manifests|deploy|deployment)/[^/]+\.ya?ml$",
    re.IGNORECASE,
)
_IAC_RULE = re.compile(r"^(terraform|dockerfile|docker-compose|kubernetes|yaml\.kubernetes|yaml\.github-actions|github-actions)\.", re.IGNORECASE)
# Engines that follow data through the code and know escaping, type checks and prepared queries.
_DATAFLOW = {
    "php": {"psalm", "progpilot"},
    "javascript": {"codeql"},
    "typescript": {"codeql"},
    "python": {"codeql"},
    "java": {"codeql"},
}
_LANGUAGE_BY_SUFFIX = {
    ".php": "php", ".phtml": "php", ".inc": "php",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".py": "python",
    ".java": "java", ".kt": "java",
}
_OWN_RULE = "grephunt."


def _path(finding: dict) -> str:
    location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    return str(location.get("path") or "").replace("\\", "/")


def _reports(finding: dict) -> list[tuple[str, str]]:
    """(tool, rule) for every report folded into the finding."""
    found = [
        (str(item.get("tool") or ""), str(item.get("rule_id") or ""))
        for item in finding.get("confirmations") or []
        if isinstance(item, dict)
    ]
    if not found:
        found = [(str(tool), str(finding.get("rule_id") or "")) for tool in finding.get("tools") or [finding.get("tool")]]
    return [(tool, rule) for tool, rule in found if tool]


def _language(path: str) -> str | None:
    lower = path.lower()
    for suffix, name in _LANGUAGE_BY_SUFFIX.items():
        if lower.endswith(suffix):
            return name
    return None


def tools_with_findings(findings: list[dict]) -> set[str]:
    """Tools that reported anything in this scan: proof they ran and analysed the code."""
    names: set[str] = set()
    for finding in findings:
        names.update(tool for tool, _rule in _reports(finding))
    return names


def _secret_live(finding: dict, checked: bool) -> bool | None:
    """True when TruffleHog verified the key, False when it checked and the key did not work.

    None when nobody checked: verification was off for this scan, the check itself failed,
    or another tool found a kind of secret TruffleHog has no detector for.
    """
    statuses = []
    for item in finding.get("confirmations") or []:
        if isinstance(item, dict) and item.get("tool") == "trufflehog":
            statuses.append(str(item.get("title") or "").lower())
    if not statuses and "trufflehog" in (finding.get("tools") or []):
        statuses.append(str(finding.get("title") or "").lower())
    if any("(verified live)" in status for status in statuses):
        return True
    if checked and statuses and all("(not verified)" in status for status in statuses):
        return False
    return None


def tier_of(
    finding: dict,
    not_executed: set[str],
    active_tools: set[str],
    secrets_checked: bool = False,
) -> tuple[str, str]:
    category = str(finding.get("category") or "code").lower()
    severity = str(finding.get("severity") or "").lower()
    path = _path(finding)
    reports = _reports(finding)
    tools = {tool for tool, _rule in reports}

    if category == "secret":
        live = _secret_live(finding, secrets_checked)
        if live is True:
            finding["secret_live"] = True
        elif live is False:
            finding["secret_live"] = False
            return REVIEW, "TruffleHog checked this key against its service: it is not live"
        return MAIN, ""

    rules = [rule for _tool, rule in reports]
    if (
        category == "misconfig"
        or _CI_PATH.search(path)
        or _IAC_PATH.search(path)
        or (tools and tools <= _INFRA_TOOLS)
        or (rules and all(_IAC_RULE.search(rule) for rule in rules))
    ):
        return INFRA, "infrastructure or CI pipeline finding"

    if tools == {"devskim"} and severity == "info":
        return HYGIENE, "informational DevSkim note, not a vulnerability"

    if category == "code" and path in not_executed:
        return NOT_EXECUTED, "nothing in the application imports, links or loads this file"

    language = _language(path)
    engines = _DATAFLOW.get(language or "", set()) & active_tools
    own_only = reports and all(rule.startswith(_OWN_RULE) for _tool, rule in reports)
    if category == "code" and engines and own_only and not (tools & engines):
        names = " or ".join(sorted(engines))
        return REVIEW, f"only GrepHunt's own pattern rule reports this; {names} analysed the same code and did not"
    return MAIN, ""


def assign_tiers(findings: list[dict], not_executed: set[str] | None = None, secrets_checked: bool = False) -> list[dict]:
    """Set tier and tier_reason on every finding. Returns the same list.

    secrets_checked: TruffleHog ran with key verification in this scan.
    """
    active = tools_with_findings(findings)
    skipped = not_executed or set()
    for finding in findings:
        tier, reason = tier_of(finding, skipped, active, secrets_checked)
        finding["tier"] = tier
        finding["tier_reason"] = reason
    return findings
