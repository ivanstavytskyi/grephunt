"""Keep only findings that matter for the business: the classes bug bounty programs pay for.

The AI scan report used to describe every finding, so weak hashes, missing
headers, ReDoS in a dev dependency and test fixtures buried the real problems.
This filter keeps the classes that lead to code execution, data theft or lost
money (RCE, injections, LFR/LFI/RFI, SSRF, memory leaks, business logic, IDOR,
access control, account takeover, authentication/authorization flaws, XSS and
CSRF) and drops the rest: low and info severity, findings an AI review called
false positives, test and example code, and findings the exploitability score
calls unlikely unless they are critical or high.
"""
from __future__ import annotations

import re

from grephunt.finding_model.exploitability import exploitability
from grephunt.finding_model.vuln_class import cwe_numbers, iac_topic, vulnerability_class

RCE = "Remote code execution (RCE)"
INJECTION = "Injection (SQL, NoSQL, XML, LDAP, XPath)"
FILE = "LFR / LFI / RFI"
SSRF = "SSRF"
MEMORY = "Memory leak"
LOGIC = "Business logic"
IDOR = "IDOR"
ACCESS = "Access control"
TAKEOVER = "Account takeover"
AUTH = "Authentication / authorization flaw"
XSS_CSRF = "XSS / CSRF"

# Report order: the most damaging classes first.
CLASS_ORDER = [RCE, INJECTION, FILE, SSRF, AUTH, TAKEOVER, IDOR, ACCESS, LOGIC, MEMORY, XSS_CSRF]

_FROM_VULN_CLASS = {
    "command-injection": RCE,
    "code-injection": RCE,
    "deserialization": RCE,
    "sql-injection": INJECTION,
    "nosql-injection": INJECTION,
    "xxe": INJECTION,
    "ldap-injection": INJECTION,
    "xpath-injection": INJECTION,
    "path-traversal": FILE,
    "file-inclusion": FILE,
    "ssrf": SSRF,
    "hardcoded-secret": AUTH,
    "xss": XSS_CSRF,
    "csrf": XSS_CSRF,
}

_FROM_CWE: dict[int, str] = {}
for _name, _numbers in {
    RCE: (77, 78, 88, 94, 95, 96, 434, 502, 917, 1336),
    INJECTION: (74, 89, 90, 91, 93, 113, 564, 611, 643, 652, 776, 943, 1321),
    FILE: (22, 23, 35, 36, 73, 98, 829),
    SSRF: (918,),
    MEMORY: (119, 120, 121, 122, 125, 126, 401, 415, 416, 787, 908),
    LOGIC: (362, 367, 840, 841, 915),
    IDOR: (639,),
    ACCESS: (269, 284, 285, 425, 862, 863),
    TAKEOVER: (384, 613, 620, 640),
    AUTH: (259, 287, 288, 290, 294, 306, 307, 321, 345, 347, 521, 522, 798, 1390, 1391),
    XSS_CSRF: (79, 80, 83, 87, 352),
}.items():
    for _number in _numbers:
        _FROM_CWE[_number] = _name

# Checked in order against rule id, title and the start of the message.
_KEYWORDS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"remote code execution|\brce\b|command injection|code injection|template injection|\bssti\b|deserializ|prototype pollution"), RCE),
    (re.compile(r"injection|\bsqli\b|\bxxe\b|external entit"), INJECTION),
    (re.compile(r"path traversal|directory traversal|\blfi\b|\brfi\b|\blfr\b|file inclusion|arbitrary file (read|write)|zip ?slip"), FILE),
    (re.compile(r"\bssrf\b|server.side request forgery"), SSRF),
    (re.compile(r"memory leak|buffer overflow|out.of.bounds|use.after.free|heap overflow|uninitiali[sz]ed memory|memory disclosure"), MEMORY),
    (re.compile(r"\bidor\b|insecure direct object"), IDOR),
    (re.compile(r"account takeover|session fixation|password reset|password recovery"), TAKEOVER),
    (re.compile(r"missing authori[sz]ation|access control|privilege escalation|authori[sz]ation bypass|broken access"), ACCESS),
    (re.compile(r"auth(entication)? bypass|missing authentication|jwt|signature (is )?not verified|hard.?coded (password|credential|secret|key)|brute.?force"), AUTH),
    (re.compile(r"race condition|mass assignment|business logic"), LOGIC),
    (re.compile(r"\bxss\b|cross.site scripting|\bcsrf\b|cross.site request forgery|dangerouslysetinnerhtml|bypasssecuritytrust"), XSS_CSRF),
]

# Infrastructure findings that expose customer data directly.
_IAC_TOPICS = {"public-access": ACCESS, "secret-exposure": AUTH}

_NON_PRODUCTION = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|fixtures?|examples?|samples?|docs?|testdata|mocks?|e2e|cypress)(/|$)"
    r"|\.(test|spec)\.[a-z0-9]+$|(^|/)test_[^/]+\.py$|_test\.(go|py)$",
    re.IGNORECASE,
)

_SEVERE = {"critical", "high"}
_KEPT_SEVERITIES = {"critical", "high", "medium"}


def impact_class(finding: dict) -> str | None:
    """The bug bounty class of a finding, or None when it is not one of them."""
    category = str(finding.get("category") or "code").lower()
    cwes = [str(item) for item in (finding.get("cwe") or [])]
    rule_id = str(finding.get("rule_id") or "")
    title = str(finding.get("title") or "")
    message = str(finding.get("message") or "")[:300]

    if category == "secret":
        return AUTH
    for number in cwe_numbers(cwes):
        if number in _FROM_CWE:
            return _FROM_CWE[number]
    known = vulnerability_class(cwes, rule_id, title)
    if known in _FROM_VULN_CLASS:
        return _FROM_VULN_CLASS[known]
    text = f"{rule_id} {title} {message}".lower().replace("_", " ").replace("-", " ")
    for pattern, name in _KEYWORDS:
        if pattern.search(text):
            return name
    if category == "misconfig":
        topic = iac_topic(rule_id, title, message)
        if topic in _IAC_TOPICS:
            return _IAC_TOPICS[topic]
    return None


def drop_reason(finding: dict) -> str | None:
    """Why a finding is left out of the report, or None when it stays."""
    severity = str(finding.get("severity") or "info").lower()
    if severity not in _KEPT_SEVERITIES:
        return "low impact"
    if finding.get("ai_verdict") == "false_positive":
        return "false positive"
    location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    path = str(location.get("path") or "").replace("\\", "/")
    if path and _NON_PRODUCTION.search(path):
        return "test or example code"
    klass = impact_class(finding)
    if klass is None:
        return "not an exploitable class"
    category = str(finding.get("category") or "code").lower()
    if category in {"dependency", "misconfig", "secret"} and severity not in _SEVERE:
        return "low impact"
    score = finding.get("exploitability")
    if not isinstance(score, dict):
        score = exploitability(finding)
    if score.get("label") == "unlikely" and severity not in _SEVERE:
        return "not exploitable"
    return None


def filter_impactful(findings: list) -> tuple[list[dict], dict]:
    """(kept findings with an impact_class field, statistics about what was dropped)."""
    kept: list[dict] = []
    dropped: dict[str, int] = {}
    for item in findings:
        if not isinstance(item, dict):
            continue
        reason = drop_reason(item)
        if reason:
            dropped[reason] = dropped.get(reason, 0) + 1
            continue
        kept.append({**item, "impact_class": impact_class(item)})
    by_class: dict[str, int] = {}
    for item in kept:
        by_class[item["impact_class"]] = by_class.get(item["impact_class"], 0) + 1
    stats = {
        "total": sum(1 for item in findings if isinstance(item, dict)),
        "kept": len(kept),
        "dropped": sum(dropped.values()),
        "dropped_by_reason": dropped,
        "by_class": {name: by_class[name] for name in CLASS_ORDER if name in by_class},
    }
    return kept, stats
