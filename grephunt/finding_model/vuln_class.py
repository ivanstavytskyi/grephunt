"""What kind of problem a finding is, independent of the tool that reported it.

Tools describe one SQL injection with different CWEs (89, 564), rule ids, and
titles. Correlation groups findings by this class and by where the dangerous
call is, so one problem becomes one finding with several confirmations.
"""
from __future__ import annotations

import re

# CWE number -> class. CWEs that are not listed keep their own number as the class.
_CWE_CLASSES: dict[int, str] = {}
for _class, _numbers in {
    "sql-injection": (89, 564, 566),
    "nosql-injection": (943,),
    "command-injection": (77, 78, 88),
    "code-injection": (94, 95, 96, 1336),
    "file-inclusion": (98,),
    "path-traversal": (22, 23, 35, 36, 73),
    "xss": (79, 80, 83, 87),
    "ssrf": (918,),
    "deserialization": (502,),
    "open-redirect": (601,),
    "xxe": (611, 776),
    "ldap-injection": (90,),
    "xpath-injection": (643,),
    "hardcoded-secret": (798, 259, 321),
    "weak-hash": (327, 328, 916, 759, 760),
    "weak-random": (330, 338),
    "tls-verification": (295, 297),
    "csrf": (352,),
}.items():
    for _number in _numbers:
        _CWE_CLASSES[_number] = _class

# Order matters: nosql before sql.
_KEYWORD_CLASSES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"nosql|\$where|mongo.*inject"), "nosql-injection"),
    (re.compile(r"sql|sqli\b"), "sql-injection"),
    (re.compile(r"command.?inject|os.?command|shell.?inject|subprocess|shell=true|\bexec\b|child_process|popen|os\.system"), "command-injection"),
    (re.compile(r"template.?inject|ssti|\beval\b|code.?inject|exec.?code|new function"), "code-injection"),
    (re.compile(r"file.?inclusion|\blfi\b|\brfi\b"), "file-inclusion"),
    (re.compile(r"path.?travers|directory.?travers|zip.?slip"), "path-traversal"),
    (re.compile(r"\bxss\b|cross.?site.?script"), "xss"),
    (re.compile(r"\bssrf\b|server.?side.?request"), "ssrf"),
    (re.compile(r"deserializ|pickle|unserialize|yaml\.load|marshal"), "deserialization"),
    (re.compile(r"open.?redirect"), "open-redirect"),
    (re.compile(r"\bxxe\b|external.?entit"), "xxe"),
    (re.compile(r"\b(md5|sha1)\b|weak.?hash"), "weak-hash"),
    (re.compile(r"verify\s*=\s*false|insecure.?skip.?verify|certificate.?validation|tls.?verif"), "tls-verification"),
]


def cwe_numbers(cwes: list[str]) -> list[int]:
    numbers = []
    for item in cwes:
        match = re.search(r"(\d+)", item or "")
        if match:
            numbers.append(int(match.group(1)))
    return numbers


def vulnerability_class(cwes: list[str], rule_id: str = "", title: str = "") -> str | None:
    """'sql-injection', 'command-injection', ... or 'cwe-1234' for an unlisted CWE; None when unknown."""
    numbers = cwe_numbers(cwes)
    for number in numbers:
        if number in _CWE_CLASSES:
            return _CWE_CLASSES[number]
    text = f"{rule_id} {title}".lower()
    for pattern, name in _KEYWORD_CLASSES:
        if pattern.search(text):
            return name
    if numbers:
        return f"cwe-{min(numbers)}"
    return None


# Infrastructure checks: the same control seen by Trivy, Checkov, KICS, and Hadolint.
_IAC_TOPICS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"user instruction|as root|image user|user for the container|non-?root|root user|last user|\buser\b.*\broot\b"), "container-root-user"),
    (re.compile(r"healthcheck"), "container-healthcheck"),
    (re.compile(r"\bsudo\b"), "container-sudo"),
    (re.compile(r"\badd\b.*\bcopy\b|\bcopy\b.*\badd\b"), "container-add-vs-copy"),
    (re.compile(r"(apt|apk|yum|dnf|pip|npm|gem).*(pin|version)|(pin|version).*(apt|apk|yum|dnf|pip|npm|gem)"), "package-pinning"),
    (re.compile(r":latest|latest tag|image tag|untagged"), "image-tag"),
    (re.compile(r"egress"), "network-egress-open"),
    (re.compile(r"ingress|port 22|\bssh\b|\brdp\b|0\.0\.0\.0/0"), "network-ingress-open"),
    (re.compile(r"encrypt|kms|cmk"), "encryption"),
    (re.compile(r"public access|publicly accessible|public read|public-read|public ip|block public"), "public-access"),
    (re.compile(r"versioning"), "versioning"),
    (re.compile(r"access log|logging|log group|cloudtrail|flow log"), "logging"),
    (re.compile(r"imdsv2|instance metadata|http_tokens|metadata service"), "instance-metadata"),
    (re.compile(r"privileged|privilege escalation|allowprivilegeescalation"), "privileged-container"),
    (re.compile(r"read-?only root|readonlyrootfilesystem"), "readonly-root-filesystem"),
    (re.compile(r"resource limit|cpu limit|memory limit|\blimits\b"), "resource-limits"),
    (re.compile(r"capabilit"), "capabilities"),
    (re.compile(r"backup|retention"), "backup-retention"),
    (re.compile(r"deletion protection"), "deletion-protection"),
    (re.compile(r"\bmfa\b|multi-factor"), "mfa"),
    (re.compile(r"secret|password|credential|token"), "secret-exposure"),
    (re.compile(r"permissions|least privilege|wildcard|\*:\*|admin access"), "permissions"),
]


def iac_topic(rule_id: str, title: str, message: str = "") -> str | None:
    text = f"{title} {rule_id} {message[:200]}".lower()
    for pattern, name in _IAC_TOPICS:
        if pattern.search(text):
            return name
    return None


def clean_path(path: str) -> str:
    """A scanner's path as a project-relative path.

    Scanners report /src/app.py (container mount), ./app.py, or, when they ran from a
    folder below the mount (KICS), ../../src/app.py.
    """
    value = (path or "").replace("\\", "/").strip()
    for prefix in ("file://", "/src/", "./"):
        value = value.removeprefix(prefix)
    if value.startswith("../"):
        while value.startswith("../"):
            value = value[3:]
        value = value.removeprefix("src/")
    value = value.lstrip("/")
    return re.sub(r"/{2,}", "/", value)
