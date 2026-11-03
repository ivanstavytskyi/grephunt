"""Recommend which scanners to run for a project, from its map.

The project map is built before any scanner runs (tree-sitter, nothing executed):
it already lists the files, their roles, the languages, and the stack. From that a
deterministic recommender picks the scanners that fit — the right code scanners for
the languages present, IaC scanners when there are Dockerfiles / Terraform / CI
workflows, dependency and secret scanners for any project. The configured AI can
then review that choice against the same digest and adjust it with reasons.
"""
from __future__ import annotations

import json

from grephunt.web_console.ai_explain import ProviderError, _call

# Language (as the map reports it) -> code scanners that specialise in it.
_LANG_SCANNERS = {
    "python": ["bandit", "codeql"],
    "go": ["gosec"],
    "php": ["psalm", "progpilot"],
    "ruby": ["brakeman"],
    "java": ["codeql"],
    "javascript": ["codeql"],
    "typescript": ["codeql"],
    "csharp": ["codeql"],
    "c": ["cppcheck"],
    "cpp": ["cppcheck"],
}
_ALWAYS_CODE = ["semgrep"]
_SECRET = ["gitleaks", "trufflehog"]
_DEPENDENCY = ["trivy", "osv-scanner"]
_IAC_DOCKER = ["hadolint", "checkov"]
_IAC_TERRAFORM = ["checkov", "kics"]
_IAC_K8S = ["kubescape", "checkov"]
_IAC_WORKFLOWS = ["zizmor"]

_MANIFESTS = {"package.json", "requirements.txt", "pyproject.toml", "go.mod", "pom.xml", "build.gradle", "composer.json", "gemfile", "cargo.toml"}


def _digest(project_map: dict) -> dict:
    """What the recommender and the AI both read: languages, roles, and what kinds of files exist."""
    files = (project_map.get("files") or {}).get("nodes") or []
    stats = project_map.get("stats") or {}
    stack = project_map.get("stack") or {}
    roles: dict[str, int] = {}
    languages: dict[str, int] = {}
    has = {"dockerfile": False, "terraform": False, "kubernetes": False, "workflows": False, "manifest": False}
    for node in files:
        if node.get("kind") != "file":
            continue
        role = node.get("role") or "source"
        roles[role] = roles.get(role, 0) + 1
        language = node.get("language")
        if language:
            languages[language] = languages.get(language, 0) + 1
        path = (node.get("path") or "").lower()
        name = path.rsplit("/", 1)[-1]
        if language == "dockerfile" or name.startswith("dockerfile"):
            has["dockerfile"] = True
        if path.endswith((".tf", ".tf.json")):
            has["terraform"] = True
        if "/.github/workflows/" in f"/{path}":
            has["workflows"] = True
        if name in _MANIFESTS:
            has["manifest"] = True
        if language in {"yaml", "yml"} and ("k8s" in path or "kubernetes" in path or "helm" in path or "/manifests/" in f"/{path}"):
            has["kubernetes"] = True
    return {
        "languages": dict(sorted(languages.items(), key=lambda kv: -kv[1])),
        "frameworks": stack.get("frameworks") or [],
        "datastores": stack.get("datastores") or [],
        "roles": roles,
        "has": has,
        "files": stats.get("files"),
        "routes": stats.get("routes"),
    }


def recommend(project_map: dict, tools: list[dict]) -> dict:
    """Deterministic recommendation: {"recommended": [names], "reasons": {name: why}, "digest": {...}}."""
    available = {tool["name"]: tool for tool in tools if not tool.get("cloud")}
    digest = _digest(project_map)
    picked: dict[str, str] = {}

    def add(name: str, reason: str) -> None:
        if name in available and name not in picked:
            picked[name] = reason

    for scanner in _ALWAYS_CODE:
        add(scanner, "broad static analysis for the code in this project")
    for language, count in digest["languages"].items():
        for scanner in _LANG_SCANNERS.get(language, []):
            add(scanner, f"specialised checks for {language} ({count} files)")
    for scanner in _SECRET[:1]:
        add(scanner, "find leaked secrets in any file")
    add("trufflehog", "second opinion on secrets, with entropy checks")
    if digest["has"]["manifest"]:
        for scanner in _DEPENDENCY:
            add(scanner, "known CVEs in the declared dependencies")
    if digest["has"]["dockerfile"]:
        for scanner in _IAC_DOCKER:
            add(scanner, "Dockerfile hardening and misconfigurations")
    if digest["has"]["terraform"]:
        for scanner in _IAC_TERRAFORM:
            add(scanner, "Terraform misconfigurations")
    if digest["has"]["kubernetes"]:
        for scanner in _IAC_K8S:
            add(scanner, "Kubernetes manifest hardening")
    if digest["has"]["workflows"]:
        for scanner in _IAC_WORKFLOWS:
            add(scanner, "GitHub Actions workflow audit")
    return {"recommended": list(picked), "reasons": picked, "digest": digest}


_PROMPT = """You choose which security scanners to run on a project, from a map built before scanning.
The map was produced by parsing the source (no code executed): it reports the languages, the stack,
the file roles, and what kinds of files exist. You are given that digest, the scanners available in
this tool (name, what it is for, the languages it covers), and a deterministic default selection.

Pick the scanners worth running for THIS project. Prefer one or two strong tools per need
(code, secrets, dependencies, infrastructure); do not enable a scanner for a language or file type
that is not present. You may add to or trim the default selection.

Return ONLY a JSON object, no prose, no code fence:
{"scanners": ["name", ...], "reasons": {"name": "one short reason", ...}, "summary": "one or two sentences on the project and the choice"}
Use only scanner names from the available list.

Project digest:
%s

Available scanners:
%s

Deterministic default selection: %s
"""


def _parse_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1] if "```" in text[3:] else text.strip("`")
        text = text[text.find("{"):]
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def recommend_with_ai(provider: str, api_key: str, model: str, project_map: dict, tools: list[dict]) -> dict:
    """Deterministic pick reviewed by the AI. Falls back to the deterministic pick if the AI is unusable."""
    base = recommend(project_map, tools)
    names = {tool["name"] for tool in tools if not tool.get("cloud")}
    catalog = [{"name": t["name"], "for": t.get("group"), "languages": t.get("languages"), "purpose": t.get("purpose")} for t in tools if not t.get("cloud")]
    prompt = _PROMPT % (
        json.dumps(base["digest"], ensure_ascii=False),
        json.dumps(catalog, ensure_ascii=False),
        json.dumps(base["recommended"], ensure_ascii=False),
    )
    try:
        answer = _call(provider, api_key, model, prompt)
    except (ValueError, ProviderError):
        raise
    parsed = _parse_json(answer)
    if not parsed or not isinstance(parsed.get("scanners"), list):
        return {**base, "summary": "", "source": "deterministic", "note": "the model did not return a usable selection; showing the default"}
    chosen = [name for name in parsed["scanners"] if name in names]
    if not chosen:
        return {**base, "summary": str(parsed.get("summary") or ""), "source": "deterministic", "note": "the model chose no valid scanner; showing the default"}
    reasons = {name: str(reason)[:200] for name, reason in (parsed.get("reasons") or {}).items() if name in chosen}
    for name in chosen:
        reasons.setdefault(name, base["reasons"].get(name, "recommended by the model"))
    return {"recommended": chosen, "reasons": reasons, "digest": base["digest"], "summary": str(parsed.get("summary") or "")[:600], "source": "ai"}
