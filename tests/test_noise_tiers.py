"""Noise reduction without deleting findings: tiers, unreferenced files, verified secrets,
KEV/EPSS ranking, Psalm config, and the code the AI reviewer sees."""
import gzip
import json
from pathlib import Path

import yaml

from grephunt.finding_model.exploitability import exploitability
from grephunt.finding_model.tiers import assign_tiers, tier_of
from grephunt.intel import feeds
from grephunt.project_map.unreferenced import not_executed_files
from grephunt.scan_pipeline.converters import trufflehog_jsonl
from grephunt.scanner_catalog.descriptor import ParameterSpec
from grephunt.scanner_catalog.parameter_schema import coerce_parameter
from grephunt.scanner_catalog.registry import load_tools
from grephunt.web_console.function_context import enclosing_code

CATALOG = Path(__file__).resolve().parents[1] / "grephunt" / "scanner_catalog"


def _finding(path, tool="semgrep", rule="r", category="code", severity="high", confirmations=None, **extra):
    data = {"tool": tool, "tools": [tool], "rule_id": rule, "title": "t", "category": category,
            "severity": severity, "location": {"path": path, "start_line": 3}}
    if confirmations:
        data["confirmations"] = confirmations
    data.update(extra)
    return data


# ---------------------------------------------------------------- tiers

def test_infra_tier_for_iac_ci_and_iac_rules():
    assert tier_of(_finding("main.tf", tool="checkov", category="misconfig"), set(), set())[0] == "infra"
    assert tier_of(_finding(".github/workflows/ci.yml", tool="zizmor"), set(), set())[0] == "infra"
    assert tier_of(_finding("deploy/main.tf", rule="terraform.aws.security.x"), set(), set())[0] == "infra"
    assert tier_of(_finding("docker/Dockerfile", rule="dockerfile.security.x"), set(), set())[0] == "infra"


def test_secret_in_infra_file_stays_main():
    assert tier_of(_finding("compose.yml", tool="gitleaks", category="secret"), set(), set())[0] == "main"


def test_devskim_info_is_hygiene_but_not_when_another_tool_agrees():
    assert tier_of(_finding("a.ts", tool="devskim", severity="info"), set(), set())[0] == "hygiene"
    assert tier_of(_finding("a.ts", tool="devskim", severity="high"), set(), set())[0] == "main"
    both = _finding("a.ts", tool="devskim", severity="info", confirmations=[
        {"tool": "devskim", "rule_id": "DS1"}, {"tool": "semgrep", "rule_id": "x"}])
    assert tier_of(both, set(), set())[0] == "main"


def test_unloaded_code_goes_to_not_executed():
    assert tier_of(_finding("data/fixes/a_1.ts"), {"data/fixes/a_1.ts"}, set())[0] == "not_executed"
    assert tier_of(_finding("routes/a.ts"), {"data/fixes/a_1.ts"}, set())[0] == "main"


def test_own_php_rule_needs_dataflow_confirmation_only_when_dataflow_ran():
    own = _finding("x/low.php", rule="grephunt.php.sql-injection")
    assert tier_of(own, set(), {"semgrep", "progpilot"})[0] == "review"
    # No dataflow engine produced anything in this scan: nothing to compare with, keep it.
    assert tier_of(own, set(), {"semgrep"})[0] == "main"
    confirmed = _finding("x/low.php", rule="grephunt.php.sql-injection", confirmations=[
        {"tool": "semgrep", "rule_id": "grephunt.php.sql-injection"}, {"tool": "progpilot", "rule_id": "sql_injection"}])
    assert tier_of(confirmed, set(), {"semgrep", "progpilot"})[0] == "main"
    # Another independent tool agrees: not only our own rule, keep it on the main list.
    other = _finding("x/low.php", rule="grephunt.php.sql-injection", confirmations=[
        {"tool": "semgrep", "rule_id": "grephunt.php.sql-injection"}, {"tool": "snyk-code", "rule_id": "php/Sqli"}])
    assert tier_of(other, set(), {"semgrep", "progpilot"})[0] == "main"


def test_secret_tiers_follow_trufflehog_verification():
    def secret(status):
        return _finding("app.env", tool="trufflehog", category="secret", confirmations=[
            {"tool": "trufflehog", "rule_id": "trufflehog.aws", "title": f"AWS key ({status})"}])
    live = secret("verified live")
    assert tier_of(live, set(), set(), secrets_checked=True)[0] == "main" and live["secret_live"] is True
    dead = secret("not verified")
    assert tier_of(dead, set(), set(), secrets_checked=True)[0] == "review" and dead["secret_live"] is False
    # Verification off: "not verified" means nobody checked.
    assert tier_of(secret("not verified"), set(), set(), secrets_checked=False)[0] == "main"
    # The check itself failed: keep it, never demote an unknown.
    assert tier_of(secret("could not verify"), set(), set(), secrets_checked=True)[0] == "main"


def test_assign_tiers_sets_every_finding_and_uses_tools_seen_in_the_scan():
    rows = [_finding("x/a.php", rule="grephunt.php.sql-injection"), _finding("x/b.php", tool="progpilot", rule="sql_injection")]
    assign_tiers(rows)
    assert [row["tier"] for row in rows] == ["review", "main"]
    assert all("tier_reason" in row for row in rows)


# ---------------------------------------------------------------- unreferenced files

def _project(tmp_path: Path) -> tuple[dict, Path]:
    files = {
        "server.ts": "import { a } from './routes/a'\n",
        "routes/a.ts": "export const a = 1\n",
        "data/fixes/challenge_1.ts": "export const x = req.query.q\n",
        "data/fixes/challenge_2_correct.ts": "export const x = String(req.query.q)\n",
        "public/js/page.js": "document.write(location.hash)\n",
        "public/index.html": '<script src="js/page.js"></script>\n',
        "plugins/loader.ts": "export const p = 1\n",
        "lazy/feature.ts": "export const f = 1\n",
        "boot.ts": "const m = await import('./lazy/' + name)\n",
        "web/page.php": "<?php echo $_GET['a'];\n",
    }
    for path, body in files.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")

    def node(path, language, role="source", entry=False):
        return {"id": f"f:{path}", "kind": "file", "path": path, "language": language, "role": role, "entry_point": entry}

    nodes = [
        node("server.ts", "typescript", entry=True), node("routes/a.ts", "typescript"),
        node("data/fixes/challenge_1.ts", "typescript"), node("data/fixes/challenge_2_correct.ts", "typescript"),
        node("public/js/page.js", "javascript"), node("public/index.html", "html"),
        node("plugins/loader.ts", "typescript"), node("lazy/feature.ts", "typescript"),
        node("boot.ts", "typescript", entry=True), node("web/page.php", "php"),
    ]
    edges = [{"kind": "import", "source": "f:server.ts", "target": "f:routes/a.ts"}]
    return {"files": {"nodes": nodes, "edges": edges}}, tmp_path


def test_only_whole_unloaded_folders_of_static_import_languages_are_not_executed(tmp_path):
    project_map, root = _project(tmp_path)
    found = not_executed_files(project_map, root)
    assert found == {"data/fixes/challenge_1.ts", "data/fixes/challenge_2_correct.ts"}
    # linked from HTML, framework convention folder, dynamic import(), PHP: all stay
    assert "public/js/page.js" not in found
    assert "plugins/loader.ts" not in found
    assert "lazy/feature.ts" not in found
    assert "web/page.php" not in found


# ---------------------------------------------------------------- TruffleHog

def test_trufflehog_status_goes_into_the_title():
    lines = [
        {"DetectorName": "AWS", "Verified": True, "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env", "line": 1}}}},
        {"DetectorName": "Slack", "Verified": False, "SourceMetadata": {"Data": {"Filesystem": {"file": "b.env", "line": 2}}}},
        {"DetectorName": "Github", "Verified": False, "VerificationError": "timeout",
         "SourceMetadata": {"Data": {"Filesystem": {"file": "c.env", "line": 3}}}},
    ]

    class Descriptor:
        version = "3"

    document = trufflehog_jsonl("\n".join(json.dumps(line) for line in lines), Descriptor())
    titles = [result["message"]["text"] for result in document["runs"][0]["results"]]
    assert titles == ["AWS credential (verified live)", "Slack credential (not verified)", "Github credential (could not verify)"]


def test_trufflehog_verify_parameter_is_a_checkbox_on_by_default():
    spec = next(item for item in load_tools()["trufflehog"].descriptor.parameters if item.name == "verify")
    assert spec.type == "bool" and spec.default is True


def test_bool_parameter_coercion():
    spec = ParameterSpec(name="verify", type="bool", default=True)
    assert coerce_parameter(spec, None) is True
    assert coerce_parameter(spec, False) is False
    assert coerce_parameter(spec, "false") is False
    assert coerce_parameter(spec, "on") is True


# ---------------------------------------------------------------- Psalm

def test_psalm_config_tolerates_missing_vendor_and_exit_codes_match_psalm():
    assert 'allowMissingFiles="true"' in (CATALOG / "config" / "psalm.xml").read_text(encoding="utf-8")
    descriptor = yaml.safe_load((CATALOG / "psalm.yaml").read_text(encoding="utf-8"))
    # 2 = issues found (a normal run), 1 = config or fatal error (a failed run).
    assert descriptor["ok_exit_codes"] == [0, 2]


# ---------------------------------------------------------------- KEV / EPSS

def test_feeds_refresh_when_stale_and_enrich_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(feeds, "intel_dir", lambda: tmp_path)
    calls = []

    def fetch(url, target):
        calls.append(url)
        if target.name == "kev.json":
            target.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}), encoding="utf-8")
        else:
            with gzip.open(target, "wt", encoding="utf-8") as handle:
                handle.write("#model\ncve,epss,percentile\nCVE-2021-44228,0.97,0.99\nCVE-2020-0001,0.002,0.1\n")

    feeds.ensure_feeds(fetch=fetch)
    assert len(calls) == 2
    feeds.ensure_feeds(fetch=fetch)  # fresh copies: nothing fetched again
    assert len(calls) == 2
    feeds.ensure_feeds(fetch=fetch, max_age=-1)  # stale: fetched again
    assert len(calls) == 4

    rows = [{"category": "dependency", "cve": ["CVE-2021-44228"]}, {"category": "dependency", "cve": ["CVE-2020-0001"]}]
    feeds.enrich_findings(rows)
    assert rows[0]["kev"] is True and rows[0]["epss"] == 0.97
    assert "kev" not in rows[1] and rows[1]["epss"] == 0.002
    hot = exploitability({**rows[0], "severity": "high"})
    cold = exploitability({**rows[1], "severity": "high"})
    assert hot["score"] > cold["score"]
    assert any("KEV" in factor for factor in hot["factors"])


def test_failed_download_keeps_working_without_feeds(tmp_path, monkeypatch):
    monkeypatch.setattr(feeds, "intel_dir", lambda: tmp_path)
    feeds.kev_cves.cache_clear()
    feeds.epss_scores.cache_clear()

    def broken(url, target):
        raise OSError("offline")

    feeds.ensure_feeds(fetch=broken)
    rows = [{"category": "dependency", "cve": ["CVE-2021-44228"]}]
    assert feeds.enrich_findings(rows) == rows and "epss" not in rows[0]


# ---------------------------------------------------------------- code for the AI reviewer

def test_reviewer_gets_the_enclosing_function_with_line_numbers(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\n\n\ndef ping(host):\n    if not host.isalnum():\n        return None\n    return os.system('ping ' + host)\n\n\ndef other():\n    return 1\n",
        encoding="utf-8",
    )
    kind, code = enclosing_code(tmp_path, "app.py", 7)
    assert kind == "function"
    assert "5|     if not host.isalnum():" in code and "def other" not in code


def test_reviewer_gets_a_short_php_page_whole_and_nothing_outside_the_project(tmp_path):
    (tmp_path / "page.php").write_text(
        "<?php\n$ip = $_GET['ip'];\nif (is_numeric($ip)) {\n  shell_exec('ping ' . $ip);\n}\n", encoding="utf-8")
    kind, code = enclosing_code(tmp_path, "page.php", 4)
    assert kind == "file" and "is_numeric" in code
    assert enclosing_code(tmp_path, "../../etc/passwd", 1) is None
