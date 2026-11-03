"""The AI scan report keeps only findings that can cost money or customer data."""
from __future__ import annotations

from grephunt.finding_model.impact_filter import drop_reason, filter_impactful, impact_class
from grephunt.web_console import ai_explain


def _finding(**overrides) -> dict:
    base = {
        "fingerprint": "f1",
        "correlation_key": "c1",
        "severity": "high",
        "category": "code",
        "rule_id": "rule",
        "title": "Issue",
        "cwe": [],
        "location": {"kind": "file", "path": "app/views.py", "start_line": 10},
        "context": {"routes": [{"id": "r", "label": "GET /items", "params": ["id"]}]},
    }
    base.update(overrides)
    return base


def test_bounty_classes_are_recognised():
    assert impact_class(_finding(cwe=["CWE-89"])) == "Injection (SQL, NoSQL, XML, LDAP, XPath)"
    assert impact_class(_finding(cwe=["CWE-78"])) == "Remote code execution (RCE)"
    assert impact_class(_finding(cwe=["CWE-918"])) == "SSRF"
    assert impact_class(_finding(cwe=["CWE-22"])) == "LFR / LFI / RFI"
    assert impact_class(_finding(cwe=["CWE-639"])) == "IDOR"
    assert impact_class(_finding(cwe=["CWE-862"])) == "Access control"
    assert impact_class(_finding(cwe=["CWE-347"])) == "Authentication / authorization flaw"
    assert impact_class(_finding(cwe=["CWE-640"])) == "Account takeover"
    assert impact_class(_finding(cwe=["CWE-352"])) == "XSS / CSRF"
    assert impact_class(_finding(title="Race condition in coupon redeem")) == "Business logic"
    assert impact_class(_finding(cwe=["CWE-125"])) == "Memory leak"
    assert impact_class(_finding(category="secret", title="AWS key")) == "Authentication / authorization flaw"


def test_hygiene_low_and_test_code_are_dropped():
    assert drop_reason(_finding(cwe=["CWE-328"], title="Weak hash MD5")) == "not an exploitable class"
    assert drop_reason(_finding(title="Missing X-Frame-Options header")) == "not an exploitable class"
    assert drop_reason(_finding(cwe=["CWE-1333"], title="ReDoS")) == "not an exploitable class"
    assert drop_reason(_finding(cwe=["CWE-89"], severity="low")) == "low impact"
    assert drop_reason(_finding(cwe=["CWE-89"], location={"path": "tests/test_db.py"})) == "test or example code"
    assert drop_reason(_finding(cwe=["CWE-89"], ai_verdict="false_positive")) == "false positive"
    assert drop_reason(_finding(category="dependency", cwe=["CWE-79"], severity="medium")) == "low impact"
    assert drop_reason(_finding(cwe=["CWE-89"])) is None


def test_scan_report_sends_only_kept_findings(monkeypatch):
    sent = {}

    def fake_call(provider, api_key, model, text, **kwargs):
        sent["text"] = text
        return "# Report"

    monkeypatch.setattr(ai_explain, "_call", fake_call)
    rows = [
        _finding(fingerprint="sqli", cwe=["CWE-89"], title="SQL injection in search"),
        _finding(fingerprint="md5", cwe=["CWE-328"], title="Weak hash MD5"),
        _finding(fingerprint="info", cwe=["CWE-79"], severity="info"),
    ]
    result = ai_explain.scan_report("gemini", "key", "gemini-2.5-flash", {"target_label": "demo"}, rows)
    assert [item["fingerprint"] for item in result["kept"]] == ["sqli"]
    assert result["filter"]["dropped"] == 2
    assert "SQL injection in search" in sent["text"]
    assert "Weak hash MD5" not in sent["text"]


def test_scan_report_without_impactful_findings_skips_the_ai(monkeypatch):
    monkeypatch.setattr(ai_explain, "_call", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no AI call")))
    rows = [_finding(cwe=["CWE-328"], title="Weak hash MD5")]
    result = ai_explain.scan_report("gemini", "key", "gemini-2.5-flash", {"target_label": "demo"}, rows)
    assert result["kept"] == []
    assert "no exploitable vulnerabilities" in result["text"]
