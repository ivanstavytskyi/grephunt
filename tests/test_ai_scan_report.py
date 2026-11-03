import json

from grephunt.web_console.ai_explain import _brief_finding, chat_scan_report, explain_scan_report


def test_brief_finding_masks_and_truncates():
    row = _brief_finding(
        {
            "title": "key",
            "severity": "high",
            "message": "x" * 500,
            "snippet": "y" * 300,
            "location": {"path": "a.py", "start_line": 1},
        }
    )
    assert len(row["message"]) <= 400
    assert len(row["snippet"]) <= 240


def test_explain_scan_report_sorts_critical_first(monkeypatch):
    sent = {}

    def fake_call(provider, api_key, model, text, require_text=True, timeout_sec=None):
        sent["text"] = text
        return "ok"

    monkeypatch.setattr("grephunt.web_console.ai_explain._call", fake_call)
    explain_scan_report(
        "gemini",
        "key",
        "gemini-2.5-flash",
        {"target_label": "demo"},
        [
            {"severity": "low", "title": "z", "location": {}},
            {"severity": "critical", "title": "a", "location": {}},
        ],
    )
    payload = json.loads(sent["text"].split("Scan data:\n", 1)[1])
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][1]["severity"] == "low"


def test_explain_scan_report_includes_all_findings_by_default(monkeypatch):
    sent = {}

    def fake_call(provider, api_key, model, text, require_text=True, timeout_sec=None):
        sent["text"] = text
        sent["timeout_sec"] = timeout_sec
        return "ok"

    monkeypatch.setattr("grephunt.web_console.ai_explain._call", fake_call)
    rows = [{"severity": "info", "title": f"f{i}", "location": {}} for i in range(410)]
    explain_scan_report("gemini", "key", "gemini-2.5-flash", {"target_label": "demo"}, rows)
    payload = json.loads(sent["text"].split("Scan data:\n", 1)[1])
    assert payload["finding_count"] == 410
    assert payload["included_in_prompt"] == 410
    assert payload["truncated"] is False
    assert len(payload["findings"]) == 410
    assert sent["timeout_sec"] >= 140


def test_explain_scan_report_includes_github_source(monkeypatch, tmp_path):
    sent = {}

    def fake_call(provider, api_key, model, text, require_text=True, timeout_sec=None):
        sent["text"] = text
        return "ok"

    monkeypatch.setattr("grephunt.web_console.ai_explain._call", fake_call)
    project = tmp_path / "app"
    js = project / "a.js"
    js.parent.mkdir(parents=True)
    js.write_text("alert(1)\n", encoding="utf-8")
    explain_scan_report(
        "gemini",
        "key",
        "gemini-2.5-flash",
        {
            "target_label": "ivanstavytskyi/numberlink",
            "target_path": str(project),
            "source_repo_url": "https://github.com/ivanstavytskyi/numberlink",
            "source_ref": "main",
        },
        [{"severity": "high", "title": "x", "location": {"path": "a.js", "start_line": 1}}],
    )
    payload = json.loads(sent["text"].split("Scan data:\n", 1)[1])
    assert payload["source"]["repository_url"] == "https://github.com/ivanstavytskyi/numberlink"
    assert payload["source"]["code_excerpts"]


def test_chat_scan_report_sends_follow_up(monkeypatch):
    sent = {}

    def fake_chat(provider, api_key, model, messages, timeout_sec=None):
        sent["messages"] = messages
        sent["timeout_sec"] = timeout_sec
        return "answer"

    monkeypatch.setattr("grephunt.web_console.ai_explain._call_chat", fake_chat)
    out = chat_scan_report(
        "deepseek",
        "key",
        "deepseek-chat",
        {"target_label": "demo"},
        [{"severity": "high", "title": "x", "location": {}}],
        "# Report\n\nBody",
        [{"role": "user", "content": "Which issue first?"}],
    )
    assert out == "answer"
    assert sent["timeout_sec"] == 120.0
    assert len(sent["messages"]) == 1
    assert "Follow-up question" in sent["messages"][0]["content"]
    assert "Which issue first?" in sent["messages"][0]["content"]


def test_chat_scan_report_keeps_history(monkeypatch):
    sent = {}

    def fake_chat(provider, api_key, model, messages, timeout_sec=None):
        sent["messages"] = messages
        return "ok"

    monkeypatch.setattr("grephunt.web_console.ai_explain._call_chat", fake_chat)
    chat_scan_report(
        "gemini",
        "key",
        "gemini-2.5-flash",
        {"target_label": "demo"},
        [],
        "report text",
        [
            {"role": "user", "content": "first?"},
            {"role": "assistant", "content": "XSS"},
            {"role": "user", "content": "why?"},
        ],
    )
    roles = [m["role"] for m in sent["messages"]]
    assert roles == ["user", "assistant", "user", "assistant", "user"]
