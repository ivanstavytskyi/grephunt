from grephunt.web_console.ai_explain import _brief_finding, explain_scan_report


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

    def fake_call(provider, api_key, model, text, require_text=True):
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
    assert '"critical"' in sent["text"]
    assert sent["text"].index("critical") < sent["text"].index("low")
