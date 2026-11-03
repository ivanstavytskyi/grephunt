from pathlib import Path

from grephunt.web_console.scan_source_context import (
    build_source_excerpts,
    github_file_url,
    infer_github_from_label,
    resolve_scan_source,
)


def test_infer_github_from_label():
    assert infer_github_from_label("ivanstavytskyi/numberlink") == "https://github.com/ivanstavytskyi/numberlink"
    assert infer_github_from_label("not-a-repo") is None


def test_github_file_url():
    url = github_file_url("https://github.com/o/r", "main", "src/app.js", 10)
    assert url == "https://github.com/o/r/blob/main/src/app.js#L10"


def test_build_source_excerpts_reads_local_tree(tmp_path: Path):
    project = tmp_path / "proj"
    file_path = project / "src" / "main.js"
    file_path.parent.mkdir(parents=True)
    file_path.write_text("line1\ninnerHTML = user\nline3\n", encoding="utf-8")
    findings = [
        {
            "severity": "high",
            "category": "code",
            "tool": "bearer",
            "title": "XSS",
            "location": {"path": "src/main.js", "start_line": 2},
        }
    ]
    scan = {
        "target_path": str(project),
        "source_repo_url": "https://github.com/o/r",
        "source_ref": "main",
    }
    excerpts = build_source_excerpts(scan, findings)
    assert len(excerpts) == 1
    assert excerpts[0]["github_url"].endswith("#L2")
    assert any("innerHTML" in line for line in excerpts[0]["lines"])


def test_resolve_scan_source_falls_back_to_label():
    source = resolve_scan_source({"target_label": "owner/repo"})
    assert source["repository_url"] == "https://github.com/owner/repo"
    assert source["browse_url"] == "https://github.com/owner/repo/tree/main"
