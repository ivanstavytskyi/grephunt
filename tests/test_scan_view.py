"""The skip-build-folders rule: scanners get a copy without node_modules, build and dist."""
from __future__ import annotations

import asyncio
from pathlib import Path

from grephunt.finding_model.record import TaskRun, TaskStatus
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.pipeline import run_scan
from grephunt.scan_pipeline.scan_view import make_scan_view
from grephunt.scanner_catalog.launch import _failure_summary, _failure_text


def _project(root: Path) -> Path:
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.js").write_text("eval(x)", encoding="utf-8")
    (root / "package-lock.json").write_text("{}", encoding="utf-8")
    for folder in ("node_modules/lodash", "build", "frontend/dist"):
        (root / folder).mkdir(parents=True)
        (root / folder / "x.js").write_text("1", encoding="utf-8")
    return root


def test_view_leaves_out_build_and_dependency_folders(tmp_path: Path):
    project = _project(tmp_path / "p")
    view = make_scan_view(project, tmp_path / "views")
    assert (view.root / "src" / "app.js").read_text(encoding="utf-8") == "eval(x)"
    assert (view.root / "package-lock.json").is_file()
    assert not (view.root / "node_modules").exists()
    assert not (view.root / "build").exists()
    assert not (view.root / "frontend" / "dist").exists()
    assert sorted(view.skipped) == ["build", "frontend/dist", "node_modules"]
    assert view.skipped_files == 3
    view.remove()
    assert not view.root.exists()
    assert (project / "node_modules" / "lodash" / "x.js").is_file()


class _Descriptor:
    def __init__(self, needs: bool) -> None:
        self.needs_dependency_dirs = needs


class _Tool:
    def __init__(self, name: str, needs: bool) -> None:
        self.name = name
        self.descriptor = _Descriptor(needs)
        self.seen: Path | None = None

    async def execute(self, project, out_dir, options, on_event):
        self.seen = project
        self.had_node_modules = (project / "node_modules").exists()
        return TaskRun(tool=self.name, status=TaskStatus.SUCCESS)


def test_dependency_scanners_keep_the_full_project(tmp_path: Path, monkeypatch):
    import grephunt.config as config

    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    project = _project(tmp_path / "p")
    code, deps = _Tool("semgrep", False), _Tool("grype", True)
    asyncio.run(run_scan(project, tmp_path / "out", [code, deps], ScanOptions(skip_build_dirs=True, use_docker=False)))
    assert code.had_node_modules is False and code.seen != project
    assert deps.had_node_modules is True and deps.seen == project
    assert not code.seen.exists()


def test_rule_off_scans_everything(tmp_path: Path):
    project = _project(tmp_path / "p")
    code = _Tool("semgrep", False)
    asyncio.run(run_scan(project, tmp_path / "out", [code], ScanOptions(use_docker=False)))
    assert code.seen == project


def test_failure_text_keeps_the_cause_at_the_start():
    raw = "fatal error: runtime: failed to create new OS thread\n" + "\n".join(f"goroutine {i}" for i in range(5000))
    text = _failure_text(raw, "x")
    assert text.startswith("fatal error: runtime: failed to create new OS thread")
    assert "lines skipped" in text
    assert text.endswith("goroutine 4999")
    assert _failure_summary(text) == "fatal error: runtime: failed to create new OS thread"


def test_console_fallback_list_matches_the_server_list():
    import json
    import re

    from grephunt.scan_pipeline.scan_view import SKIP_GROUPS
    from grephunt.scanner_catalog.registry import load_descriptors

    page = (Path(__file__).resolve().parents[1] / "web" / "src" / "pages" / "new-scan.tsx").read_text(encoding="utf-8")
    found = re.findall(r'\{ label: ("[^"]+"), folders: (\[[^\]]*\]) \}', page)
    assert [(json.loads(label), tuple(json.loads(folders))) for label, folders in found] == [
        (label, tuple(names)) for label, names in SKIP_GROUPS
    ]
    from grephunt.scan_pipeline.scan_view import needs_full_project

    descriptors = load_descriptors()
    dependency = json.loads(re.search(r"FALLBACK_DEPENDENCY_SCANNERS = (\[[^\]]*\])", page).group(1))
    secret = json.loads(re.search(r"FALLBACK_SECRET_SCANNERS = (\[[^\]]*\])", page).group(1))
    assert dependency == sorted(name for name, item in descriptors.items() if item.needs_dependency_dirs)
    assert secret == sorted(
        name for name, item in descriptors.items() if needs_full_project(item) and not item.needs_dependency_dirs
    )


def test_secret_scanners_get_the_whole_project(tmp_path: Path, monkeypatch):
    import grephunt.config as config
    from grephunt.finding_model.record import Category

    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    project = _project(tmp_path / "p")
    secrets = _Tool("gitleaks", False)
    secrets.descriptor.category = Category.SECRET
    asyncio.run(run_scan(project, tmp_path / "out", [secrets], ScanOptions(skip_build_dirs=True, use_docker=False)))
    assert secrets.seen == project


def test_secrets_in_build_output_stay_in_the_report():
    from grephunt.finding_model.record import Category, Finding, Location, Module, Severity
    from grephunt.scan_pipeline.excludes import DEFAULT_EXCLUDES
    from grephunt.scan_pipeline.pipeline import accept_finding

    options = ScanOptions(excludes=list(DEFAULT_EXCLUDES))

    def finding(category: Category, path: str) -> Finding:
        return Finding(
            module=Module.SAST, category=category, tool="t", rule_id="r", title="t", message="m",
            severity=Severity.HIGH, location=Location(path=path, start_line=1),
        )

    assert accept_finding(finding(Category.SECRET, "frontend/dist/main.js"), options, set()) is True
    assert accept_finding(finding(Category.CODE, "frontend/dist/main.js"), options, set()) is False
    assert accept_finding(finding(Category.SECRET, "tests/fixtures/key.pem"), options, set()) is False
