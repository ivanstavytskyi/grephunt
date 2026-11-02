"""Merge SARIF runs into one report. The reporter does not parse findings again."""
from __future__ import annotations

import json
from pathlib import Path


def merge_sarif_files(paths: list[Path], out_path: Path) -> Path:
    merged = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [],
    }
    for path in paths:
        merged["runs"].extend(json.loads(path.read_text(encoding="utf-8")).get("runs", []))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path
