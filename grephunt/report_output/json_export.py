"""JSON report from an already normalized ScanResult."""
from __future__ import annotations

import json
from pathlib import Path

from grephunt.finding_model.record import ScanResult


def write_findings_json(result: ScanResult, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "findings.json"
    payload = [finding.model_dump(mode="json") for finding in result.findings]
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    meta = {
        "id": result.id,
        "target": result.target,
        "raw_total": result.raw_total,
        "excluded": result.excluded,
        "findings": len(result.findings),
        "merged_sarif": str(result.merged_sarif) if result.merged_sarif else None,
        "runs": [
            {
                "tool": run.tool,
                "status": run.status.value,
                "duration_sec": round(run.duration_sec, 2),
                "tool_version": run.tool_version,
                "image": run.image,
                "error": run.error,
                "sarif_path": str(run.sarif_path) if run.sarif_path else None,
            }
            for run in result.runs
        ],
    }
    (directory / "scan.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
