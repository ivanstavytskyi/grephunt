"""One-off analysis helper for a GrepHunt scan (local)."""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "grephunt.db"


def load(scan_id: str) -> list[dict]:
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT body FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
    conn.close()
    return [json.loads(row[0]) for row in rows]


def main() -> None:
    scan_id = sys.argv[1] if len(sys.argv) > 1 else "f7038eb773ce"
    findings = load(scan_id)
    print(f"scan={scan_id} findings={len(findings)}\n")

    crit = [f for f in findings if f.get("severity") == "critical"]
    print(f"=== CRITICAL ({len(crit)}) ===")
    for f in crit:
        loc = f.get("location") or {}
        title = f.get("title") or f.get("rule_id") or ""
        print(f"{f.get('tool')} | {f.get('category')} | {title[:80]}")
        print(f"  {loc.get('path')}:{loc.get('start_line')}  cve={f.get('cve')}")
        msg = (f.get("message") or "")[:220].replace("\n", " ")
        print(f"  {msg}\n")

    deps = [f for f in findings if f.get("category") == "dependency"]
    print(f"=== DEPENDENCY ({len(deps)}) ===")
    for f in deps:
        loc = f.get("location") or {}
        print(
            f"{f.get('severity')} {f.get('tool')} pkg={f.get('package')} "
            f"ver={f.get('installed_version')} fix={f.get('fixed_version')} "
            f"cve={f.get('cve')} path={loc.get('path')}"
        )

    secrets = [f for f in findings if f.get("category") == "secret"]
    print(f"\n=== SECRETS ({len(secrets)}) ===")
    for f in secrets:
        loc = f.get("location") or {}
        print(f"{f.get('severity')} {f.get('tool')} {loc.get('path')}:{loc.get('start_line')} {f.get('title')[:60]}")

    high_code = [f for f in findings if f.get("severity") in ("critical", "high") and f.get("category") == "code"]
    print(f"\n=== HIGH/CRITICAL CODE ({len(high_code)}) ===")
    for f in sorted(high_code, key=lambda x: (0 if x.get("severity") == "critical" else 1, x.get("tool", ""))):
        loc = f.get("location") or {}
        title = (f.get("title") or f.get("rule_id") or "")[:75]
        print(f"{f.get('severity')} {f.get('tool')} | {title}")
        print(f"  {loc.get('path')}:{loc.get('start_line')}")


if __name__ == "__main__":
    main()
