"""CLI.
    python -m grephunt
    python -m grephunt scan ./project [-s semgrep -s trivy] [--local] [--config p/python]
    GREPHUNT_TARGET=./project python -m grephunt scan
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from grephunt.scan_pipeline.events import EventType, ScanEvent
from grephunt.scan_pipeline.options import ScanOptions
from grephunt.scan_pipeline.excludes import IGNORE_FILE, collect_excludes
from grephunt.scan_pipeline.pipeline import run_scan
from grephunt.report_output.console import render_summary
from grephunt.report_output.json_export import write_findings_json
from grephunt.scanner_catalog.registry import load_tools


def _clean_path(raw: str) -> Path:
    return Path(raw.strip().strip('"').strip("'")).expanduser().resolve()


def resolve_project(cli_value: str | None) -> Path:
    raw = cli_value or os.environ.get("GREPHUNT_TARGET")
    if raw:
        path = _clean_path(raw)
        if path.is_dir():
            return path
        print(f"Directory not found: {path}")

    while True:
        try:
            raw = input("Path to the project to scan: ")
        except (EOFError, KeyboardInterrupt):
            sys.exit("\nCancelled.")
        if not raw.strip():
            continue
        path = _clean_path(raw)
        if path.is_dir():
            return path
        print(f"Directory not found: {path}")


def parse_scanners(values: list[str] | None, known: dict) -> list[str]:
    if not values:
        # Cloud scanners (Snyk) upload project data. They run only when named with -s.
        return [name for name, tool in known.items() if tool.descriptor.default_enabled]
    names = [item.strip().lower() for value in values for item in value.split(",") if item.strip()]
    unknown = [name for name in names if name not in known]
    if unknown:
        sys.exit(f"Unknown scanner: {', '.join(unknown)}. Available: {', '.join(known)}")
    return list(dict.fromkeys(names))


def _print_event(event: ScanEvent) -> None:
    if event.type is EventType.FINDING_ACCEPTED:
        return
    tool = f"[{event.tool}] " if event.tool else ""
    print(f"{tool}{event.message}", flush=True)


_MODEL_EXAMPLES = [
    ("Security group rule allows unrestricted egress to any IP address", "Security Group With Unrestricted Egress", True),
    ("EC2 Instance Monitoring Disabled", "Ensure that detailed monitoring is enabled for EC2 instances", True),
    ("Unpinned Actions Full Length Commit SHA", "unpinned action reference (unpinned-uses)", True),
    ("IAM Database Auth Not Enabled", "Ensure RDS database has IAM authentication enabled", True),
    ("Cookie without the Secure flag", "Debug backdoor left in a TODO comment", False),
    ("Variable Without Description", "Ensure that RDS instances have Multi-AZ enabled", False),
]


def _models(action: str, scan_id: str | None) -> int:
    from grephunt.finding_model import embeddings

    if action == "download":
        try:
            folder = embeddings.download()
        except ImportError:
            print("Install the package first: pip install model2vec")
            return 1
        except Exception as exc:  # noqa: BLE001  network, disk, or a missing model: report and stop
            print(f"Download failed: {exc}")
            return 1
        print(f"Model saved to {folder}. Scans now cluster unclassified findings by meaning.")
        return 0

    model = embeddings.get_model()
    if model is None:
        print(f"No model in {embeddings.model_dir()}. Run: python -m grephunt models download")
        return 1
    threshold = embeddings.EMBEDDING_THRESHOLD
    if scan_id is None:
        texts = [text for left, right, _ in _MODEL_EXAMPLES for text in (left, right)]
        matrix = embeddings.similarity_matrix(texts, model)
        for index, (left, right, same) in enumerate(_MODEL_EXAMPLES):
            score = matrix[2 * index][2 * index + 1]
            verdict = "join" if score >= threshold else "apart"
            mark = "ok" if (score >= threshold) == same else "MISS"
            print(f"{score:.2f} {verdict:5} {mark:4} | {left} | {right}")
        print(f"threshold {threshold}")
        return 0

    import json

    from grephunt.config import DATA_DIR
    from grephunt.finding_model.vuln_class import clean_path, iac_topic, vulnerability_class

    path = DATA_DIR / "scans" / scan_id / "findings.json"
    if not path.is_file():
        print(f"No findings for scan {scan_id} at {path}")
        return 1
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("findings", data) if isinstance(data, dict) else data
    pairs = []
    by_file: dict[str, list[dict]] = {}
    for item in items:
        kind = iac_topic(item["rule_id"], item["title"], item.get("message", "")) if item.get("category") == "misconfig" else vulnerability_class(item.get("cwe", []), item["rule_id"], item["title"])
        if kind is None:
            by_file.setdefault(clean_path((item.get("location") or {}).get("path") or ""), []).append(item)
    for group in by_file.values():
        if len(group) < 2:
            continue
        matrix = embeddings.similarity_matrix([f"{item['title']}. {item.get('message', '')[:200]}" for item in group], model)
        for left in range(len(group)):
            for right in range(left + 1, len(group)):
                pairs.append((matrix[left][right], group[left], group[right]))
    pairs.sort(key=lambda pair: -pair[0])
    for score, left, right in pairs[:25]:
        print(f"{score:.2f} {'join' if score >= threshold else 'apart':5} | {left['tool']}: {left['title'][:60]} | {right['tool']}: {right['title'][:60]}")
    print(f"{len(pairs)} pairs of unclassified findings in the same file; threshold {threshold}")
    return 0


def main() -> None:
    tools = load_tools()
    parser = argparse.ArgumentParser(prog="grephunt")
    sub = parser.add_subparsers(dest="cmd")
    scan = sub.add_parser("scan", help="scan a directory")
    scan.add_argument("project", nargs="?", help="path to the project")
    scan.add_argument("--image", type=Path, metavar="TAR", help="container image tar (docker save or OCI layout) instead of a folder")
    scan.add_argument("-o", "--out", type=Path, default=Path("reports"))
    scan.add_argument("--local", action="store_true", help="scanners installed on this machine")
    scan.add_argument("-s", "--scanner", action="append", metavar="NAME")
    scan.add_argument("--config", action="append", help="Semgrep ruleset")
    scan.add_argument("-e", "--exclude", action="append", metavar="PATTERN")
    scan.add_argument("--no-default-excludes", action="store_true")
    sub.add_parser("serve", help="web console on port 4000")
    project_map = sub.add_parser("map", help="build the project map (files, imports, architecture) without scanning")
    project_map.add_argument("project", help="path to the project")
    project_map.add_argument("-o", "--out", type=Path, default=Path("reports"))
    models = sub.add_parser("models", help="sentence-embedding model for clustering findings by meaning")
    models.add_argument("action", choices=["download", "check"], help="download: fetch the model once; check: show how it groups findings")
    models.add_argument("--scan", help="scan id whose findings check compares (default: built-in examples)")
    doctor = sub.add_parser("doctor", help="check Docker and remove stale scanner containers")
    doctor.add_argument(
        "--restart-docker",
        action="store_true",
        help="restart Docker Desktop on Windows, then purge stale containers",
    )
    args = parser.parse_args(sys.argv[1:] if len(sys.argv) > 1 else ["scan"])

    if args.cmd == "map":
        from grephunt.project_map import build_project_map, write_project_map

        project = _clean_path(args.project)
        if not project.is_dir():
            sys.exit(f"Directory not found: {project}")
        built = build_project_map(project)
        written = write_project_map(built, args.out / project.name)
        stats = built.stats
        print(f"Files: {stats['files']} ({stats['parsed_files']} parsed), imports: {stats['import_edges']}, "
              f"external packages: {stats['external_packages']}")
        print(f"Stack: {', '.join(built.stack['frameworks']) or 'no known framework'}; "
              f"data: {', '.join(built.stack['datastores']) or 'none found'}")
        print(f"Architecture: {len(built.architecture.nodes)} nodes, {len(built.architecture.edges)} edges")
        print(f"Map:   {written}")
        return

    if args.cmd == "models":
        sys.exit(_models(args.action, args.scan))

    if args.cmd == "doctor":
        from grephunt.doctor import run_doctor

        sys.exit(run_doctor(restart_docker=args.restart_docker))

    if args.cmd == "serve":
        import socket

        import uvicorn

        from grephunt.config import PORT

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", PORT))
        except OSError:
            sys.exit(
                f"Port {PORT} is already in use. "
                "Another GrepHunt console is already running. "
                "Stop it, or set GREPHUNT_PORT to a free port."
            )
        finally:
            probe.close()
        uvicorn.run("grephunt.web_console.app:app", host="127.0.0.1", port=PORT, reload=False)
        return

    if args.image is not None:
        if args.project:
            sys.exit("Give a project folder or --image, not both.")
        return _scan_image(args, tools)

    names = parse_scanners(args.scanner, tools)
    project = resolve_project(args.project)
    out_dir = args.out / project.name
    mode = "locally" if args.local else "Docker"
    print(f"Scanning: {project}\nReports:   {out_dir.resolve()}\nMode:    {mode}\nScanners:  {', '.join(names)}\n")

    excludes = collect_excludes(project, args.exclude, use_defaults=not args.no_default_excludes)
    sources = (["defaults (tests, build output)"] if not args.no_default_excludes else [])
    sources += [IGNORE_FILE] if (project / IGNORE_FILE).is_file() else []
    sources += ["-e"] if args.exclude else []
    if excludes:
        print(f"Excludes: {len(excludes)} patterns — {', '.join(sources)}\n")

    options = ScanOptions(
        configs=args.config or ["p/default"],
        excludes=excludes,
        use_docker=not args.local,
    )
    selected = [tools[name] for name in names]
    try:
        result = asyncio.run(run_scan(project, out_dir, selected, options, on_event=_print_event))
    except KeyboardInterrupt:
        sys.exit("\nScan interrupted (Ctrl+C). Containers stopped.")

    print()
    print(render_summary(result))
    json_path = write_findings_json(result, out_dir)
    print(f"JSON:  {json_path}")


def _scan_image(args, tools) -> None:
    from grephunt.scan_pipeline.image_archive import detect_image_format

    image = args.image.expanduser().resolve()
    try:
        image_format = detect_image_format(image)
    except ValueError as exc:
        sys.exit(str(exc))
    capable = [
        name
        for name, tool in tools.items()
        if getattr(tool.hook, "supports_image", lambda: False)() and tool.descriptor.default_enabled
    ]
    names = parse_scanners(args.scanner, tools) if args.scanner else capable
    out_dir = args.out / image.stem
    mode = "locally" if args.local else "Docker"
    print(f"Image:     {image} ({image_format})\nReports:   {out_dir.resolve()}\nMode:      {mode}\nScanners:  {', '.join(names)}\n")
    options = ScanOptions(
        configs=args.config or ["p/default"],
        excludes=list(args.exclude or []),
        use_docker=not args.local,
        target_kind="image",
        image_format=image_format,
    )
    selected = [tools[name] for name in names]
    try:
        result = asyncio.run(run_scan(image, out_dir, selected, options, on_event=_print_event))
    except KeyboardInterrupt:
        sys.exit("\nScan interrupted (Ctrl+C). Containers stopped.")
    print()
    print(render_summary(result))
    print(f"JSON:  {write_findings_json(result, out_dir)}")


if __name__ == "__main__":
    main()
