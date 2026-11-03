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
    doctor = sub.add_parser("doctor", help="check Docker and remove stale scanner containers")
    doctor.add_argument(
        "--restart-docker",
        action="store_true",
        help="restart Docker Desktop on Windows, then purge stale containers",
    )
    args = parser.parse_args(sys.argv[1:] if len(sys.argv) > 1 else ["scan"])

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
