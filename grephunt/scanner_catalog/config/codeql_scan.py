"""Run CodeQL security-extended on every language this tree actually contains.

The database is created with --build-mode=none, so Python, JavaScript, Java,
Ruby, C#, C/C++, and Rust do not need a project build. Go is not handled:
CodeQL still traces a Go build, and Gosec already covers Go.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "bower_components",
    ".yarn",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
}


@dataclass(frozen=True)
class Language:
    name: str
    extensions: frozenset[str]
    suite: str
    build_mode: str


# Headers alone do not select C/C++. A single .h next to Python is not a C program.
LANGUAGES = (
    Language("python", frozenset({".py"}), "codeql/python-queries:codeql-suites/python-security-extended.qls", "none"),
    Language(
        "javascript-typescript",
        frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}),
        "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        "none",
    ),
    Language("ruby", frozenset({".rb"}), "codeql/ruby-queries:codeql-suites/ruby-security-extended.qls", "none"),
    Language("java-kotlin", frozenset({".java", ".kt"}), "codeql/java-queries:codeql-suites/java-security-extended.qls", "none"),
    Language("csharp", frozenset({".cs"}), "codeql/csharp-queries:codeql-suites/csharp-security-extended.qls", "none"),
    Language("c-cpp", frozenset({".c", ".cc", ".cpp", ".cxx"}), "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls", "none"),
    Language("rust", frozenset({".rs"}), "codeql/rust-queries:codeql-suites/rust-security-extended.qls", "none"),
)


def detect_languages(root: Path) -> list[Language]:
    present: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for name in filenames:
            suffix = Path(name).suffix.lower()
            for language in LANGUAGES:
                if suffix in language.extensions:
                    present.add(language.name)
    return [language for language in LANGUAGES if language.name in present]


def empty_sarif() -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [],
    }


def merge_sarif(documents: list[dict]) -> dict:
    merged = empty_sarif()
    for document in documents:
        runs = document.get("runs")
        if isinstance(runs, list):
            merged["runs"].extend(runs)
    return merged


def _run(command: list[str], env: dict[str, str]) -> None:
    outcome = subprocess.run(command, env=env, text=True, capture_output=True)
    if outcome.returncode != 0:
        tail = "\n".join((outcome.stderr or outcome.stdout or "").splitlines()[-40:])
        raise RuntimeError(tail or f"exit {outcome.returncode}")


def scan(src: Path, out: Path, work: Path, codeql: Path) -> None:
    if not codeql.is_file():
        raise SystemExit(f"CodeQL CLI is missing at {codeql}. The prepare step did not finish.")
    languages = detect_languages(src)
    if not languages:
        out.write_text(json.dumps(empty_sarif()), encoding="utf-8")
        return
    work.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HOME"] = str(work / "home")
    env["TMPDIR"] = str(work / "tmp")
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)
    documents: list[dict] = []
    failed: list[str] = []
    for language in languages:
        db = work / language.name
        part = work / f"{language.name}.sarif"
        shutil.rmtree(db, ignore_errors=True)
        print(f"codeql {language.name}", flush=True)
        try:
            _run(
                [
                    str(codeql),
                    "database",
                    "create",
                    str(db),
                    f"--language={language.name}",
                    f"--source-root={src}",
                    f"--build-mode={language.build_mode}",
                    "--ram=2048",
                    "--threads=2",
                    "--overwrite",
                ],
                env,
            )
            _run(
                [
                    str(codeql),
                    "database",
                    "analyze",
                    str(db),
                    language.suite,
                    "--format=sarifv2.1.0",
                    "--output",
                    str(part),
                    "--ram=2048",
                    "--threads=2",
                ],
                env,
            )
            documents.append(json.loads(part.read_text(encoding="utf-8")))
        except (OSError, RuntimeError, json.JSONDecodeError) as exc:
            failed.append(f"{language.name}: {exc}")
            print(failed[-1], file=sys.stderr, flush=True)
        finally:
            shutil.rmtree(db, ignore_errors=True)
            part.unlink(missing_ok=True)
    if not documents:
        raise SystemExit("CodeQL produced no report.\n" + "\n".join(failed))
    out.write_text(json.dumps(merge_sarif(documents)), encoding="utf-8")
    if failed:
        print("CodeQL skipped a language after another one succeeded:\n" + "\n".join(failed), file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--codeql", type=Path, required=True)
    args = parser.parse_args()
    scan(args.src, args.out, args.work, args.codeql)


if __name__ == "__main__":
    main()
