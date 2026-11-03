"""Unpack a project archive without leaving the destination directory."""
from __future__ import annotations

import zipfile
from pathlib import Path

MAX_UNCOMPRESSED = 15_000_000_000
MAX_MEMBERS = 450_000

def safe_extract(archive: Path, destination: Path, max_bytes: int = MAX_UNCOMPRESSED) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    total = 0
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > MAX_MEMBERS:
            raise ValueError("the archive contains too many files")
        for info in members:
            name = info.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            if name.startswith("/") or name.startswith("../") or "/../" in f"/{name}/":
                raise ValueError(f"illegal path in the archive: {info.filename}")
            target = (destination / name).resolve()
            if root not in target.parents and target != root:
                raise ValueError(f"illegal path in the archive: {info.filename}")
            total += info.file_size
            if total > max_bytes:
                raise ValueError("unpacked archive is too large")
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info) as source, target.open("wb") as sink:
                sink.write(source.read())
