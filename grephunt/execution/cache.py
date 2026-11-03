"""Host cache directories so a non-root container can write them."""
from __future__ import annotations

import os
from pathlib import Path

from grephunt.config import DATA_DIR
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the catalog imports this module through the hooks
    from grephunt.scanner_catalog.descriptor import ToolDescriptor


def cache_dir(name: str) -> Path:
    """Host directory of one named cache. The same path is mounted into the container."""
    host = DATA_DIR / "caches" / name
    host.mkdir(parents=True, exist_ok=True)
    return host


def cache_binds(descriptor: ToolDescriptor) -> list[tuple[str, str, bool]]:
    root = DATA_DIR / "caches"
    root.mkdir(parents=True, exist_ok=True)
    binds: list[tuple[str, str, bool]] = []
    for item in descriptor.cache_volumes:
        host = root / item.name
        host.mkdir(parents=True, exist_ok=True)
        if os.name != "nt" and not item.read_only:
            os.chmod(host, 0o777)
        binds.append((str(host.resolve()), item.path, item.read_only))
    return binds
