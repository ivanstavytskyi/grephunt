"""Host cache directories so a non-root container can write them."""
from __future__ import annotations

import os
from pathlib import Path

from grephunt.config import DATA_DIR
from grephunt.scanner_catalog.descriptor import ToolDescriptor


def cache_binds(descriptor: ToolDescriptor) -> list[tuple[str, str, bool]]:
    root = DATA_DIR / "caches"
    root.mkdir(parents=True, exist_ok=True)
    binds: list[tuple[str, str, bool]] = []
    for item in descriptor.cache_volumes:
        host = root / item.name
        host.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(host, 0o777)
        binds.append((str(host.resolve()), item.path, False))
    return binds
