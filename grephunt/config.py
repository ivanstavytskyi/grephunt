"""Paths and settings for one local installation."""
from __future__ import annotations

import os
from pathlib import Path

# The src-code directory. samples, rules, and data sit beside this package.
ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("GREPHUNT_DATA", ROOT / "data"))
DB_PATH = DATA_DIR / "grephunt.db"
DEFAULT_TENANT = os.environ.get("GREPHUNT_TENANT", "local")
PORT = int(os.environ.get("GREPHUNT_PORT", "4000"))
WEB_DIST = ROOT / "web" / "dist"
RULES_DIR = ROOT / "rules"


def database_url() -> str:
    return os.environ.get("GREPHUNT_DATABASE_URL", f"sqlite:///{DB_PATH.as_posix()}")
