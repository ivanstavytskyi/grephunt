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

# Upload limits for the console (zip, folder, GitHub, and container image tar).
_DEFAULT_UPLOAD_MB = 10_240  # 10 GB


def max_upload_bytes() -> int:
    return int(os.environ.get("GREPHUNT_MAX_UPLOAD_MB", str(_DEFAULT_UPLOAD_MB))) * 1_000_000


def max_image_upload_bytes() -> int:
    return int(os.environ.get("GREPHUNT_MAX_IMAGE_MB", str(_DEFAULT_UPLOAD_MB))) * 1_000_000


def upload_limit_label(limit_bytes: int) -> str:
    mb = limit_bytes // 1_000_000
    if mb >= 1024 and mb % 1024 == 0:
        return f"{mb // 1024} GB"
    return f"{mb} MB"


def database_url() -> str:
    return os.environ.get("GREPHUNT_DATABASE_URL", f"sqlite:///{DB_PATH.as_posix()}")
