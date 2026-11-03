"""CISA KEV and FIRST EPSS, cached on disk and read offline.

The catalogs are public. A scan does not need the network once the files are here.
Missing files score as "unknown", they do not fail the scan. EPSS is republished every
day and KEV grows every few days, so a cached file older than a day is fetched again;
when the fetch fails the old copy keeps working.
"""
from __future__ import annotations

import csv
import gzip
import json
import os
import time
import urllib.request
from functools import lru_cache
from pathlib import Path

from grephunt.execution.cache import cache_dir

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# FIRST links here; the URL redirects to that day's dated file on the same host.
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
_TIMEOUT = 25
MAX_AGE_SEC = 24 * 3600


def intel_dir() -> Path:
    return cache_dir("grephunt-intel")


def _stale(path: Path, max_age: float) -> bool:
    try:
        return time.time() - path.stat().st_mtime > max_age
    except OSError:
        return True


def ensure_feeds(fetch=None, max_age: float = MAX_AGE_SEC) -> None:
    """Download a catalog when its cache file is missing or older than max_age. Never raises."""
    if os.environ.get("PYTEST_CURRENT_TEST") and fetch is None:
        return
    directory = intel_dir()
    getter = fetch or _download
    changed = False
    for url, name in ((KEV_URL, "kev.json"), (EPSS_URL, "epss.csv.gz")):
        target = directory / name
        if target.is_file() and not _stale(target, max_age):
            continue
        try:
            getter(url, target)
            changed = True
        except (OSError, ValueError):
            continue
    if changed:
        kev_cves.cache_clear()
        epss_scores.cache_clear()


def _download(url: str, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "GrepHunt"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as response, partial.open("wb") as sink:
        while True:
            chunk = response.read(1024 * 256)
            if not chunk:
                break
            sink.write(chunk)
    partial.replace(target)


@lru_cache(maxsize=1)
def kev_cves() -> frozenset[str]:
    path = intel_dir() / "kev.json"
    if not path.is_file():
        return frozenset()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return frozenset()
    rows = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return frozenset()
    return frozenset(
        str(item.get("cveID") or "").upper()
        for item in rows
        if isinstance(item, dict) and item.get("cveID")
    )


@lru_cache(maxsize=1)
def epss_scores() -> dict[str, float]:
    path = intel_dir() / "epss.csv.gz"
    if not path.is_file():
        return {}
    scores: dict[str, float] = {}
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            lines = (line for line in handle if not line.startswith("#"))
            for row in csv.DictReader(lines):
                cve = str(row.get("cve") or "").upper()
                raw = row.get("epss")
                if not cve or raw is None:
                    continue
                try:
                    scores[cve] = float(raw)
                except ValueError:
                    continue
    except (OSError, gzip.BadGzipFile, csv.Error):
        return {}
    return scores


def enrich_findings(findings: list[dict]) -> list[dict]:
    """Add epss (highest score of the finding's CVEs, 0-1) and kev (any CVE in the catalog). Offline."""
    kev = kev_cves()
    epss = epss_scores()
    if not kev and not epss:
        return findings
    for finding in findings:
        cves = [str(item).upper() for item in finding.get("cve") or [] if str(item).upper().startswith("CVE-")]
        if not cves:
            continue
        scores = [epss[item] for item in cves if item in epss]
        if scores:
            finding["epss"] = max(scores)
        if any(item in kev for item in cves):
            finding["kev"] = True
    return findings
