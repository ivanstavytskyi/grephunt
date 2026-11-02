"""HTTP console. The panel is served from the same port once web/dist is built."""
from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Body, FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from grephunt.web_console.ai_explain import DEEPSEEK_MODELS, GEMINI_MODELS, check_key, explain_finding
from grephunt.web_console.github_source import download_github_zip
from grephunt.web_console.uploads import safe_extract
from grephunt.web_console.scans import (
    create_scan,
    get_events,
    get_findings,
    get_scan,
    list_scans,
    list_tools,
    session_factory,
)
from grephunt.config import DATA_DIR, WEB_DIST
from grephunt.database.tables import ScanRow, TaskRow
from grephunt.execution.docker import docker_daemon_ready, purge_stale_grephunt_containers

MAX_UPLOAD = 500_000_000
MAX_UPLOAD_LABEL = f"{MAX_UPLOAD // 1_000_000} MB"
_GITHUB_URL = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/tree/([^?#]+))?/?$"
)


def _fail_interrupted() -> None:
    factory = session_factory()
    now = datetime.now(timezone.utc)
    with factory() as session:
        rows = session.query(ScanRow).filter(ScanRow.status == "running").all()
        for row in rows:
            row.status = "failed"
            row.error = "the server stopped while a scan was running"
            if row.finished_at is None:
                row.finished_at = now
            tasks = session.query(TaskRow).filter(
                TaskRow.scan_id == row.id,
                TaskRow.status.in_(("queued", "running")),
            ).all()
            for task in tasks:
                task.status = "failed"
                if not task.error:
                    task.error = row.error
        session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    session_factory()
    _fail_interrupted()
    await asyncio.to_thread(purge_stale_grephunt_containers)
    yield


app = FastAPI(title="GrepHunt", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _collapse_root(path: Path) -> Path:
    entries = [item for item in path.iterdir() if item.name != "__MACOSX" and not item.name.startswith(".")]
    files = [item for item in entries if item.is_file()]
    dirs = [item for item in entries if item.is_dir()]
    if not files and len(dirs) == 1:
        return dirs[0]
    return path


def _relative_upload_path(raw: str) -> Path:
    name = raw.replace("\\", "/").lstrip("/")
    parts = [part for part in name.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        raise ValueError(f"illegal path in the folder: {raw}")
    return Path(*parts)


async def _save_folder(files: list[UploadFile], relative_paths: list[str], folder_name: str) -> tuple[Path, str]:
    if len(files) != len(relative_paths):
        raise HTTPException(status_code=400, detail="folder upload is missing a path for a file")
    if len(files) > 20_000:
        raise HTTPException(status_code=400, detail="the folder contains too many files")
    label = Path(folder_name).name or "project"
    workspace = DATA_DIR / "uploads" / label
    workspace.mkdir(parents=True, exist_ok=True)
    extracted = workspace / "tree"
    if extracted.exists():
        import shutil
        shutil.rmtree(extracted)
    extracted.mkdir(parents=True, exist_ok=True)
    root = extracted.resolve()
    total = 0
    for upload, raw in zip(files, relative_paths, strict=True):
        try:
            relative = _relative_upload_path(raw or upload.filename or "")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        target = (extracted / relative).resolve()
        if root not in target.parents and target != root:
            raise HTTPException(status_code=400, detail=f"illegal path in the folder: {raw}")
        target.parent.mkdir(parents=True, exist_ok=True)
        size = 0
        with target.open("wb") as handle:
            while chunk := await upload.read(1024 * 1024):
                size += len(chunk)
                total += len(chunk)
                if total > MAX_UPLOAD:
                    raise HTTPException(status_code=413, detail=f"folder is larger than {MAX_UPLOAD_LABEL}")
                handle.write(chunk)
    return _collapse_root(extracted), label


def _parse_github(url: str) -> tuple[str, str, str | None]:
    raw = url.strip()
    if "@" in raw or not raw.startswith("https://github.com/"):
        raise ValueError("use a public link like https://github.com/owner/repo")
    match = _GITHUB_URL.match(raw.split("?", 1)[0].split("#", 1)[0])
    if not match:
        raise ValueError("use a public link like https://github.com/owner/repo")
    return match.group(1), match.group(2), match.group(3)


def _download_github(url: str) -> tuple[Path, str]:
    owner, repo, branch = _parse_github(url)
    headers = {"User-Agent": "GrepHunt", "Accept": "application/vnd.github+json"}
    if not branch:
        request = urllib.request.Request(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            raise ValueError("repository was not found, or it is private") from exc
        branch = str(payload.get("default_branch") or "main")
    archive_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{urllib.parse.quote(branch, safe='')}"
    label = f"{owner}/{repo}"
    workspace = DATA_DIR / "uploads" / f"{owner}-{repo}"
    workspace.mkdir(parents=True, exist_ok=True)
    blob = workspace / "source.zip"
    request = urllib.request.Request(archive_url, headers={"User-Agent": "GrepHunt"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response, blob.open("wb") as handle:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_UPLOAD:
                    raise ValueError(f"repository archive is larger than {MAX_UPLOAD_LABEL}")
                handle.write(chunk)
    except urllib.error.HTTPError as exc:
        raise ValueError("repository was not found, or it is private") from exc
    except urllib.error.URLError as exc:
        raise ValueError("could not download the repository") from exc
    extracted = workspace / "tree"
    if extracted.exists():
        import shutil
        shutil.rmtree(extracted)
    safe_extract(blob, extracted)
    return _collapse_root(extracted), label


async def _save_upload(upload: UploadFile, destination: Path) -> None:
    size = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as handle:
        while chunk := await upload.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD:
                raise HTTPException(status_code=413, detail=f"archive is larger than {MAX_UPLOAD_LABEL}")
            handle.write(chunk)


@app.get("/api/health")
def health() -> dict:
    ok, detail = docker_daemon_ready()
    return {"status": "ok" if ok else "degraded", "docker": {"ok": ok, "detail": detail}}


@app.get("/api/tools")
def tools() -> list[dict]:
    return list_tools()


@app.get("/api/scans")
def scans() -> list[dict]:
    return list_scans()


@app.get("/api/scans/{scan_id}")
def scan(scan_id: str) -> dict:
    found = get_scan(scan_id)
    if found is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return found


@app.get("/api/scans/{scan_id}/findings")
def findings(scan_id: str) -> list[dict]:
    found = get_findings(scan_id)
    if found is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return found


@app.get("/api/scans/{scan_id}/log")
def scan_log(scan_id: str) -> list[dict]:
    found = get_events(scan_id, 0)
    if found is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return found


async def _send_after(websocket: WebSocket, scan_id: str, cursor: int) -> int:
    batch = await asyncio.to_thread(get_events, scan_id, cursor) or []
    for event in batch:
        seq = int(event.get("seq") or 0)
        if seq <= cursor:
            continue
        cursor = seq
        await websocket.send_json(event)
    return cursor


@app.websocket("/api/scans/{scan_id}/events")
async def events_ws(websocket: WebSocket, scan_id: str) -> None:
    await websocket.accept()
    current = await asyncio.to_thread(get_scan, scan_id)
    if current is None:
        await websocket.send_json({"type": "scan.missing", "message": "scan not found", "tool": None, "data": {}})
        await websocket.close(code=1000)
        return
    if current["status"] != "running":
        await websocket.close(code=1000)
        return
    cursor = 0
    try:
        while True:
            cursor = await _send_after(websocket, scan_id, cursor)
            current = await asyncio.to_thread(get_scan, scan_id)
            if not current or current["status"] != "running":
                await _send_after(websocket, scan_id, cursor)
                await websocket.close(code=1000)
                return
            await asyncio.sleep(0.4)
    except WebSocketDisconnect:
        return


@app.post("/api/scans")
async def start(
    path: str | None = Form(default=None),
    scanners: str = Form(default="semgrep,trivy"),
    configs: str = Form(default="p/default"),
    use_docker: str = Form(default="true"),
    archive: UploadFile | None = File(default=None),
    files: list[UploadFile] | None = File(default=None),
    relative_paths: list[str] | None = Form(default=None),
    folder_name: str | None = Form(default=None),
    github_url: str | None = Form(default=None),
) -> dict:
    names = [item.strip().lower() for item in scanners.split(",") if item.strip()]
    config_list = [item.strip() for item in configs.split(",") if item.strip()]
    if not names:
        raise HTTPException(status_code=400, detail="select at least one scanner")

    if github_url and github_url.strip():
        try:
            target, label = await asyncio.to_thread(_download_github, github_url.strip())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    elif files:
        target, label = await _save_folder(files, relative_paths or [], folder_name or "project")
    elif archive is not None and archive.filename:
        scan_token = Path(archive.filename).stem or "project"
        workspace = DATA_DIR / "uploads" / scan_token
        workspace.mkdir(parents=True, exist_ok=True)
        blob = workspace / "source.zip"
        await _save_upload(archive, blob)
        extracted = workspace / "tree"
        if extracted.exists():
            import shutil
            shutil.rmtree(extracted)
        try:
            safe_extract(blob, extracted)
        except (ValueError, Exception) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        target = _collapse_root(extracted)
        label = Path(archive.filename).name
    elif github_url and github_url.strip():
        label = "repository"
        workspace = DATA_DIR / "uploads" / "github"
        workspace.mkdir(parents=True, exist_ok=True)
        blob = workspace / "source.zip"
        extracted = workspace / "tree"
        try:
            label, _branch = await asyncio.to_thread(download_github_zip, github_url.strip(), blob, MAX_UPLOAD)
            if extracted.exists():
                import shutil
                shutil.rmtree(extracted)
            safe_extract(blob, extracted)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        target = _collapse_root(extracted)
    elif path and path.strip():
        target = Path(path.strip().strip('"').strip("'")).expanduser().resolve()
        if not target.is_dir():
            raise HTTPException(status_code=400, detail=f"directory not found: {target}")
        label = target.name
    else:
        raise HTTPException(status_code=400, detail="provide a folder path or upload an archive")

    try:
        scan_id = create_scan(target, label, names, config_list or ["p/default"], use_docker.lower() not in {"0", "false", "no"})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return get_scan(scan_id)


_REGISTRY_CONFIG = re.compile(r"^[pr]/[A-Za-z0-9_./-]{1,120}$")


def _rule_rows(document: object) -> list[dict]:
    rules = document.get("rules") if isinstance(document, dict) else None
    if not isinstance(rules, list):
        return []
    rows: list[dict] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        message = rule.get("message")
        text = message if isinstance(message, str) else ""
        rows.append(
            {
                "id": str(rule.get("id") or ""),
                "severity": str(rule.get("severity") or ""),
                "message": " ".join(text.split())[:220],
            }
        )
    return rows


def _preview_rules(config: str) -> dict:
    import yaml

    raw = config.strip().strip('"').strip("'")
    if not raw:
        raise ValueError("enter a rules path")
    if raw.startswith("https://semgrep.dev/"):
        source = raw
    elif _REGISTRY_CONFIG.match(raw):
        source = f"https://semgrep.dev/c/{raw}"
    else:
        source = ""
    if source:
        request = urllib.request.Request(source, headers={"User-Agent": "GrepHunt"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                text = response.read(4_000_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raise ValueError("Semgrep registry did not return this ruleset") from exc
        except urllib.error.URLError as exc:
            raise ValueError("could not reach the Semgrep registry") from exc
        origin = "Semgrep registry"
    else:
        path = Path(raw).expanduser()
        if not path.is_file():
            raise ValueError("rules file was not found on this machine")
        source = str(path.resolve())
        origin = "file on this machine"
        text = path.read_text(encoding="utf-8", errors="replace")[:4_000_000]
    rows = _rule_rows(yaml.safe_load(text))
    shown = rows[:80]
    return {
        "origin": origin,
        "source": source,
        "total": len(rows),
        "shown": len(shown),
        "rules": shown,
    }


@app.get("/api/ai/models")
def ai_models() -> dict:
    return {"gemini": list(GEMINI_MODELS), "deepseek": list(DEEPSEEK_MODELS)}


@app.post("/api/ai/check")
def ai_check(body: dict = Body()) -> dict:
    try:
        check_key(str(body.get("provider") or ""), str(body.get("api_key") or ""), str(body.get("model") or ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True}


@app.post("/api/ai/explain")
def ai_explain(body: dict = Body()) -> dict:
    finding = body.get("finding")
    if not isinstance(finding, dict):
        raise HTTPException(status_code=400, detail="finding is missing")
    try:
        text = explain_finding(
            str(body.get("provider") or ""),
            str(body.get("api_key") or ""),
            str(body.get("model") or ""),
            finding,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"text": text}


@app.get("/api/rules")
def rules_preview(config: str = "p/default") -> dict:
    try:
        return _preview_rules(config)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="could not read these rules") from exc


def _mount_ui(application: FastAPI) -> None:
    if not WEB_DIST.is_dir():
        return
    assets = WEB_DIST / "assets"
    if assets.is_dir():
        application.mount("/assets", StaticFiles(directory=assets), name="assets")

    @application.get("/")
    def index():
        return FileResponse(WEB_DIST / "index.html")

    @application.get("/{full_path:path}")
    def spa(full_path: str):
        candidate = (WEB_DIST / full_path).resolve()
        if candidate.is_file() and WEB_DIST.resolve() in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(WEB_DIST / "index.html")


_mount_ui(app)
