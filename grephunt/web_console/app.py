"""HTTP console. The panel is served from the same port once web/dist is built."""
from __future__ import annotations

import asyncio
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from grephunt.integrations import snyk as snyk_integration
from grephunt.web_console.ai_explain import (
    DEEPSEEK_MODELS,
    GEMINI_MODELS,
    ProviderError,
    chat_scan_report,
    check_key,
    explain_finding,
    explain_scan_report,
)
from grephunt.web_console.github_source import download_github_zip
from grephunt.web_console.uploads import safe_extract
from grephunt.scan_pipeline.image_archive import detect_image_format
from grephunt.web_console.scans import (
    create_scan,
    dismiss_findings,
    get_events,
    get_findings,
    get_map_overlay,
    get_project_map,
    get_scan,
    get_source,
    list_scans,
    list_tools,
    rebuild_project_map,
    save_map_overlay,
    session_factory,
)
from grephunt.config import DATA_DIR, WEB_DIST, max_image_upload_bytes, max_upload_bytes, upload_limit_label
from grephunt.database.tables import ScanRow, TaskRow
from grephunt.execution.docker import docker_daemon_ready, purge_stale_grephunt_containers

MAX_UPLOAD = max_upload_bytes()
MAX_UPLOAD_LABEL = upload_limit_label(MAX_UPLOAD)
MAX_IMAGE_UPLOAD = max_image_upload_bytes()
MAX_IMAGE_LABEL = upload_limit_label(MAX_IMAGE_UPLOAD)
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


def _download_github(url: str) -> tuple[Path, str, str, str]:
    owner, repo, branch = _parse_github(url)
    headers = {"User-Agent": "GrepHunt", "Accept": "application/vnd.github+json"}
    canonical = f"https://github.com/{owner}/{repo}"
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
    return _collapse_root(extracted), label, canonical, branch


async def _save_upload(upload: UploadFile, destination: Path, limit: int = MAX_UPLOAD) -> None:
    size = 0
    label = f"{limit // 1_000_000} MB"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as handle:
        while chunk := await upload.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                handle.close()
                destination.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail=f"archive is larger than {label}")
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


@app.get("/api/scans/{scan_id}/map")
def project_map(scan_id: str) -> dict:
    found = get_project_map(scan_id)
    if found is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return found


@app.post("/api/scans/{scan_id}/map")
async def project_map_rebuild(scan_id: str) -> dict:
    try:
        found = await asyncio.to_thread(rebuild_project_map, scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if found is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return found


class MapOverlay(BaseModel):
    version: int = 1
    views: dict[str, dict] = {}


@app.get("/api/scans/{scan_id}/map/export")
def project_map_export(scan_id: str, format: str = "canvas", view: str = "architecture") -> Response:
    """The map as an Obsidian canvas or a Mermaid flowchart, with the person's edits applied."""
    from grephunt.project_map.export import to_canvas, to_mermaid

    if format not in {"canvas", "mermaid"} or view not in {"architecture", "files"}:
        raise HTTPException(status_code=400, detail="format is canvas or mermaid; view is architecture or files")
    found = get_project_map(scan_id)
    if found is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if not found:
        raise HTTPException(status_code=409, detail="this scan has no project map yet")
    overlay = get_map_overlay(scan_id) or {}
    label = (get_scan(scan_id) or {}).get("target_label") or found.get("root_label") or scan_id
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", re.sub(r"\.(zip|tar|tgz)$", "", str(label))).strip("-") or scan_id
    if format == "canvas":
        body = json.dumps(to_canvas(found, view, overlay, get_findings(scan_id) or []), indent=1)
        return Response(body, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{name}-{view}.canvas"'})
    return Response(to_mermaid(found, view, overlay), media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}-{view}.mmd"'})


@app.get("/api/scans/{scan_id}/map/overlay")
def project_map_overlay(scan_id: str) -> dict:
    found = get_map_overlay(scan_id)
    if found is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return found


@app.put("/api/scans/{scan_id}/map/overlay")
def project_map_overlay_save(scan_id: str, overlay: MapOverlay) -> dict:
    try:
        saved = save_map_overlay(scan_id, overlay.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    if saved is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return saved


@app.get("/api/scans/{scan_id}/source")
def scan_source(scan_id: str, path: str, line: int | None = None, end_line: int | None = None, context: int = 12) -> dict:
    from grephunt.web_console.source_view import SourceUnavailable

    try:
        found = get_source(scan_id, path, line, end_line, max(0, min(context, 1000)))
    except SourceUnavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if found is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return found


@app.post("/api/scans/{scan_id}/findings/dismiss")
def dismiss_scan_findings(scan_id: str, body: dict = Body()) -> dict:
    raw = body.get("findings")
    if not isinstance(raw, list) or not raw:
        raise HTTPException(status_code=400, detail="findings list is missing")
    keys: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        fingerprint = str(item.get("fingerprint") or "").strip()
        if fingerprint:
            keys.append((fingerprint, str(item.get("correlation_key") or "")))
    if not keys:
        raise HTTPException(status_code=400, detail="findings list is missing")
    if len(keys) > 5000:
        raise HTTPException(status_code=400, detail="too many findings")
    removed = dismiss_findings(scan_id, keys)
    if removed is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return {"removed": removed}


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
    params: str = Form(default=""),
    configs: str = Form(default=""),
    trivy_scanners: str = Form(default=""),
    use_docker: str = Form(default="true"),
    archive: UploadFile | None = File(default=None),
    files: list[UploadFile] | None = File(default=None),
    relative_paths: list[str] | None = Form(default=None),
    folder_name: str | None = Form(default=None),
    github_url: str | None = Form(default=None),
) -> dict:
    names = [item.strip().lower() for item in scanners.split(",") if item.strip()]
    if not names:
        raise HTTPException(status_code=400, detail="select at least one scanner")

    raw_params: dict = {}
    if params and params.strip():
        try:
            parsed = json.loads(params)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="params must be valid JSON") from exc
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail="params must be a JSON object")
        raw_params = parsed
    config_list = [item.strip() for item in configs.split(",") if item.strip()]
    trivy_list = [item.strip().lower() for item in trivy_scanners.split(",") if item.strip()]
    if config_list and "semgrep" in names:
        raw_params.setdefault("semgrep", {})["configs"] = config_list
    if trivy_list and "trivy" in names:
        raw_params.setdefault("trivy", {})["scanners"] = trivy_list

    target_kind = "source"
    image_format = "docker"

    source_repo_url: str | None = None
    source_ref: str | None = None

    if github_url and github_url.strip():
        try:
            target, label, source_repo_url, source_ref = await asyncio.to_thread(
                _download_github, github_url.strip()
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    elif files:
        target, label = await _save_folder(files, relative_paths or [], folder_name or "project")
    elif archive is not None and archive.filename and archive.filename.lower().endswith(".tar"):
        name = Path(archive.filename).name
        workspace = DATA_DIR / "uploads" / f"image-{uuid.uuid4().hex[:12]}"
        target = workspace / "image.tar"
        await _save_upload(archive, target, MAX_IMAGE_UPLOAD)
        try:
            image_format = detect_image_format(target)
        except ValueError as exc:
            target.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        target_kind = "image"
        label = f"{name} (image)"
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
        if target.is_file() and target.suffix.lower() == ".tar":
            try:
                image_format = detect_image_format(target)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            target_kind = "image"
            label = f"{target.name} (image)"
        elif not target.is_dir():
            raise HTTPException(status_code=400, detail=f"directory not found: {target}")
        else:
            label = target.name
    else:
        raise HTTPException(status_code=400, detail="provide a folder path or upload an archive")

    try:
        scan_id = create_scan(
            target,
            label,
            names,
            use_docker.lower() not in {"0", "false", "no"},
            params=raw_params,
            target_kind=target_kind,
            image_format=image_format,
            source_repo_url=source_repo_url,
            source_ref=source_ref,
        )
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


def _same_origin(request: Request) -> None:
    """A page on another site can send a POST here (CORS only hides the answer). The account
    endpoints accept only the console itself."""
    origin = request.headers.get("origin")
    if origin is None:
        return
    host = request.headers.get("host", "")
    allowed = {f"http://{host}", f"https://{host}", "http://127.0.0.1:5173", "http://localhost:5173"}
    if origin not in allowed:
        raise HTTPException(status_code=403, detail="request from another site")


@app.get("/api/integrations/snyk")
def snyk_status() -> dict:
    return snyk_integration.LOGIN.status()


@app.post("/api/integrations/snyk/login")
def snyk_login(request: Request) -> dict:
    """Start the Snyk CLI's OAuth login. The console polls the status for the app.snyk.io address
    and opens it in a popup; Snyk redirects back to the CLI on 127.0.0.1."""
    _same_origin(request)
    return snyk_integration.LOGIN.start()


@app.post("/api/integrations/snyk/cancel")
def snyk_cancel(request: Request) -> dict:
    _same_origin(request)
    snyk_integration.LOGIN.cancel()
    return snyk_integration.LOGIN.status()


@app.post("/api/integrations/snyk/logout")
def snyk_logout(request: Request) -> dict:
    _same_origin(request)
    snyk_integration.LOGIN.cancel()
    snyk_integration.disconnect()
    return snyk_integration.LOGIN.status()


@app.get("/api/ai/models")
def ai_models() -> dict:
    return {"gemini": list(GEMINI_MODELS), "deepseek": list(DEEPSEEK_MODELS)}


@app.post("/api/ai/check")
def ai_check(body: dict = Body()) -> dict:
    try:
        check_key(str(body.get("provider") or ""), str(body.get("api_key") or ""), str(body.get("model") or ""))
    except (ValueError, ProviderError) as exc:
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
    except (ValueError, ProviderError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"text": text}


@app.post("/api/ai/scan-report")
def ai_scan_report(body: dict = Body()) -> dict:
    scan = body.get("scan")
    findings = body.get("findings")
    if not isinstance(scan, dict):
        raise HTTPException(status_code=400, detail="scan summary is missing")
    if not isinstance(findings, list):
        raise HTTPException(status_code=400, detail="findings list is missing")
    if not findings:
        raise HTTPException(status_code=400, detail="this scan has no findings to summarize")
    try:
        text = explain_scan_report(
            str(body.get("provider") or ""),
            str(body.get("api_key") or ""),
            str(body.get("model") or ""),
            scan,
            findings,
        )
    except (ValueError, ProviderError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"text": text}


@app.post("/api/ai/scan-report/chat")
def ai_scan_report_chat(body: dict = Body()) -> dict:
    scan = body.get("scan")
    findings = body.get("findings")
    report = body.get("report")
    messages = body.get("messages")
    if not isinstance(scan, dict):
        raise HTTPException(status_code=400, detail="scan summary is missing")
    if not isinstance(findings, list):
        raise HTTPException(status_code=400, detail="findings list is missing")
    if not isinstance(report, str) or not report.strip():
        raise HTTPException(status_code=400, detail="report text is missing")
    if not isinstance(messages, list):
        raise HTTPException(status_code=400, detail="messages list is missing")
    try:
        text = chat_scan_report(
            str(body.get("provider") or ""),
            str(body.get("api_key") or ""),
            str(body.get("model") or ""),
            scan,
            findings,
            report,
            messages,
        )
    except (ValueError, ProviderError) as exc:
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
