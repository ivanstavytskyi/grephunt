"""Export the project map to Obsidian (JSON Canvas 1.0) and Mermaid.

Both exports apply the person's edits from map_overlay.json: renamed nodes,
notes, own blocks and links, and positions they dragged. Nodes without a saved
position get a simple layered layout: one column per layer, left to right.
The files view is exported at folder level, since thousands of files do not
read as a picture.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath

from grephunt.finding_model.vuln_class import clean_path
from grephunt.project_map.model import ProjectMap

CANVAS_WIDTH = 280
CANVAS_HEIGHT = 90
COLUMN_GAP = 140
ROW_GAP = 30
FOLDER_DEPTH = 2

# JSON Canvas preset colors: 1 red, 2 orange, 3 yellow, 4 green, 5 cyan, 6 purple.
SEVERITY_COLOR = {"critical": "1", "high": "2", "medium": "3"}
KIND_COLOR = {"route": "6", "frontend": "4", "orm": "3", "datastore": "1", "external": "5", "service": "5"}
LAYERS = [("services", "Services"), ("frontend", "Frontend"), ("route", "Routes"), ("backend", "Backend"), ("orm", "ORM"), ("data", "Data")]


def _arch_layer(node: dict) -> str:
    meta = node.get("meta") or {}
    kind = node.get("kind")
    if kind == "route":
        return "route"
    if kind in {"datastore", "external"}:
        return "data"
    if kind == "component" and meta.get("orm"):
        return "orm"
    if kind == "component" and meta.get("service"):
        return "services"
    return "frontend" if node.get("layer") == "frontend" else "backend"


def _subtitle(node: dict) -> str:
    meta = node.get("meta") or {}
    if node.get("kind") == "route":
        params = ", ".join(f"{item['source']}.{item['name']}" for item in meta.get("params", [])[:8])
        handler = meta.get("handler") or ""
        if meta.get("unmatched"):
            return "no route matched"
        return " · ".join(part for part in (handler, params) if part)
    if node.get("kind") == "datastore":
        return ", ".join(meta.get("services", [])) or "database"
    if meta.get("dynamic_sql"):
        return f"{node.get('path') or ''} · {meta['dynamic_sql']} queries built from variables"
    return node.get("path") or str(meta.get("image") or "")


def _folder(path: str, depth: int = FOLDER_DEPTH) -> str:
    parts = PurePosixPath(path).parts[:-1]
    return "/".join(parts[:depth]) or "."


def view_graph(project_map: dict, view: str) -> tuple[list[dict], list[dict]]:
    """(nodes, edges) for a view. Nodes: id, label, subtitle, layer, kind, path. Edges: source, target, kind, label, dynamic."""
    if view == "architecture":
        nodes = [
            {"id": node["id"], "label": node.get("label", node["id"]), "subtitle": _subtitle(node), "layer": _arch_layer(node),
             "kind": "datastore" if node.get("kind") == "datastore" else _arch_layer(node), "path": node.get("path")}
            for node in project_map.get("architecture", {}).get("nodes", [])
        ]
        edges = [
            {"source": edge["source"], "target": edge["target"], "kind": edge["kind"], "label": edge.get("label", ""),
             "dynamic": "(dynamic)" in (edge.get("label") or ""), "evidence": edge.get("evidence", [])[:1]}
            for edge in project_map.get("architecture", {}).get("edges", [])
        ]
        return nodes, edges

    files = project_map.get("files", {})
    by_id = {node["id"]: node for node in files.get("nodes", [])}
    counts: dict[str, int] = defaultdict(int)
    folder_of: dict[str, str] = {}
    for node in files.get("nodes", []):
        if node.get("kind") == "file" and node.get("path"):
            folder = _folder(node["path"])
            folder_of[node["id"]] = folder
            counts[folder] += 1
    nodes = [{"id": f"d:{folder}", "label": f"{folder}/" if folder != "." else "(root)", "subtitle": f"{count} files",
              "layer": "files", "kind": "dir", "path": folder} for folder, count in sorted(counts.items())]
    merged: dict[tuple[str, str], dict] = {}
    for edge in files.get("edges", []):
        source, target = folder_of.get(edge["source"]), folder_of.get(edge["target"])
        if not source or not target or source == target or edge["target"] not in by_id:
            continue
        item = merged.setdefault((source, target), {"source": f"d:{source}", "target": f"d:{target}", "kind": "import", "label": "", "dynamic": False, "count": 0, "evidence": edge.get("evidence", [])[:1]})
        item["count"] += edge.get("count", 1)
    edges = [{**item, "label": f"{item['count']} imports"} for item in merged.values()]
    return nodes, edges


def _apply_overlay(nodes: list[dict], edges: list[dict], overlay_view: dict) -> tuple[list[dict], list[dict]]:
    labels = overlay_view.get("labels") or {}
    notes = overlay_view.get("notes") or {}
    for node in nodes:
        node["label"] = labels.get(node["id"], node["label"])
        node["note"] = notes.get(node["id"], "")
    for block in overlay_view.get("blocks") or []:
        nodes.append({"id": block["id"], "label": block.get("label", "Block"), "subtitle": "", "layer": "notes", "kind": "block",
                      "path": None, "note": notes.get(block["id"], ""), "position": {"x": block.get("x", 0), "y": block.get("y", 0)}})
    ids = {node["id"] for node in nodes}
    for link in overlay_view.get("links") or []:
        if link.get("source") in ids and link.get("target") in ids:
            edges.append({"source": link["source"], "target": link["target"], "kind": "link", "label": link.get("label", ""), "dynamic": False, "evidence": []})
    return nodes, edges


def _positions(nodes: list[dict], overlay_view: dict) -> dict[str, tuple[int, int]]:
    saved = overlay_view.get("positions") or {}
    order = [key for key, _ in LAYERS] + ["files", "notes"]
    columns: dict[str, list[dict]] = defaultdict(list)
    for node in nodes:
        columns[node["layer"]].append(node)
    out: dict[str, tuple[int, int]] = {}
    x = 0
    for layer in [name for name in order if name in columns]:
        members = columns[layer]
        per_column = 40 if layer == "files" else len(members) or 1
        for index, node in enumerate(members):
            column, row = divmod(index, per_column)
            out[node["id"]] = (x + column * (CANVAS_WIDTH + COLUMN_GAP // 2), row * (CANVAS_HEIGHT + ROW_GAP))
        x += (len(members) // per_column + 1) * (CANVAS_WIDTH + COLUMN_GAP // 2) + COLUMN_GAP // 2
    for node in nodes:
        position = saved.get(node["id"]) or node.get("position")
        if position:
            out[node["id"]] = (int(position["x"]), int(position["y"]))
    return out


def _severity(findings: list[dict]) -> tuple[dict[str, str], dict[str, str]]:
    """Worst severity per file path and per route id."""
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    by_path: dict[str, str] = {}
    by_route: dict[str, str] = {}
    for finding in findings:
        severity = finding.get("severity", "info")
        path = clean_path((finding.get("location") or {}).get("path") or "")
        current = by_path.get(path)
        if path and (current is None or rank.get(severity, 4) < rank.get(current, 4)):
            by_path[path] = severity
        for route in (finding.get("context") or {}).get("routes", []):
            current = by_route.get(route["id"])
            if current is None or rank.get(severity, 4) < rank.get(current, 4):
                by_route[route["id"]] = severity
    return by_path, by_route


def to_canvas(project_map: dict, view: str = "architecture", overlay: dict | None = None, findings: list[dict] | None = None) -> dict:
    overlay_view = ((overlay or {}).get("views") or {}).get(view) or {}
    nodes, edges = _apply_overlay(*view_graph(project_map, view), overlay_view)
    positions = _positions(nodes, overlay_view)
    by_path, by_route = _severity(findings or [])
    canvas_nodes: list[dict] = []
    ids: dict[str, str] = {}
    for index, node in enumerate(nodes):
        canvas_id = f"n{index}"
        ids[node["id"]] = canvas_id
        x, y = positions.get(node["id"], (0, 0))
        lines = [f"**{node['label']}**"]
        if node.get("subtitle"):
            lines.append(node["subtitle"])
        if node.get("note"):
            lines += ["", node["note"]]
        item = {"id": canvas_id, "type": "text", "text": "\n".join(lines), "x": x, "y": y, "width": CANVAS_WIDTH, "height": CANVAS_HEIGHT}
        severity = by_route.get(node["id"]) if node["kind"] == "route" else by_path.get(node.get("path") or "")
        color = SEVERITY_COLOR.get(severity or "") or KIND_COLOR.get(node["kind"])
        if node["kind"] == "block":
            color = "3"
        if color:
            item["color"] = color
        canvas_nodes.append(item)
    if view == "architecture" and not overlay_view.get("positions"):
        # Frame each layer in a labelled group so the canvas reads left to right.
        for key, title in LAYERS:
            members = [positions[node["id"]] for node in nodes if node["layer"] == key and node["id"] in positions]
            if not members:
                continue
            left, top = min(x for x, _ in members), min(y for _, y in members)
            right, bottom = max(x for x, _ in members) + CANVAS_WIDTH, max(y for _, y in members) + CANVAS_HEIGHT
            canvas_nodes.insert(0, {"id": f"g-{key}", "type": "group", "label": title, "x": left - 30, "y": top - 60,
                                    "width": right - left + 60, "height": bottom - top + 90})
    canvas_edges = []
    for index, edge in enumerate(edges):
        if edge["source"] not in ids or edge["target"] not in ids:
            continue
        item = {"id": f"e{index}", "fromNode": ids[edge["source"]], "fromSide": "right", "toNode": ids[edge["target"]], "toSide": "left"}
        if edge.get("label"):
            item["label"] = edge["label"][:80]
        if edge.get("dynamic"):
            item["color"] = "1"
        elif edge["kind"] == "link":
            item["color"] = "3"
        canvas_edges.append(item)
    return {"nodes": canvas_nodes, "edges": canvas_edges}


def _mermaid_text(value: str) -> str:
    return re.sub(r"[\"<>{}\[\]|`]", " ", value).replace("#", "&#35;").strip()[:80] or " "


def to_mermaid(project_map: dict, view: str = "architecture", overlay: dict | None = None) -> str:
    overlay_view = ((overlay or {}).get("views") or {}).get(view) or {}
    nodes, edges = _apply_overlay(*view_graph(project_map, view), overlay_view)
    ids = {node["id"]: f"n{index}" for index, node in enumerate(nodes)}
    lines = ["flowchart LR"]
    groups: dict[str, list[dict]] = defaultdict(list)
    for node in nodes:
        groups[node["layer"]].append(node)
    titles = dict(LAYERS) | {"files": "Folders", "notes": "Notes"}
    shapes = {"route": ('(["', '"])'), "datastore": ('[("', '")]'), "orm": ('[["', '"]]'), "block": ('>"', '"]')}
    for layer, members in groups.items():
        lines.append(f'  subgraph {layer}["{titles.get(layer, layer)}"]')
        for node in members:
            open_, close = shapes.get(node["kind"], ('["', '"]'))
            text = _mermaid_text(node["label"])
            if node.get("note"):
                text += "<br/><i>" + _mermaid_text(node["note"].splitlines()[0]) + "</i>"
            lines.append(f"    {ids[node['id']]}{open_}{text}{close}")
        lines.append("  end")
    dynamic_links: list[int] = []
    count = 0
    for edge in edges:
        if edge["source"] not in ids or edge["target"] not in ids:
            continue
        arrow = "-.->" if edge["kind"] == "link" else "-->"
        label = _mermaid_text(edge["label"]) if edge.get("label") else ""
        quoted = f'|"{label}"|' if label else ""
        lines.append(f"  {ids[edge['source']]} {arrow}{quoted} {ids[edge['target']]}")
        if edge.get("dynamic"):
            dynamic_links.append(count)
        count += 1
    if dynamic_links:
        lines.append(f"  linkStyle {','.join(map(str, dynamic_links))} stroke:#e11d48,stroke-width:3px")
    return "\n".join(lines) + "\n"


def write_exports(project_map: ProjectMap, directory: Path) -> None:
    """project_map.canvas and project_map.mmd next to project_map.json (architecture, no edits yet)."""
    data = json.loads(project_map.model_dump_json())
    view = "architecture" if data.get("architecture", {}).get("nodes") else "files"
    (directory / "project_map.canvas").write_text(json.dumps(to_canvas(data, view), indent=1), encoding="utf-8")
    (directory / "project_map.mmd").write_text(to_mermaid(data, view), encoding="utf-8")
