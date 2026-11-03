"""Attach project-map context to findings: the route that reaches the code, and the database call on the line.

A finding that a scanner reports and the map confirms (a query built from
variables on the same line, behind a route with request parameters) is the
strongest kind of evidence GrepHunt has without running the application.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath

NEAR_LINES = 2
MAX_ROUTES = 3


class MapIndex:
    def __init__(self, project_map: dict) -> None:
        architecture = project_map.get("architecture") or {}
        nodes = {node["id"]: node for node in architecture.get("nodes", [])}
        self.routes: dict[str, list[tuple[int | None, dict]]] = defaultdict(list)
        self.db: dict[str, dict[int, dict]] = defaultdict(dict)
        for edge in architecture.get("edges", []):
            if edge.get("kind") == "handles" and edge.get("target", "").startswith("f:"):
                route = nodes.get(edge["source"])
                if route is None:
                    continue
                handler = edge["target"][2:]
                same_file = next((item["line"] for item in edge.get("evidence", []) if item.get("path") == handler), None)
                meta = route.get("meta") or {}
                self.routes[handler].append((same_file, {
                    "id": route["id"],
                    "label": route.get("label", route["id"]),
                    "params": [f"{item['source']}.{item['name']}" for item in meta.get("params", [])][:12],
                    "framework": meta.get("framework"),
                }))
            elif edge.get("kind") == "db" and edge.get("source", "").startswith("f:"):
                path = edge["source"][2:]
                target = nodes.get(edge["target"], {})
                dynamic = "(dynamic)" in (edge.get("label") or "")
                for item in edge.get("evidence", []):
                    if item.get("path") == path and item.get("line"):
                        self.db[path][item["line"]] = {"target": target.get("label", edge["target"]), "dynamic": dynamic, "line": item["line"]}

    def context(self, path: str, line: int | None) -> dict | None:
        out: dict = {}
        candidates = self.routes.get(path, [])
        if candidates:
            same_file = sorted((item for item in candidates if item[0] is not None), key=lambda item: item[0])
            if same_file and line:
                before = [item for item in same_file if item[0] <= line]
                chosen = [before[-1][1]] if before else []  # code above the first route belongs to none
            else:
                chosen = [route for _, route in candidates]
            unique = {route["id"]: route for route in chosen}
            if unique:
                out["routes"] = list(unique.values())[:MAX_ROUTES]
        if line:
            near = [self.db[path][number] for number in range(line - NEAR_LINES, line + NEAR_LINES + 1) if number in self.db.get(path, {})]
            if near:
                best = max(near, key=lambda item: (item["dynamic"], -abs(item["line"] - line)))
                out["database"] = best
        return out or None


def clean_path(path: str) -> str:
    """A scanner's path as a project-relative path.

    Scanners report /src/app.py (container mount), ./app.py, or, when they ran from a
    folder below the mount (KICS), ../../src/app.py.
    """
    value = path.replace("\\", "/").strip()
    for prefix in ("file://", "/src/", "./"):
        value = value.removeprefix(prefix)
    if value.startswith("../"):
        while value.startswith("../"):
            value = value[3:]
        value = value.removeprefix("src/")
    return str(PurePosixPath(value.lstrip("/"))) if value else ""


_relative = clean_path


def attach_context(findings: list[dict], project_map: dict) -> list[dict]:
    """Add finding["context"] = {"routes": [...], "database": {...}} where the map knows them."""
    if not project_map:
        return findings
    index = MapIndex(project_map)
    for finding in findings:
        location = finding.get("location") or {}
        if not location.get("path"):
            continue
        context = index.context(_relative(location["path"]), location.get("start_line"))
        if context:
            finding["context"] = context
    return findings
