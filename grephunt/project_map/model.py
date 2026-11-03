"""The project map: a graph built from source code before the scanners run.

Every edge carries evidence (file and line) found in the code. Nothing here is
guessed by a model: an edge exists because a parser saw an import, a route, an
HTTP call, or a database call.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

MAP_VERSION = 1

NodeKind = Literal["dir", "file", "package", "component", "route", "datastore", "external"]
EdgeKind = Literal["import", "http", "handles", "db", "service"]
Layer = Literal["frontend", "backend", "data", "external", "other"]


class Evidence(BaseModel):
    path: str
    line: int
    text: str = ""


class MapNode(BaseModel):
    id: str
    kind: NodeKind
    label: str
    path: str | None = None
    parent: str | None = None
    """Id of the containing dir or component node."""
    language: str | None = None
    role: str | None = None
    """source, test, config, iac, docs, asset, generated, vendor."""
    layer: Layer | None = None
    entry_point: bool = False
    lines: int | None = None
    meta: dict = Field(default_factory=dict)


class MapEdge(BaseModel):
    id: str
    source: str
    target: str
    kind: EdgeKind
    label: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    count: int = 1


class MapView(BaseModel):
    nodes: list[MapNode] = Field(default_factory=list)
    edges: list[MapEdge] = Field(default_factory=list)


class ProjectMap(BaseModel):
    version: int = MAP_VERSION
    root_label: str
    stats: dict = Field(default_factory=dict)
    stack: dict = Field(default_factory=dict)
    """Languages, frameworks, and datastores detected from manifests and code."""
    files: MapView = Field(default_factory=MapView)
    architecture: MapView = Field(default_factory=MapView)
    unresolved: list[Evidence] = Field(default_factory=list)
    """Places the map could not follow, such as dynamic imports. Shown, not dropped."""
    truncated: bool = False
