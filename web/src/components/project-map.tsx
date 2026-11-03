import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  applyNodeChanges,
  useReactFlow,
  type Connection,
  type Edge,
  type Node,
  type NodeChange,
  type NodeProps,
} from "@xyflow/react";
import ELK from "elkjs/lib/elk.bundled.js";
import "@xyflow/react/dist/style.css";
import { ChevronDown, ChevronRight, Download, LayoutGrid, Plus, RefreshCw, StickyNote, X } from "lucide-react";
import type { Finding, MapEdge, MapNode, MapOverlay, MapOverlayView, ProjectMap, Severity } from "@/api/types";
import { fetchMapOverlay, fetchProjectMap, rebuildProjectMap, saveMapOverlay } from "@/lib/api";
import { cn } from "@/lib/utils";

type ViewName = "architecture" | "files";

type CardData = {
  title: string;
  subtitle: string;
  kind: string;
  layer: string;
  severity: Severity | null;
  findings: number;
  note: boolean;
  dynamicSql: number;
  entry: boolean;
  dir: boolean;
  expanded: boolean;
  dimmed: boolean;
  block: boolean;
};

type Shape = { id: string; width: number; height: number; partition: number; data: Omit<CardData, "title" | "note" | "dimmed"> & { label: string }; source?: MapNode };
type Link = { id: string; source: string; target: string; kind: string; label: string; count: number; dynamic: boolean; evidence: MapEdge["evidence"] };

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_RING: Record<Severity, string> = {
  critical: "ring-rose-500/80",
  high: "ring-orange-400/80",
  medium: "ring-amber-300/70",
  low: "ring-zinc-400/50",
  info: "ring-sky-400/50",
};
const SEVERITY_TEXT: Record<Severity, string> = {
  critical: "bg-rose-500/20 text-rose-200",
  high: "bg-orange-500/20 text-orange-200",
  medium: "bg-amber-400/20 text-amber-100",
  low: "bg-zinc-500/20 text-zinc-200",
  info: "bg-sky-500/20 text-sky-200",
};
const KIND_STRIPE: Record<string, string> = {
  route: "bg-violet-400",
  frontend: "bg-emerald-400",
  backend: "bg-zinc-300",
  datastore: "bg-rose-400",
  orm: "bg-amber-300",
  external: "bg-sky-400",
  service: "bg-zinc-500",
  dir: "bg-zinc-500",
  file: "bg-zinc-300",
  package: "bg-sky-400",
  block: "bg-signal",
};
const EDGE_STYLE: Record<string, { stroke: string; width: number }> = {
  http: { stroke: "#34d399", width: 1.4 },
  handles: { stroke: "#a78bfa", width: 1.4 },
  db: { stroke: "#fb7185", width: 1.4 },
  import: { stroke: "#71717a", width: 1 },
  service: { stroke: "#38bdf8", width: 1.2 },
  link: { stroke: "#d6f25c", width: 1.6 },
};
// Left to right: infrastructure services (nginx, containers), frontend, routes, backend, ORM, data.
const PARTITION: Record<string, number> = { other: 0, frontend: 1, route: 2, backend: 3, orm: 4, data: 5, external: 5 };

const elk = new ELK();

/** Paths as the map stores them; scanners report /src/x, ./x, ../../src/x. */
function cleanPath(path: string): string {
  let value = path.replace(/\\/g, "/").trim();
  for (const prefix of ["file://", "/src/", "./"]) if (value.startsWith(prefix)) value = value.slice(prefix.length);
  if (value.startsWith("../")) {
    while (value.startsWith("../")) value = value.slice(3);
    if (value.startsWith("src/")) value = value.slice(4);
  }
  return value.replace(/^\/+/, "");
}

function worst(left: Severity | null, right: Severity | null): Severity | null {
  if (!left) return right;
  if (!right) return left;
  return SEVERITY_RANK[left] <= SEVERITY_RANK[right] ? left : right;
}

type FindingIndex = {
  byPath: Map<string, { severity: Severity; count: number }>;
  byRoute: Map<string, { severity: Severity; count: number }>;
};

function indexFindings(findings: Finding[], knownPaths: Set<string>): FindingIndex {
  const byPath = new Map<string, { severity: Severity; count: number }>();
  const byRoute = new Map<string, { severity: Severity; count: number }>();
  const add = (map: typeof byPath, key: string, severity: Severity) => {
    const current = map.get(key);
    map.set(key, { severity: worst(current?.severity ?? null, severity) as Severity, count: (current?.count ?? 0) + 1 });
  };
  for (const finding of findings) {
    const raw = finding.location?.path;
    if (raw) {
      let path = cleanPath(raw);
      if (!knownPaths.has(path) && path.startsWith("src/") && knownPaths.has(path.slice(4))) path = path.slice(4);
      add(byPath, path, finding.severity);
    }
    for (const route of finding.context?.routes ?? []) add(byRoute, route.id, finding.severity);
  }
  return { byPath, byRoute };
}

function cardSize(label: string, subtitle: string): { width: number; height: number } {
  const longest = Math.max(label.length, subtitle.length * 0.82);
  return { width: Math.round(Math.min(300, Math.max(170, longest * 7 + 56))), height: subtitle ? 58 : 44 };
}

function archKind(node: MapNode): string {
  if (node.kind === "route") return "route";
  if (node.kind === "datastore") return "datastore";
  if (node.kind === "external") return "external";
  if (node.kind === "component" && node.meta.orm) return "orm";
  if (node.kind === "component" && node.meta.service) return "service";
  return node.layer === "frontend" ? "frontend" : "backend";
}

function archSubtitle(node: MapNode): string {
  const meta = node.meta as Record<string, unknown>;
  if (node.kind === "route") {
    const params = (meta.params as { source: string; name: string }[] | undefined) ?? [];
    const framework = (meta.framework as string) ?? "";
    if (meta.unmatched) return "no route matched";
    return [framework, params.length ? `${params.length} params` : ""].filter(Boolean).join(" · ");
  }
  if (node.kind === "datastore") return ((meta.services as string[] | undefined) ?? []).join(", ") || "database";
  if (node.kind === "component" && meta.service) return (meta.image as string) || (meta.build ? `build ${meta.build}` : "service");
  if (node.kind === "component" && meta.orm) return "ORM";
  return (meta.dir as string) ?? node.path ?? "";
}

/** Nodes and links of one view, before positions. */
const GROUP_THRESHOLD = 60;
const FOCUS_DEPTH = 4;

const MAX_GROUPS_PER_LAYER = 18;

/** Group key for the overview of a large architecture: routes by path prefix, files by folder, at a given depth. */
function archGroup(node: MapNode, depth: number): { id: string; label: string; kind: string } | null {
  if (node.kind === "route") {
    const parts = String(node.meta.path ?? "").split("/").filter((part) => part && !/^[:{<*(]/.test(part));
    const prefix = node.meta.unmatched ? "unmatched calls" : `/${parts.slice(0, depth).join("/")}`;
    return { id: `g:route:${prefix}`, label: prefix, kind: "route" };
  }
  if (node.kind === "file") {
    const parts = String(node.meta.dir ?? ".").split("/").filter((part) => part && part !== ".");
    const dir = parts.slice(0, depth + 1).join("/") || ".";
    const layer = node.layer === "frontend" ? "frontend" : "backend";
    return { id: `g:${layer}:${dir}`, label: `${dir === "." ? "(root)" : dir}/`, kind: layer };
  }
  return null;
}

/** The deepest grouping per layer that still fits on screen (at most MAX_GROUPS_PER_LAYER groups). */
function chooseDepths(nodes: MapNode[]): Record<string, number> {
  const depths: Record<string, number> = {};
  for (const kind of ["route", "frontend", "backend"]) {
    const members = nodes.filter((node) =>
      kind === "route" ? node.kind === "route" : node.kind === "file" && (node.layer === "frontend") === (kind === "frontend"),
    );
    let chosen = 1;
    for (const depth of [4, 3, 2, 1]) {
      const groups = new Set(members.map((node) => archGroup(node, depth)?.id));
      if (groups.size <= MAX_GROUPS_PER_LAYER) {
        chosen = depth;
        break;
      }
    }
    depths[kind] = chosen;
  }
  return depths;
}

/** Nodes reachable from focus along the flow (down and up), so one request path stands alone. */
function neighbourhood(edges: MapEdge[], focus: string): Set<string> {
  const out = new Map<string, string[]>();
  const into = new Map<string, string[]>();
  for (const edge of edges) {
    out.set(edge.source, [...(out.get(edge.source) ?? []), edge.target]);
    into.set(edge.target, [...(into.get(edge.target) ?? []), edge.source]);
  }
  const keep = new Set([focus]);
  for (const graph of [out, into]) {
    let frontier = [focus];
    for (let depth = 0; depth < FOCUS_DEPTH && frontier.length; depth += 1) {
      const next: string[] = [];
      for (const id of frontier) {
        for (const neighbour of graph.get(id) ?? []) {
          if (!keep.has(neighbour)) {
            keep.add(neighbour);
            next.push(neighbour);
          }
        }
      }
      frontier = next;
    }
  }
  return keep;
}

function buildStructure(
  map: ProjectMap,
  view: ViewName,
  expanded: Set<string>,
  filters: { unmatched: boolean; middleware: boolean; packages: boolean; services: boolean },
  index: FindingIndex,
  focus: string | null = null,
): { shapes: Shape[]; links: Link[] } {
  if (view === "architecture") {
    let nodes = map.architecture.nodes.filter((node) => {
      if (node.meta.unmatched && !filters.unmatched) return false;
      if (node.kind === "route" && node.meta.method === "USE" && !filters.middleware) return false;
      if (node.meta.service && !filters.services) return false;
      return true;
    });
    if (focus) {
      const keep = neighbourhood(map.architecture.edges, focus);
      nodes = nodes.filter((node) => keep.has(node.id));
    }
    const grouping = !focus && nodes.length > GROUP_THRESHOLD;
    const groupOf = new Map<string, { id: string; label: string; kind: string }>();
    if (grouping) {
      const depths = chooseDepths(nodes);
      for (const node of nodes) {
        const kind = node.kind === "route" ? "route" : node.layer === "frontend" ? "frontend" : "backend";
        const group = archGroup(node, depths[kind] ?? 1);
        if (group && !expanded.has(group.id)) groupOf.set(node.id, group);
      }
      // A group of one is just the node.
      const sizes = new Map<string, number>();
      for (const group of groupOf.values()) sizes.set(group.id, (sizes.get(group.id) ?? 0) + 1);
      for (const [id, group] of [...groupOf]) if ((sizes.get(group.id) ?? 0) < 2) groupOf.delete(id);
    }
    const groupShapes = new Map<string, Shape>();
    for (const node of nodes) {
      const group = groupOf.get(node.id);
      if (!group) continue;
      const hit = node.kind === "route" ? index.byRoute.get(node.id) : node.path ? index.byPath.get(node.path) : undefined;
      let shape = groupShapes.get(group.id);
      if (!shape) {
        shape = {
          id: group.id, width: 0, height: 0, partition: PARTITION[group.kind] ?? 5,
          data: { label: group.label, subtitle: "", kind: group.kind, layer: group.kind, severity: null, findings: 0, dynamicSql: 0, entry: false, dir: true, expanded: false, block: false },
        };
        groupShapes.set(group.id, shape);
      }
      shape.data.findings += hit?.count ?? 0;
      shape.data.severity = worst(shape.data.severity, hit?.severity ?? null);
      shape.data.dynamicSql += Number(node.meta.dynamic_sql ?? 0);
      shape.data.subtitle = String(Number(shape.data.subtitle.split(" ")[0] || 0) + 1) + (group.kind === "route" ? " routes" : " files");
    }
    for (const shape of groupShapes.values()) Object.assign(shape, cardSize(shape.data.label, shape.data.subtitle));
    const ids = new Set(nodes.map((node) => node.id));
    const shapes: Shape[] = nodes.filter((node) => !groupOf.has(node.id)).map((node) => {
      const kind = archKind(node);
      const subtitle = archSubtitle(node);
      const hit = node.kind === "route" ? index.byRoute.get(node.id) : node.path ? index.byPath.get(node.path) : undefined;
      return {
        id: node.id,
        ...cardSize(node.label, subtitle),
        partition: PARTITION[kind === "datastore" ? "data" : kind === "service" ? "other" : kind] ?? 5,
        source: node,
        data: {
          label: node.label,
          subtitle,
          kind,
          layer: node.layer ?? "other",
          severity: hit?.severity ?? null,
          findings: hit?.count ?? 0,
          dynamicSql: Number(node.meta.dynamic_sql ?? 0),
          entry: Boolean(node.entry_point),
          dir: false,
          expanded: false,
          block: false,
        },
      };
    });
    const merged = new Map<string, Link>();
    for (const edge of map.architecture.edges) {
      if (!ids.has(edge.source) || !ids.has(edge.target)) continue;
      const source = groupOf.get(edge.source)?.id ?? edge.source;
      const target = groupOf.get(edge.target)?.id ?? edge.target;
      if (source === target) continue;
      const grouped = source !== edge.source || target !== edge.target;
      const key = grouped ? `agg:${edge.kind}:${source}->${target}` : edge.id;
      const dynamic = edge.label.includes("(dynamic)");
      const current = merged.get(key);
      if (current) {
        current.count += edge.count;
        current.dynamic = current.dynamic || dynamic;
        if (current.evidence.length < 5) current.evidence = [...current.evidence, ...edge.evidence].slice(0, 5);
        continue;
      }
      merged.set(key, { id: key, source, target, kind: edge.kind, label: grouped ? "" : edge.label, count: edge.count, dynamic, evidence: edge.evidence.slice(0, 5) });
    }
    return { shapes: [...shapes, ...groupShapes.values()], links: [...merged.values()] };
  }

  // Files view: folders collapse; a hidden node is drawn as its nearest visible folder.
  const byId = new Map(map.files.nodes.map((node) => [node.id, node]));
  const visible = (node: MapNode): boolean => {
    let parent = node.parent ? byId.get(node.parent) : undefined;
    while (parent) {
      if (!expanded.has(parent.id)) return false;
      parent = parent.parent ? byId.get(parent.parent) : undefined;
    }
    return true;
  };
  const representative = new Map<string, string>();
  const resolve = (node: MapNode): string => {
    const cached = representative.get(node.id);
    if (cached) return cached;
    let result = node.id;
    const chain: MapNode[] = [];
    let parent = node.parent ? byId.get(node.parent) : undefined;
    while (parent) {
      chain.push(parent);
      parent = parent.parent ? byId.get(parent.parent) : undefined;
    }
    for (const ancestor of chain.reverse()) {
      if (!expanded.has(ancestor.id)) {
        result = ancestor.id;
        break;
      }
    }
    representative.set(node.id, result);
    return result;
  };
  const counts = new Map<string, number>();
  const severity = new Map<string, { severity: Severity; count: number }>();
  for (const node of map.files.nodes) {
    if (node.kind !== "file") continue;
    const hit = node.path ? index.byPath.get(node.path) : undefined;
    let parent = node.parent ? byId.get(node.parent) : undefined;
    while (parent) {
      counts.set(parent.id, (counts.get(parent.id) ?? 0) + 1);
      if (hit) {
        const current = severity.get(parent.id);
        severity.set(parent.id, { severity: worst(current?.severity ?? null, hit.severity) as Severity, count: (current?.count ?? 0) + hit.count });
      }
      parent = parent.parent ? byId.get(parent.parent) : undefined;
    }
  }
  const shapes: Shape[] = [];
  for (const node of map.files.nodes) {
    if (node.kind === "package" && !filters.packages) continue;
    if (!visible(node)) continue;
    const isDir = node.kind === "dir";
    const fileCount = isDir ? (counts.get(node.id) ?? Number(node.meta.files ?? 0)) : 0;
    const subtitle = isDir
      ? node.role === "vendor"
        ? `vendor · ${fileCount} packages`
        : `${fileCount} files`
      : node.kind === "package"
        ? String(node.meta.ecosystem ?? "package")
        : [node.language, node.lines ? `${node.lines} lines` : "", node.role !== "source" ? node.role : ""].filter(Boolean).join(" · ");
    const hit = isDir ? severity.get(node.id) : node.path ? index.byPath.get(node.path) : undefined;
    // Opened folders put their children among the top-level items: say where each one lives.
    const parentPath = node.parent ? (byId.get(node.parent)?.path ?? "") : "";
    const where = parentPath ? `${parentPath}/ · ` : "";
    shapes.push({
      id: node.id,
      ...cardSize(isDir ? `${node.label}/` : node.label, where + subtitle),
      partition: 0,
      source: node,
      data: {
        label: isDir ? `${node.label}/` : node.label,
        subtitle: where + subtitle,
        kind: node.kind === "package" ? "package" : isDir ? "dir" : "file",
        layer: "other",
        severity: hit?.severity ?? null,
        findings: hit?.count ?? 0,
        dynamicSql: 0,
        entry: Boolean(node.entry_point),
        dir: isDir && node.role !== "vendor",
        expanded: expanded.has(node.id),
        block: false,
      },
    });
  }
  const shown = new Set(shapes.map((shape) => shape.id));
  const merged = new Map<string, Link>();
  for (const edge of map.files.edges) {
    const sourceNode = byId.get(edge.source);
    const targetNode = byId.get(edge.target);
    if (!sourceNode || !targetNode) continue;
    const source = resolve(sourceNode);
    const target = resolve(targetNode);
    if (source === target || !shown.has(source) || !shown.has(target)) continue;
    const key = `${source}->${target}`;
    const current = merged.get(key);
    if (current) {
      current.count += edge.count;
      if (current.evidence.length < 5) current.evidence = [...current.evidence, ...edge.evidence].slice(0, 5);
    } else {
      merged.set(key, { id: `agg:${key}`, source, target, kind: "import", label: "", count: edge.count, dynamic: false, evidence: edge.evidence.slice(0, 5) });
    }
  }
  return { shapes, links: [...merged.values()] };
}

async function layout(shapes: Shape[], links: Link[], view: ViewName): Promise<Record<string, { x: number; y: number }>> {
  const graph = {
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "RIGHT",
      "elk.spacing.nodeNode": "22",
      "elk.layered.spacing.nodeNodeBetweenLayers": view === "architecture" ? "110" : "70",
      "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
      "elk.partitioning.activate": view === "architecture" ? "true" : "false",
      "elk.separateConnectedComponents": "true",
    },
    children: shapes.map((shape) => ({
      id: shape.id,
      width: shape.width,
      height: shape.height,
      layoutOptions: (view === "architecture" ? { "elk.partitioning.partition": String(shape.partition) } : {}) as Record<string, string>,
    })),
    edges: links.map((link) => ({ id: link.id, sources: [link.source], targets: [link.target] })),
  };
  const result = await elk.layout(graph);
  const positions: Record<string, { x: number; y: number }> = {};
  for (const child of result.children ?? []) positions[child.id] = { x: child.x ?? 0, y: child.y ?? 0 };
  return positions;
}

function MapCard({ data, selected }: NodeProps<Node<CardData>>) {
  return (
    <div
      className={cn(
        "relative flex h-full w-full overflow-hidden rounded-md border bg-ink-panel text-left shadow-sm transition-opacity",
        selected ? "border-signal" : "border-ink-line",
        data.severity && `ring-2 ${SEVERITY_RING[data.severity]}`,
        data.dimmed && "opacity-25",
      )}
    >
      <Handle type="target" position={Position.Left} className="!size-2 !border-0 !bg-zinc-500" />
      <span className={cn("w-1 shrink-0", KIND_STRIPE[data.kind] ?? "bg-zinc-500")} />
      <div className="min-w-0 flex-1 px-2.5 py-1.5">
        <div className="flex items-center gap-1.5">
          {data.dir && (data.expanded ? <ChevronDown className="size-3.5 shrink-0 text-ink-muted" /> : <ChevronRight className="size-3.5 shrink-0 text-ink-muted" />)}
          <p className={cn("truncate text-[12px] font-medium leading-4 text-ink-text", data.kind === "route" && "font-mono text-[11px]")} title={data.title}>
            {data.title}
          </p>
          {data.note && <StickyNote className="size-3 shrink-0 text-signal" />}
        </div>
        {data.subtitle && <p className="truncate text-[10.5px] leading-4 text-ink-muted" title={data.subtitle}>{data.subtitle}</p>}
        <div className="absolute right-1.5 top-1 flex gap-1">
          {data.entry && <span className="rounded bg-emerald-500/20 px-1 text-[9px] uppercase tracking-wide text-emerald-200">entry</span>}
          {data.dynamicSql > 0 && <span className="rounded bg-rose-500/25 px-1 text-[9px] uppercase tracking-wide text-rose-200" title="Queries built from variables">sql</span>}
          {data.severity && data.findings > 0 && (
            <span className={cn("rounded px-1 font-mono text-[9.5px]", SEVERITY_TEXT[data.severity])}>{data.findings}</span>
          )}
        </div>
      </div>
      <Handle type="source" position={Position.Right} className="!size-2 !border-0 !bg-zinc-500" />
    </div>
  );
}

const NODE_TYPES = { card: MapCard };

const EMPTY_VIEW: MapOverlayView = { positions: {}, labels: {}, notes: {}, blocks: [], links: [] };

function MapCanvas({ scanId, title, map, findings, overlay, onOverlay, onRebuild, rebuilding, onClose }: {
  scanId: string;
  title: string;
  map: ProjectMap;
  findings: Finding[];
  overlay: MapOverlay;
  onOverlay: (next: MapOverlay) => void;
  onRebuild: () => void;
  rebuilding: boolean;
  onClose: () => void;
}) {
  const flow = useReactFlow();
  const [view, setView] = useState<ViewName>(map.architecture.nodes.length > 0 ? "architecture" : "files");
  const [expanded, setExpanded] = useState<Set<string>>(() =>
    map.files.nodes.filter((node) => node.kind === "file").length <= 60
      ? new Set(map.files.nodes.filter((node) => node.kind === "dir" && node.role !== "vendor").map((node) => node.id))
      : new Set(),
  );
  const [filters, setFilters] = useState({ unmatched: true, middleware: false, packages: false, services: true });
  const [archExpanded, setArchExpanded] = useState<Set<string>>(() => new Set());
  const [focus, setFocus] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<{ type: "node" | "edge"; id: string } | null>(null);
  const [layoutPositions, setLayoutPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [laying, setLaying] = useState(false);
  const [nodes, setNodes] = useState<Node<CardData>[]>([]);

  const current: MapOverlayView = useMemo(() => ({ ...EMPTY_VIEW, ...(overlay.views[view] ?? {}) }), [overlay, view]);
  const updateView = useCallback(
    (change: (value: MapOverlayView) => MapOverlayView) => {
      const base = { ...EMPTY_VIEW, ...(overlay.views[view] ?? {}) };
      onOverlay({ ...overlay, views: { ...overlay.views, [view]: change(base) } });
    },
    [onOverlay, overlay, view],
  );

  const knownPaths = useMemo(() => new Set(map.files.nodes.filter((node) => node.path).map((node) => node.path as string)), [map]);
  const index = useMemo(() => indexFindings(findings, knownPaths), [findings, knownPaths]);
  const structure = useMemo(
    () => buildStructure(map, view, view === "files" ? expanded : archExpanded, filters, index, view === "architecture" ? focus : null),
    [map, view, expanded, archExpanded, filters, index, focus],
  );
  const structureKey = useMemo(
    () => `${view}|${structure.shapes.map((shape) => shape.id).join(",")}|${structure.links.length}`,
    [structure, view],
  );

  // Layout runs when the set of nodes changes, not when labels or notes change.
  useEffect(() => {
    let cancelled = false;
    setLaying(true);
    layout(structure.shapes, structure.links, view)
      .then((positions) => {
        if (!cancelled) setLayoutPositions(positions);
      })
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) setLaying(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [structureKey]);

  const query = search.trim().toLowerCase();
  const derived = useMemo<Node<CardData>[]>(() => {
    const out: Node<CardData>[] = structure.shapes.map((shape) => {
      const title = current.labels?.[shape.id] || shape.data.label;
      const match = !query || title.toLowerCase().includes(query) || (shape.source?.path ?? "").toLowerCase().includes(query);
      const position = current.positions?.[shape.id] ?? layoutPositions[shape.id];
      return {
        id: shape.id,
        type: "card",
        position: position ?? { x: 0, y: 0 },
        hidden: !position,
        width: shape.width,
        height: shape.height,
        deletable: false,
        selected: selected?.type === "node" && selected.id === shape.id,
        data: { ...shape.data, title, note: Boolean(current.notes?.[shape.id]), dimmed: !match },
      };
    });
    for (const block of current.blocks ?? []) {
      const subtitle = current.notes?.[block.id] ? current.notes[block.id].split("\n")[0].slice(0, 60) : "your block";
      out.push({
        id: block.id,
        type: "card",
        position: current.positions?.[block.id] ?? { x: block.x, y: block.y },
        ...cardSize(block.label, subtitle),
        deletable: true,
        selected: selected?.type === "node" && selected.id === block.id,
        data: {
          title: block.label, subtitle, kind: "block", layer: "other", severity: null, findings: 0, note: false,
          dynamicSql: 0, entry: false, dir: false, expanded: false, dimmed: Boolean(query) && !block.label.toLowerCase().includes(query), block: true,
        },
      });
    }
    return out;
  }, [structure, current, layoutPositions, query, selected]);

  useEffect(() => setNodes(derived), [derived]);

  const edges = useMemo<Edge[]>(() => {
    const generated: Edge[] = structure.links.map((link) => {
      const style = EDGE_STYLE[link.kind] ?? EDGE_STYLE.import;
      return {
        id: link.id,
        source: link.source,
        target: link.target,
        type: "smoothstep",
        deletable: false,
        animated: link.dynamic,
        selected: selected?.type === "edge" && selected.id === link.id,
        style: { stroke: link.dynamic ? "#f43f5e" : style.stroke, strokeWidth: link.dynamic ? 2.2 : style.width + Math.min(2, Math.log10(link.count + 1)) },
        markerEnd: { type: MarkerType.ArrowClosed, color: link.dynamic ? "#f43f5e" : style.stroke, width: 14, height: 14 },
      };
    });
    const ids = new Set(derived.map((node) => node.id));
    const custom: Edge[] = (current.links ?? [])
      .filter((link) => ids.has(link.source) && ids.has(link.target))
      .map((link) => ({
        id: link.id,
        source: link.source,
        target: link.target,
        type: "smoothstep",
        label: link.label || undefined,
        deletable: true,
        selected: selected?.type === "edge" && selected.id === link.id,
        style: { stroke: EDGE_STYLE.link.stroke, strokeWidth: EDGE_STYLE.link.width, strokeDasharray: "6 4" },
        labelStyle: { fill: "#e4e4e7", fontSize: 11 },
        labelBgStyle: { fill: "#18181b" },
        markerEnd: { type: MarkerType.ArrowClosed, color: EDGE_STYLE.link.stroke },
      }));
    return [...generated, ...custom];
  }, [structure, current.links, derived, selected]);

  const onNodesChange = useCallback((changes: NodeChange<Node<CardData>>[]) => {
    setNodes((value) => applyNodeChanges(changes.filter((change) => change.type !== "remove"), value));
  }, []);

  const onNodeDragStop = useCallback(
    (_: unknown, node: Node) => {
      updateView((value) => ({ ...value, positions: { ...value.positions, [node.id]: { x: Math.round(node.position.x), y: Math.round(node.position.y) } } }));
    },
    [updateView],
  );

  const onConnect = useCallback(
    (connection: Connection) => {
      if (!connection.source || !connection.target) return;
      const id = `l:${Date.now().toString(36)}`;
      updateView((value) => ({ ...value, links: [...(value.links ?? []), { id, source: connection.source, target: connection.target, label: "" }] }));
      setSelected({ type: "edge", id });
    },
    [updateView],
  );

  const removeSelected = useCallback(() => {
    if (!selected) return;
    if (selected.type === "node" && selected.id.startsWith("b:")) {
      updateView((value) => ({
        ...value,
        blocks: (value.blocks ?? []).filter((block) => block.id !== selected.id),
        links: (value.links ?? []).filter((link) => link.source !== selected.id && link.target !== selected.id),
      }));
      setSelected(null);
    } else if (selected.type === "edge" && selected.id.startsWith("l:")) {
      updateView((value) => ({ ...value, links: (value.links ?? []).filter((link) => link.id !== selected.id) }));
      setSelected(null);
    }
  }, [selected, updateView]);

  const addBlock = () => {
    const center = flow.screenToFlowPosition({ x: window.innerWidth / 2 - 160, y: window.innerHeight / 2 });
    const id = `b:${Date.now().toString(36)}`;
    updateView((value) => ({ ...value, blocks: [...(value.blocks ?? []), { id, label: "New block", x: Math.round(center.x), y: Math.round(center.y) }] }));
    setSelected({ type: "node", id });
  };

  const relayout = () => {
    updateView((value) => ({ ...value, positions: Object.fromEntries(Object.entries(value.positions ?? {}).filter(([id]) => id.startsWith("b:"))) }));
    window.setTimeout(() => flow.fitView({ padding: 0.12, duration: 300 }), 50);
  };

  useEffect(() => {
    if (!laying) window.setTimeout(() => flow.fitView({ padding: 0.12 }), 30);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [laying, view]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA") return;
      if (event.key === "Escape") onClose();
      if (event.key === "Delete" || event.key === "Backspace") removeSelected();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, removeSelected]);

  const toggleDir = (id: string) =>
    (view === "files" ? setExpanded : setArchExpanded)((value) => {
      const next = new Set(value);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const stats = map.stats as Record<string, number>;
  const selectedShape = selected?.type === "node" ? structure.shapes.find((shape) => shape.id === selected.id) : undefined;
  const selectedBlock = selected?.type === "node" ? (current.blocks ?? []).find((block) => block.id === selected.id) : undefined;
  const selectedLink = selected?.type === "edge" ? structure.links.find((link) => link.id === selected.id) : undefined;
  const selectedCustom = selected?.type === "edge" ? (current.links ?? []).find((link) => link.id === selected.id) : undefined;
  const neighbours = selectedShape
    ? structure.links.filter((link) => link.source === selectedShape.id || link.target === selectedShape.id).slice(0, 40)
    : [];
  const labelOf = (id: string) =>
    current.labels?.[id] || structure.shapes.find((shape) => shape.id === id)?.data.label || (current.blocks ?? []).find((block) => block.id === id)?.label || id;

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-ink-line px-4 py-2.5">
        <h2 className="mr-2 text-sm font-semibold text-ink-text">Project map · {title}</h2>
        <div className="flex rounded-md border border-ink-line p-0.5">
          {(["architecture", "files"] as ViewName[]).map((name) => (
            <button
              key={name}
              type="button"
              onClick={() => {
                setView(name);
                setSelected(null);
              }}
              className={cn("h-7 rounded px-3 text-xs capitalize", view === name ? "bg-ink-raised text-ink-text" : "text-ink-muted hover:text-ink-text")}
            >
              {name}
            </button>
          ))}
        </div>
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Find a node"
          aria-label="Find a node on the map"
          className="h-8 w-48 rounded-md border border-ink-line bg-ink-bg px-2.5 text-xs outline-none focus-visible:ring-2 focus-visible:ring-signal/60"
        />
        {view === "architecture" && focus && (
          <span className="inline-flex h-8 items-center gap-2 rounded-md border border-signal/50 px-2.5 text-xs text-ink-text">
            Path of {labelOf(focus)}
            <button type="button" onClick={() => setFocus(null)} className="text-ink-muted hover:text-ink-text" aria-label="Show the whole map">
              <X className="size-3.5" />
            </button>
          </span>
        )}
        {view === "architecture" ? (
          <>
            <Toggle label="Unmatched calls" value={filters.unmatched} onChange={(value) => setFilters({ ...filters, unmatched: value })} />
            <Toggle label="Middleware" value={filters.middleware} onChange={(value) => setFilters({ ...filters, middleware: value })} />
            <Toggle label="Services" value={filters.services} onChange={(value) => setFilters({ ...filters, services: value })} />
          </>
        ) : (
          <Toggle label="Packages" value={filters.packages} onChange={(value) => setFilters({ ...filters, packages: value })} />
        )}
        <div className="ml-auto flex items-center gap-2">
          {laying && <span className="text-xs text-ink-muted">Laying out…</span>}
          <a
            href={`/api/scans/${scanId}/map/export?format=canvas&view=${view}`}
            download
            title="Obsidian JSON Canvas with your edits; open it in an Obsidian vault"
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-ink-line px-2.5 text-xs text-ink-text hover:bg-white/5"
          >
            <Download className="size-3.5" />
            Obsidian
          </a>
          <a
            href={`/api/scans/${scanId}/map/export?format=mermaid&view=${view}`}
            download
            title="Mermaid flowchart for GitHub, GitLab, or docs"
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-ink-line px-2.5 text-xs text-ink-text hover:bg-white/5"
          >
            <Download className="size-3.5" />
            Mermaid
          </a>
          <ToolbarButton onClick={addBlock} icon={<Plus className="size-3.5" />} label="Add block" />
          <ToolbarButton onClick={relayout} icon={<LayoutGrid className="size-3.5" />} label="Re-layout" />
          <ToolbarButton onClick={onRebuild} icon={<RefreshCw className={cn("size-3.5", rebuilding && "animate-spin")} />} label="Rebuild map" disabled={rebuilding} />
          <button type="button" onClick={onClose} aria-label="Close map" className="grid size-8 place-items-center rounded-md border border-ink-line hover:bg-white/5">
            <X className="size-4" />
          </button>
        </div>
      </div>
      <div className="flex min-h-0 flex-1">
        <div className="relative min-w-0 flex-1">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={NODE_TYPES}
            onNodesChange={onNodesChange}
            onNodeDragStop={onNodeDragStop}
            onConnect={onConnect}
            onNodeClick={(_, node) => setSelected({ type: "node", id: node.id })}
            onNodeDoubleClick={(_, node) => {
              const shape = structure.shapes.find((item) => item.id === node.id);
              if (shape?.data.dir) toggleDir(node.id);
              else if (view === "architecture" && !node.id.startsWith("b:")) setFocus(node.id);
            }}
            onEdgeClick={(_, edge) => setSelected({ type: "edge", id: edge.id })}
            onPaneClick={() => setSelected(null)}
            deleteKeyCode={null}
            colorMode="dark"
            minZoom={0.05}
            maxZoom={2}
            proOptions={{ hideAttribution: true }}
            fitView
          >
            <Background gap={24} color="#27272a" />
            <Controls showInteractive={false} />
            <MiniMap pannable zoomable nodeColor={(node) => ((node.data as CardData).severity === "critical" ? "#f43f5e" : (node.data as CardData).severity === "high" ? "#fb923c" : "#52525b")} maskColor="rgba(9,9,11,0.7)" />
          </ReactFlow>
          <div className="pointer-events-none absolute bottom-3 left-14 flex flex-wrap gap-3 rounded-md bg-ink-panel/90 px-3 py-1.5 text-[11px] text-ink-muted">
            {view === "architecture" ? (
              <>
                <Legend color="bg-emerald-400" label="frontend" />
                <Legend color="bg-violet-400" label="route" />
                <Legend color="bg-zinc-300" label="backend" />
                <Legend color="bg-amber-300" label="ORM" />
                <Legend color="bg-rose-400" label="database" />
                <span className="text-rose-300">— query built from variables</span>
              </>
            ) : (
              <span>Double-click a folder to open it · {stats.files ?? 0} files · {stats.import_edges ?? 0} imports</span>
            )}
          </div>
        </div>
        <aside className="w-80 shrink-0 space-y-3 overflow-auto border-l border-ink-line bg-ink-panel p-4 text-xs">
          {!selected && (
            <div className="space-y-2 text-ink-muted">
              <p className="text-ink-text">Select a node or a link to see where it comes from in the code.</p>
              <p>Drag nodes to arrange them, connect two nodes by dragging from the right handle, and add your own blocks. Edits are saved for this scan and survive a rebuild.</p>
              <dl className="grid grid-cols-2 gap-x-3 gap-y-1 pt-2 font-mono">
                <dt>routes</dt><dd className="text-ink-text">{stats.routes ?? 0}</dd>
                <dt>frontend calls</dt><dd className="text-ink-text">{stats.http_links ?? 0}</dd>
                <dt>datastores</dt><dd className="text-ink-text">{stats.datastores ?? 0}</dd>
                <dt>dynamic SQL</dt><dd className="text-rose-200">{stats.dynamic_sql ?? 0}</dd>
                <dt>files</dt><dd className="text-ink-text">{stats.files ?? 0}</dd>
              </dl>
              {(map.stack.frameworks?.length ?? 0) > 0 && <p>Stack: {[...(map.stack.frameworks ?? []), ...(map.stack.datastores ?? [])].join(", ")}</p>}
            </div>
          )}
          {selected?.type === "node" && (selectedShape || selectedBlock) && (
            <NodePanel
              key={selected.id}
              id={selected.id}
              shape={selectedShape}
              block={selectedBlock}
              label={labelOf(selected.id)}
              note={current.notes?.[selected.id] ?? ""}
              onLabel={(value) =>
                selectedBlock
                  ? updateView((view) => ({ ...view, blocks: (view.blocks ?? []).map((block) => (block.id === selectedBlock.id ? { ...block, label: value || "Block" } : block)) }))
                  : updateView((view) => {
                      const labels = { ...view.labels };
                      if (value && value !== selectedShape?.data.label) labels[selected.id] = value;
                      else delete labels[selected.id];
                      return { ...view, labels };
                    })
              }
              onNote={(value) =>
                updateView((view) => {
                  const notes = { ...view.notes };
                  if (value.trim()) notes[selected.id] = value;
                  else delete notes[selected.id];
                  return { ...view, notes };
                })
              }
              onToggleDir={selectedShape?.data.dir ? () => toggleDir(selected.id) : undefined}
              expanded={(view === "files" ? expanded : archExpanded).has(selected.id)}
              onFocus={view === "architecture" && selectedShape && !selectedShape.data.dir && focus !== selected.id ? () => setFocus(selected.id) : undefined}
              onDelete={selectedBlock ? removeSelected : undefined}
              neighbours={neighbours}
              labelOf={labelOf}
              onSelectEdge={(id) => setSelected({ type: "edge", id })}
            />
          )}
          {selected?.type === "edge" && selectedLink && (
            <div className="space-y-2">
              <p className="text-[11px] uppercase tracking-wide text-ink-muted">{selectedLink.kind} link</p>
              <p className="text-ink-text">
                {labelOf(selectedLink.source)} → {labelOf(selectedLink.target)}
              </p>
              {selectedLink.label && <p className={selectedLink.dynamic ? "text-rose-200" : "text-ink-text/80"}>{selectedLink.label}</p>}
              <Evidence items={selectedLink.evidence} count={selectedLink.count} />
            </div>
          )}
          {selected?.type === "edge" && selectedCustom && (
            <div className="space-y-2">
              <p className="text-[11px] uppercase tracking-wide text-ink-muted">your link</p>
              <p className="text-ink-text">
                {labelOf(selectedCustom.source)} → {labelOf(selectedCustom.target)}
              </p>
              <input
                key={selectedCustom.id}
                defaultValue={selectedCustom.label}
                placeholder="Label"
                onBlur={(event) =>
                  updateView((view) => ({ ...view, links: (view.links ?? []).map((link) => (link.id === selectedCustom.id ? { ...link, label: event.target.value } : link)) }))
                }
                className="h-8 w-full rounded-md border border-ink-line bg-ink-bg px-2 outline-none focus-visible:ring-2 focus-visible:ring-signal/60"
              />
              <button type="button" onClick={removeSelected} className="h-8 rounded-md border border-rose-500/40 px-3 text-rose-100 hover:bg-rose-500/10">
                Delete link
              </button>
            </div>
          )}
          <p className="pt-2 text-[10.5px] text-ink-muted/80">Scan {scanId}</p>
        </aside>
      </div>
    </div>
  );
}

function NodePanel({ id, shape, block, label, note, onLabel, onNote, onToggleDir, expanded, onFocus, onDelete, neighbours, labelOf, onSelectEdge }: {
  id: string;
  shape?: Shape;
  block?: { id: string; label: string };
  label: string;
  note: string;
  onLabel: (value: string) => void;
  onNote: (value: string) => void;
  onToggleDir?: () => void;
  expanded: boolean;
  onFocus?: () => void;
  onDelete?: () => void;
  neighbours: Link[];
  labelOf: (id: string) => string;
  onSelectEdge: (id: string) => void;
}) {
  const source = shape?.source;
  const meta = (source?.meta ?? {}) as Record<string, unknown>;
  const params = (meta.params as { source: string; name: string; line?: number }[] | undefined) ?? [];
  const middleware = (meta.middleware as string[] | undefined) ?? [];
  return (
    <div className="space-y-3">
      <p className="text-[11px] uppercase tracking-wide text-ink-muted">{block ? "your block" : `${shape?.data.kind} · ${source?.kind}`}</p>
      <label className="block space-y-1">
        <span className="text-ink-muted">Label</span>
        <input
          defaultValue={label}
          onBlur={(event) => onLabel(event.target.value.trim())}
          onKeyDown={(event) => event.key === "Enter" && (event.target as HTMLInputElement).blur()}
          className="h-8 w-full rounded-md border border-ink-line bg-ink-bg px-2 text-ink-text outline-none focus-visible:ring-2 focus-visible:ring-signal/60"
        />
      </label>
      <label className="block space-y-1">
        <span className="text-ink-muted">Note</span>
        <textarea
          defaultValue={note}
          onBlur={(event) => onNote(event.target.value)}
          rows={4}
          placeholder="What you found here, what to check next"
          className="w-full rounded-md border border-ink-line bg-ink-bg px-2 py-1.5 text-ink-text outline-none focus-visible:ring-2 focus-visible:ring-signal/60"
        />
      </label>
      {onToggleDir && (
        <button type="button" onClick={onToggleDir} className="h-8 w-full rounded-md border border-ink-line text-ink-text hover:bg-white/5">
          {expanded ? "Close group" : "Open group"}
        </button>
      )}
      {onFocus && (
        <button type="button" onClick={onFocus} className="h-8 w-full rounded-md border border-signal/50 text-ink-text hover:bg-signal/10">
          Show its path through the system
        </button>
      )}
      {onDelete && (
        <button type="button" onClick={onDelete} className="h-8 w-full rounded-md border border-rose-500/40 text-rose-100 hover:bg-rose-500/10">
          Delete block
        </button>
      )}
      {source && (
        <dl className="space-y-1 font-mono text-[11px] text-ink-muted">
          {source.path && <div className="break-all text-ink-text/90">{source.path}</div>}
          {source.language && <div>{source.language}{source.lines ? ` · ${source.lines} lines` : ""}</div>}
          {typeof meta.handler === "string" && <div>handler {meta.handler}</div>}
          {typeof meta.framework === "string" && <div>{meta.framework}</div>}
          {shape?.data.findings ? <div className="text-orange-200">{shape.data.findings} findings</div> : null}
          {shape?.data.dynamicSql ? <div className="text-rose-200">{shape.data.dynamicSql} queries built from variables</div> : null}
        </dl>
      )}
      {params.length > 0 && (
        <div className="space-y-1">
          <p className="text-ink-muted">Request parameters</p>
          <div className="flex flex-wrap gap-1">
            {params.map((param) => (
              <span key={`${param.source}.${param.name}`} className="rounded bg-sky-500/15 px-1.5 py-0.5 font-mono text-[11px] text-sky-200">
                {param.source}.{param.name}
              </span>
            ))}
          </div>
        </div>
      )}
      {middleware.length > 0 && <p className="text-ink-muted">Middleware: <span className="font-mono text-ink-text/80">{middleware.join(", ")}</span></p>}
      {neighbours.length > 0 && (
        <div className="space-y-1">
          <p className="text-ink-muted">Links</p>
          {neighbours.map((link) => (
            <button
              key={link.id}
              type="button"
              onClick={() => onSelectEdge(link.id)}
              className="block w-full truncate rounded px-1 py-0.5 text-left hover:bg-white/5"
              title={link.label}
            >
              <span className={cn("font-mono", link.dynamic ? "text-rose-300" : "text-ink-muted")}>{link.kind}</span>{" "}
              <span className="text-ink-text/90">{link.source === id ? `→ ${labelOf(link.target)}` : `← ${labelOf(link.source)}`}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function Evidence({ items, count }: { items: MapEdge["evidence"]; count: number }) {
  if (items.length === 0) return null;
  return (
    <div className="space-y-1.5">
      <p className="text-ink-muted">Found in the code{count > items.length ? ` (${count} places, first ${items.length})` : ""}</p>
      {items.map((item, index) => (
        <div key={index} className="rounded-md border border-ink-line bg-black/20 px-2 py-1.5">
          <p className="font-mono text-[11px] text-ink-muted">{item.path}:{item.line}</p>
          {item.text && <pre className="mt-0.5 whitespace-pre-wrap break-all font-mono text-[11px] text-ink-text/90">{item.text}</pre>}
        </div>
      ))}
    </div>
  );
}

function Toggle({ label, value, onChange }: { label: string; value: boolean; onChange: (value: boolean) => void }) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-1.5 text-xs text-ink-muted">
      <input type="checkbox" checked={value} onChange={(event) => onChange(event.target.checked)} className="size-3.5 accent-signal" />
      {label}
    </label>
  );
}

function ToolbarButton({ onClick, icon, label, disabled }: { onClick: () => void; icon: React.ReactNode; label: string; disabled?: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex h-8 items-center gap-1.5 rounded-md border border-ink-line px-2.5 text-xs text-ink-text hover:bg-white/5 disabled:opacity-40"
    >
      {icon}
      {label}
    </button>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className={cn("inline-block h-2.5 w-1 rounded-sm", color)} />
      {label}
    </span>
  );
}

/** Full-screen project map of a scan: architecture and files, editable, saved per scan. */
export default function ProjectMapSheet({ scanId, label, findings, onClose }: { scanId: string; label?: string; findings: Finding[]; onClose: () => void }) {
  const queryClient = useQueryClient();
  const map = useQuery({ queryKey: ["project-map", scanId], queryFn: () => fetchProjectMap(scanId), staleTime: 60_000 });
  const overlayQuery = useQuery({ queryKey: ["map-overlay", scanId], queryFn: () => fetchMapOverlay(scanId), staleTime: Infinity });
  const [overlay, setOverlay] = useState<MapOverlay | null>(null);
  const [saveState, setSaveState] = useState<"saved" | "saving" | "error">("saved");
  const [rebuilding, setRebuilding] = useState(false);
  const [rebuildError, setRebuildError] = useState("");
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (overlayQuery.data && overlay === null) setOverlay(overlayQuery.data);
  }, [overlayQuery.data, overlay]);

  const changeOverlay = useCallback(
    (next: MapOverlay) => {
      setOverlay(next);
      setSaveState("saving");
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => {
        saveMapOverlay(scanId, next)
          .then(() => setSaveState("saved"))
          .catch(() => setSaveState("error"));
      }, 600);
    },
    [scanId],
  );

  const rebuild = async () => {
    setRebuilding(true);
    setRebuildError("");
    try {
      const fresh = await rebuildProjectMap(scanId);
      queryClient.setQueryData(["project-map", scanId], fresh);
    } catch (error) {
      setRebuildError(error instanceof Error ? error.message : "Could not build the map");
    } finally {
      setRebuilding(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-ink-bg">
      {map.isLoading || overlayQuery.isLoading || (overlayQuery.data && !overlay) ? (
        <p className="p-6 text-sm text-ink-muted">Loading the project map…</p>
      ) : map.error ? (
        <MapMessage text={(map.error as Error).message} onClose={onClose} />
      ) : !map.data ? (
        <div className="flex h-full flex-col items-center justify-center gap-3 text-sm text-ink-muted">
          <p>This scan has no project map yet. Scans made before the map existed can build one now.</p>
          <div className="flex gap-2">
            <button type="button" onClick={() => void rebuild()} disabled={rebuilding} className="h-9 rounded-md border border-signal/50 px-4 text-ink-text hover:bg-signal/10 disabled:opacity-40">
              {rebuilding ? "Building…" : "Build the map"}
            </button>
            <button type="button" onClick={onClose} className="h-9 rounded-md border border-ink-line px-4 text-ink-text hover:bg-white/5">
              Close
            </button>
          </div>
          {rebuildError && <p className="text-rose-200">{rebuildError}</p>}
        </div>
      ) : (
        <ReactFlowProvider>
          <MapCanvas
            scanId={scanId}
            title={label || map.data.root_label}
            map={map.data}
            findings={findings}
            overlay={overlay ?? { version: 1, views: {} }}
            onOverlay={changeOverlay}
            onRebuild={() => void rebuild()}
            rebuilding={rebuilding}
            onClose={onClose}
          />
          <span
            className={cn(
              "pointer-events-none fixed bottom-3 right-[21rem] rounded bg-ink-panel/90 px-2 py-1 text-[11px]",
              saveState === "error" ? "text-rose-200" : "text-ink-muted",
            )}
          >
            {saveState === "saving" ? "Saving…" : saveState === "error" ? "Edits not saved" : "Edits saved"}
          </span>
          {rebuildError && <span className="fixed bottom-10 right-[21rem] rounded bg-ink-panel px-2 py-1 text-[11px] text-rose-200">{rebuildError}</span>}
        </ReactFlowProvider>
      )}
    </div>
  );
}

function MapMessage({ text, onClose }: { text: string; onClose: () => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 text-sm">
      <p className="text-rose-200">{text}</p>
      <button type="button" onClick={onClose} className="h-9 rounded-md border border-ink-line px-4 text-ink-text hover:bg-white/5">
        Close
      </button>
    </div>
  );
}
