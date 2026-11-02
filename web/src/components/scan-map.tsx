import { memo, useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import type { Finding, TaskSummary } from "@/api/types";

type Box = { id: string; x: number; y: number; text: string; fill: string; color: string };
type Link = { id: string; x1: number; y1: number; x2: number; y2: number };

const BOX_W = 188;
const BOX_H = 40;

export const ScanMap = memo(function ScanMap({
  label,
  tasks,
  findings,
}: {
  label: string;
  tasks: TaskSummary[];
  findings: Finding[];
}) {
  const surface = useRef<HTMLDivElement>(null);
  const drag = useRef<{ pointerId: number; x: number; y: number; originX: number; originY: number } | null>(null);
  const [view, setView] = useState({ x: 28, y: 24, scale: 1 });
  const graph = useMemo(() => buildGraph(label, tasks, findings), [findings, label, tasks]);

  useEffect(() => {
    const element = surface.current;
    if (!element) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      const factor = event.deltaY < 0 ? 1.08 : 0.92;
      setView((current) => ({
        ...current,
        scale: clamp(current.scale * factor, 0.4, 2.2),
      }));
    };
    element.addEventListener("wheel", onWheel, { passive: false });
    return () => element.removeEventListener("wheel", onWheel);
  }, []);

  function onPointerDown(event: ReactPointerEvent<HTMLDivElement>) {
    if (event.button === 1) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    drag.current = {
      pointerId: event.pointerId,
      x: event.clientX,
      y: event.clientY,
      originX: view.x,
      originY: view.y,
    };
  }

  function onPointerMove(event: ReactPointerEvent<HTMLDivElement>) {
    const active = drag.current;
    if (!active || active.pointerId !== event.pointerId) return;
    setView((current) => ({
      ...current,
      x: active.originX + event.clientX - active.x,
      y: active.originY + event.clientY - active.y,
    }));
  }

  function endDrag(event: ReactPointerEvent<HTMLDivElement>) {
    if (drag.current?.pointerId === event.pointerId) drag.current = null;
  }

  return (
    <div
      ref={surface}
      className="relative h-80 cursor-grab overflow-hidden rounded-lg border border-ink-line bg-ink-bg active:cursor-grabbing"
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      onContextMenu={(event) => event.preventDefault()}
    >
      <svg className="h-full w-full" aria-label="Scan map">
        <g transform={`translate(${view.x} ${view.y}) scale(${view.scale})`}>
          {graph.links.map((link) => (
            <line key={link.id} x1={link.x1} y1={link.y1} x2={link.x2} y2={link.y2} stroke="#8b98ab" strokeWidth={1.5} />
          ))}
          {graph.boxes.map((box) => (
            <g key={box.id} transform={`translate(${box.x} ${box.y})`}>
              <rect width={BOX_W} height={BOX_H} rx={8} fill={box.fill} stroke="#2a3240" />
              <text
                x={12}
                y={25}
                fill={box.color}
                fontSize={12}
                fontFamily="Geist Mono Variable, ui-monospace, monospace"
              >
                {box.text}
              </text>
            </g>
          ))}
        </g>
      </svg>
      <p className="pointer-events-none absolute bottom-2 left-3 text-[11px] text-ink-muted">Scroll to zoom, drag to move</p>
    </div>
  );
});

function buildGraph(label: string, tasks: TaskSummary[], findings: Finding[]) {
  const categories = [...new Set(findings.map((item) => item.category))];
  const boxes: Box[] = [
    { id: "target", x: 0, y: 80, text: clip(label), fill: "#14180c", color: "#d6f25c" },
    ...tasks.map((task, index) => ({
      id: `tool-${task.tool}`,
      x: 280,
      y: 16 + index * 88,
      text: clip(`${task.tool}${task.tool_version ? ` ${task.tool_version}` : ""}`),
      fill: "#131820",
      color: "#e8edf5",
    })),
    ...categories.map((category, index) => ({
      id: `cat-${category}`,
      x: 560,
      y: 16 + index * 72,
      text: clip(`${category} · ${findings.filter((item) => item.category === category).length}`),
      fill: "#131820",
      color: "#e8edf5",
    })),
  ];
  const byId = new Map(boxes.map((box) => [box.id, box]));
  const links: Link[] = [];
  const connect = (id: string, source: string, target: string) => {
    const from = byId.get(source);
    const to = byId.get(target);
    if (!from || !to) return;
    links.push({
      id,
      x1: from.x + BOX_W,
      y1: from.y + BOX_H / 2,
      x2: to.x,
      y2: to.y + BOX_H / 2,
    });
  };
  for (const task of tasks) connect(`e-${task.tool}`, "target", `tool-${task.tool}`);
  for (const task of tasks) {
    for (const category of categories) {
            const linked = findings.some((item) => {
              const tools = item.tools ?? [];
              return (item.tool === task.tool || tools.includes(task.tool)) && item.category === category;
            });
      if (linked) connect(`e-${task.tool}-${category}`, `tool-${task.tool}`, `cat-${category}`);
    }
  }
  return { boxes, links };
}

function clip(value: string) {
  return value.length > 28 ? `${value.slice(0, 27)}…` : value;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}
