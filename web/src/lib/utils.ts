import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return "";
  const total = Math.max(0, seconds);
  if (total < 10) return `${total.toFixed(1)}s`;
  if (total < 60) return `${Math.round(total)}s`;
  const minutes = Math.floor(total / 60);
  const rest = Math.round(total % 60);
  return `${minutes}m ${rest.toString().padStart(2, "0")}s`;
}

export function elapsedSeconds(
  createdAt: string | null | undefined,
  finishedAt: string | null | undefined,
  now = Date.now(),
): number | null {
  if (!createdAt) return null;
  const start = Date.parse(createdAt);
  if (Number.isNaN(start)) return null;
  const end = finishedAt ? Date.parse(finishedAt) : now;
  if (Number.isNaN(end)) return null;
  return Math.max(0, (end - start) / 1000);
}

export function locationLabel(location: {
  kind: string;
  path: string | null;
  start_line: number | null;
  url: string | null;
  parameter: string | null;
  host: string | null;
  port: number | null;
}) {
  if (location.kind === "file") {
    if (location.path && location.start_line) return `${location.path}:${location.start_line}`;
    return location.path ?? "";
  }
  if (location.kind === "url") {
    if (location.url && location.parameter) return `${location.url}?${location.parameter}`;
    return location.url ?? "";
  }
  if (location.host && location.port) return `${location.host}:${location.port}`;
  return location.host ?? "";
}
