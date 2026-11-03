import type { Finding, ScanEvent, ScanSummary, ToolInfo } from "@/api/types";

async function readError(response: Response) {
  try {
    const body = await response.json();
    return typeof body.detail === "string" ? body.detail : response.statusText;
  } catch {
    return response.statusText;
  }
}

export async function fetchTools(): Promise<ToolInfo[]> {
  const response = await fetch("/api/tools");
  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

export async function fetchScans(): Promise<ScanSummary[]> {
  const response = await fetch("/api/scans");
  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

export async function fetchScan(id: string): Promise<ScanSummary> {
  const response = await fetch(`/api/scans/${id}`);
  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

export async function fetchFindings(id: string): Promise<Finding[]> {
  const response = await fetch(`/api/scans/${id}/findings`);
  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

export async function dismissFindings(
  id: string,
  findings: Array<Pick<Finding, "fingerprint" | "correlation_key">>,
): Promise<void> {
  const response = await fetch(`/api/scans/${id}/findings/dismiss`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      findings: findings.map((finding) => ({
        fingerprint: finding.fingerprint,
        correlation_key: finding.correlation_key,
      })),
    }),
  });
  if (!response.ok) throw new Error(await readError(response));
}

export async function startScan(input: {
  path?: string;
  archive?: File | null;
  folder?: File[] | null;
  githubUrl?: string;
  scanners: string[];
  params: Record<string, Record<string, unknown>>;
  useDocker: boolean;
}): Promise<ScanSummary> {
  const body = new FormData();
  if (input.githubUrl && input.githubUrl.trim()) {
    body.set("github_url", input.githubUrl.trim());
  } else if (input.folder && input.folder.length > 0) {
    const root = input.folder[0].webkitRelativePath.split("/")[0] || "project";
    body.set("folder_name", root);
    for (const file of input.folder) {
      body.append("files", file);
      body.append("relative_paths", file.webkitRelativePath || file.name);
    }
  } else {
    if (input.path) body.set("path", input.path);
    if (input.archive) body.set("archive", input.archive);
  }
  body.set("scanners", input.scanners.join(","));
  body.set("params", JSON.stringify(input.params));
  body.set("use_docker", input.useDocker ? "true" : "false");
  const response = await fetch("/api/scans", { method: "POST", body });
  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

export async function fetchLog(id: string): Promise<ScanEvent[]> {
  const response = await fetch(`/api/scans/${id}/log`);
  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

export type LiveChannel = "connecting" | "live" | "reconnecting" | "closed";

export function watchScan(
  scanId: string,
  onEvents: (events: ScanEvent[]) => void,
  onState?: (state: LiveChannel) => void,
): () => void {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  let stopped = false;
  let socket: WebSocket | null = null;
  let attempt = 0;
  let timer = 0;
  let frame = 0;
  let pending: ScanEvent[] = [];

  const flush = () => {
    frame = 0;
    if (stopped || pending.length === 0) {
      pending = [];
      return;
    }
    const batch = pending;
    pending = [];
    onEvents(batch);
  };

  const enqueue = (event: ScanEvent) => {
    pending.push(event);
    if (frame) return;
    frame = window.requestAnimationFrame(flush);
  };

  const open = () => {
    if (stopped) return;
    onState?.(attempt === 0 ? "connecting" : "reconnecting");
    const next = new WebSocket(`${protocol}//${window.location.host}/api/scans/${scanId}/events`);
    socket = next;
    next.onopen = () => {
      attempt = 0;
      onState?.("live");
    };
    next.onmessage = (message) => {
      if (stopped || typeof message.data !== "string") return;
      try {
        const event = JSON.parse(message.data) as ScanEvent;
        if (event && typeof event.type === "string") enqueue(event);
      } catch {
        return;
      }
    };
    next.onerror = () => {
      if (next.readyState !== WebSocket.CLOSING && next.readyState !== WebSocket.CLOSED) next.close();
    };
    next.onclose = (event) => {
      if (stopped || socket !== next) return;
      if (event.code === 1000) {
        flush();
        onState?.("closed");
        return;
      }
      attempt += 1;
      if (attempt > 8) {
        onState?.("closed");
        return;
      }
      onState?.("reconnecting");
      const delay = Math.min(8000, 400 * 2 ** attempt);
      timer = window.setTimeout(open, delay);
    };
  };

  open();
  return () => {
    stopped = true;
    window.clearTimeout(timer);
    if (frame) window.cancelAnimationFrame(frame);
    frame = 0;
    pending = [];
    const current = socket;
    if (!current) return;
    if (current.readyState === WebSocket.CONNECTING) {
      current.addEventListener("open", () => current.close(1000), { once: true });
      return;
    }
    if (current.readyState === WebSocket.OPEN) current.close(1000);
  };
}

export type SnykStatus = {
  connected: boolean;
  login: "idle" | "preparing" | "waiting" | "connected" | "failed";
  url: string | null;
  error: string | null;
  cli_version: string;
};

async function snykCall(path: string, method: "GET" | "POST" = "POST"): Promise<SnykStatus> {
  const response = await fetch(`/api/integrations/snyk${path}`, { method });
  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

export const fetchSnykStatus = () => snykCall("", "GET");
export const startSnykLogin = () => snykCall("/login");
export const cancelSnykLogin = () => snykCall("/cancel");
export const disconnectSnyk = () => snykCall("/logout");
