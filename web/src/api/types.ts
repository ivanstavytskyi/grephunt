export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type SourceMarkKind = "finding" | "input" | "route" | "sink" | "call";

export type SourceMark = {
  line: number;
  end_line?: number;
  kind: SourceMarkKind;
  label: string;
  severity?: Severity;
  fingerprint?: string;
  correlation_key?: string;
};

export type SourceView = {
  path: string;
  language: string | null;
  start: number;
  lines: string[];
  total_lines: number;
  focus: { start: number; end: number };
  marks: SourceMark[];
};

export type Finding = {
  module: string;
  category: "code" | "secret" | "dependency" | "misconfig";
  tool: string;
  tool_version: string | null;
  tools: string[];
  rule_id: string;
  title: string;
  message: string;
  description?: string | null;
  severity: Severity;
  severity_original: string | null;
  cwe: string[];
  cve: string[];
  owasp: string[];
  location: {
    kind: "file" | "url" | "service";
    path: string | null;
    start_line: number | null;
    end_line: number | null;
    url: string | null;
    parameter: string | null;
    host: string | null;
    port: number | null;
  };
  snippet: string | null;
  context?: FindingContext;
  confirmations?: { tool: string; rule_id: string; title: string; line: number | null; severity: string | null }[];
  lines?: number[];
  exploitability?: { score: number; label: string; factors: string[] };
  ai_verdict?: "confirmed" | "likely" | "false_positive" | null;
  ai_reason?: string;
  tier?: FindingTier;
  tier_reason?: string;
  epss?: number;
  kev?: boolean;
  secret_live?: boolean;
  evidence: string | null;
  status: string;
  raw_ref: string | null;
  help_uri: string | null;
  package: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  correlation_key: string;
  fingerprint: string;
};

export type ScanSummary = {
  id: string;
  tenant_id: string;
  target_label: string;
  target_path: string;
  status: "running" | "success" | "failed";
  partial: boolean;
  created_at: string | null;
  finished_at: string | null;
  duration_sec: number | null;
  raw_total: number;
  excluded: number;
  finding_count: number;
  error: string | null;
  run_params?: Record<string, Record<string, unknown>>;
  source_repo_url?: string | null;
  source_ref?: string | null;
  tasks?: TaskSummary[];
};

export type TaskContainer = {
  name?: string;
  status?: string;
  image?: string;
  cpu?: string;
  memory?: string;
  memory_pct?: string;
  pids?: string;
  net_io?: string;
  block_io?: string;
  cpus_limit?: string;
  memory_limit?: string;
  pids_limit?: number;
  network?: string;
  user?: string | null;
  exit_code?: number | null;
};

export type TaskDetails = {
  phase?: string;
  failed_phase?: string;
  timeline?: { phase: string; at: string }[];
  started_at?: string;
  finished_at?: string;
  last_message?: string;
  last_event_at?: string;
  mode?: "docker" | "local";
  cloud?: boolean;
  timeout_sec?: number;
  image?: string;
  pulled?: boolean;
  pull_sec?: number | null;
  binary?: string;
  container?: TaskContainer;
  exit_code?: number | null;
  run_sec?: number;
  stdout_bytes?: number;
  stderr_bytes?: number;
  raw_findings?: number;
  raw_severities?: Partial<Record<Severity, number>>;
  accepted?: number;
  severities?: Partial<Record<Severity, number>>;
  rules?: number;
  files?: number;
  sarif_bytes?: number;
};

export type TaskLimits = {
  module?: string;
  category?: string | null;
  cloud?: boolean;
  network?: boolean;
  timeout_sec?: number;
  cpus?: string;
  memory?: string;
  pids_limit?: number;
};

export type TaskSummary = {
  tool: string;
  status: string;
  duration_sec: number;
  tool_version: string | null;
  image: string | null;
  error: string | null;
  details?: TaskDetails;
  report_findings?: Partial<Record<Severity, number>>;
  limits?: TaskLimits;
};

export type ScannerGroup = "code" | "secret" | "dependency" | "iac";

export type ToolParameterSpec = {
  name: string;
  type: "multi" | "string_list" | "string" | "bool";
  label: string;
  description: string;
  choices: string[];
  default: string | string[] | boolean | null;
  widget: string | null;
};

export type ToolInfo = {
  name: string;
  module: string;
  image: string;
  version: string;
  network: boolean;
  prepare_network: boolean;
  scans_images: boolean;
  default_enabled: boolean;
  cloud: boolean;
  finding_category: string | null;
  group: ScannerGroup;
  languages: string;
  purpose: string;
  parameters: ToolParameterSpec[];
};

export type ScanEvent = {
  seq?: number;
  type: string;
  message: string;
  tool: string | null;
  data: Record<string, unknown>;
};
export type FindingContext = {
  routes?: { id: string; label: string; params: string[]; framework?: string | null }[];
  database?: { target: string; dynamic: boolean; line: number };
};

export type MapEvidence = { path: string; line: number; text: string };

export type MapNode = {
  id: string;
  kind: "dir" | "file" | "package" | "component" | "route" | "datastore" | "external";
  label: string;
  path?: string | null;
  parent?: string | null;
  language?: string | null;
  role?: string | null;
  layer?: "frontend" | "backend" | "data" | "external" | "other" | null;
  entry_point?: boolean;
  lines?: number | null;
  meta: Record<string, unknown>;
};

export type MapEdge = {
  id: string;
  source: string;
  target: string;
  kind: "import" | "http" | "handles" | "db" | "service";
  label: string;
  evidence: MapEvidence[];
  count: number;
};

export type MapView = { nodes: MapNode[]; edges: MapEdge[] };

export type ProjectMap = {
  version: number;
  root_label: string;
  stats: Record<string, unknown>;
  stack: { languages?: Record<string, number>; frameworks?: string[]; datastores?: string[] };
  files: MapView;
  architecture: MapView;
  unresolved: MapEvidence[];
  truncated: boolean;
};

export type MapOverlayView = {
  positions?: Record<string, { x: number; y: number }>;
  labels?: Record<string, string>;
  notes?: Record<string, string>;
  blocks?: { id: string; label: string; x: number; y: number }[];
  links?: { id: string; source: string; target: string; label: string }[];
};

export type MapOverlay = { version: number; views: Record<string, MapOverlayView> };

export type FindingTier = "main" | "review" | "not_executed" | "hygiene" | "infra";
