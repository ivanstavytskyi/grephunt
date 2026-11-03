export type Severity = "critical" | "high" | "medium" | "low" | "info";

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
  tasks?: TaskSummary[];
};

export type TaskSummary = {
  tool: string;
  status: string;
  duration_sec: number;
  tool_version: string | null;
  image: string | null;
  error: string | null;
};

export type ToolInfo = {
  name: string;
  module: string;
  image: string;
  version: string;
  network: boolean;
  prepare_network: boolean;
};

export type ScanEvent = {
  seq?: number;
  type: string;
  message: string;
  tool: string | null;
  data: Record<string, unknown>;
};