// Typed client for the WallScope dashboard API.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Finding {
  id: string;
  module: string;
  severity: Severity;
  title: string;
  detail: string;
  target?: string;
  remediation?: string;
  evidence?: Record<string, string>;
}

export interface FirewallProfile {
  name: string;
  enabled: boolean;
  defaultInbound: string;
  defaultOutbound: string;
}

export interface FirewallRule {
  name: string;
  protocol: string;
  localPorts: string;
  remoteAddresses: string;
  action: string;
  profile?: string;
  program?: string;
}

export interface FirewallBackend {
  name: string;
  state: "active" | "inactive" | "notInstalled" | "unknown";
  detail?: string;
  error?: string;
  profiles?: FirewallProfile[];
  rules?: FirewallRule[];
}

export interface LocalAudit {
  platform: string;
  firewallActive?: boolean | null;
  elevated: boolean;
  backends: FirewallBackend[];
}

export interface PortResult {
  port: number;
  state: "open" | "closed" | "filtered";
  reason: string;
  latencyMs: number;
  service?: string;
}

export interface HostProbe {
  target: string;
  resolvedAddress?: string;
  ports: PortResult[];
  open: number;
  closed: number;
  filtered: number;
  verdict: string;
  explanation: string;
  error?: string;
}

export interface WafMatch {
  name: string;
  vendor: string;
  kind: string;
  confidence: number;
  evidence: string[];
}

export interface WafResult {
  url: string;
  reachable: boolean;
  activeProbe: boolean;
  baselineStatus?: number;
  provocationStatus?: number;
  detected: boolean;
  genericBlockingObserved: boolean;
  matches: WafMatch[];
  notes?: string;
  error?: string;
}

export interface ScanReport {
  host: string;
  os: string;
  toolVersion: string;
  startedUtc: string;
  finishedUtc: string;
  localAudit?: LocalAudit;
  networkProbes: HostProbe[];
  wafResults: WafResult[];
  findings: Finding[];
}

export interface Risk {
  score: number;
  grade: string;
  posture: string;
  counts: Record<Severity, number>;
}

export interface StoredReport {
  id: string;
  label: string;
  report: ScanReport;
  risk: Risk;
}

export interface ReportSummary {
  id: string;
  label: string;
  host: string;
  finishedUtc: string;
  score: number;
  grade: string;
  findings: number;
}

export interface Drift {
  changed: boolean;
  score_before: number;
  score_after: number;
  new_findings: Finding[];
  resolved_findings: Finding[];
  port_changes: { target: string; port: number; before: string; after: string }[];
  waf_changes: { url: string; before: string; after: string }[];
  firewall_change: { before: boolean | null; after: boolean | null } | null;
}

export interface Session {
  setupRequired: boolean;
  authenticated: boolean;
  user: string | null;
}

export interface Status {
  version: string;
  engine: string | null;
  assistant: "claude" | "built-in";
}

export type Mood = "neutral" | "happy" | "alert" | "thinking";

export interface ChatReply {
  text: string;
  suggestions: string[];
  source: "claude" | "built-in";
  mood: Mood;
}

export interface ChatTurn {
  role: "user" | "assistant";
  content: string;
}

export interface ScanRequest {
  local?: boolean;
  targets?: string[];
  ports?: string;
  urls?: string[];
  passive?: boolean;
  authorized?: boolean;
}

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function call<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method, credentials: "same-origin" };
  if (method === "POST") {
    // The custom header is what makes cross-site requests fail: a plain HTML form cannot send it.
    init.headers = { "Content-Type": "application/json", "X-WallScope": "1" };
    init.body = JSON.stringify(body ?? {});
  }

  let response: Response;
  try {
    response = await fetch(path, init);
  } catch {
    throw new ApiError("Can't reach the WallScope server. Is it still running?", 0);
  }

  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    // Non-JSON error bodies fall through to the generic message below.
  }

  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && "error" in payload
        ? String((payload as { error: unknown }).error)
        : `Request failed (${response.status}).`;
    throw new ApiError(message, response.status);
  }
  return payload as T;
}

export const api = {
  session: () => call<Session>("GET", "/api/session"),
  setup: (username: string, password: string) => call<{ user: string }>("POST", "/api/setup", { username, password }),
  login: (username: string, password: string) => call<{ user: string }>("POST", "/api/login", { username, password }),
  logout: () => call<{ ok: boolean }>("POST", "/api/logout"),
  status: () => call<Status>("GET", "/api/status"),
  scan: (request: ScanRequest) => call<StoredReport>("POST", "/api/scan", request),
  sample: () => call<StoredReport>("POST", "/api/sample"),
  reports: () => call<ReportSummary[]>("GET", "/api/reports"),
  report: (id: string) => call<StoredReport>("GET", `/api/reports/${encodeURIComponent(id)}`),
  diff: (base: string, head: string) => call<Drift>("POST", "/api/diff", { base, head }),
  chat: (message: string, reportId: string | null, history: ChatTurn[]) =>
    call<ChatReply>("POST", "/api/chat", { message, reportId, history }),
  exportUrl: (id: string, format: "html" | "md" | "sarif" | "json") =>
    `/api/reports/${encodeURIComponent(id)}/export?format=${format}`,
};
