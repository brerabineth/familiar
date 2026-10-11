export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export function maxSeverity(list: Severity[]): Severity {
  let best: Severity = 'info';
  for (const s of list) {
    if (severityRank(s) > severityRank(best)) best = s;
  }
  return best;
}

/** A server entry as it appears in an agent config file. */
export interface ConfigServer {
  /** absolute path of the config file it came from */
  file: string;
  /** which agent product the config belongs to (best effort) */
  configKind: string;
  /** key name inside the config */
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  cwd?: string;
  /** keys like autoApprove / alwaysAllow / permissions.allow */
  autoApprove?: string[];
  disabled?: boolean;
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  /** server name, when scoped to one */
  server?: string;
  /** config file path, when scoped */
  file?: string;
  /** tool name, when scoped */
  tool?: string;
}

export interface ToolDef {
  server: string;
  name: string;
  description: string;
  inputSchema?: unknown;
  annotations?: unknown;
}

/** result of auditing one config file */
export interface ConfigAudit {
  file: string;
  configKind: string;
  servers: ServerAudit[];
  parseError?: string;
}

export interface ServerAudit {
  name: string;
  file: string;
  configKind: string;
  findings: Finding[];
  /** live tools, when a handshake was performed */
  tools?: ToolDef[];
  liveError?: string;
}

export interface RugPullDiff {
  changed: { server: string; tool: string; from: string; to: string }[];
  added: { server: string; tool: string; hash: string }[];
  removed: { server: string; tool: string; hash: string }[];
}

export interface ReportSummary {
  filesAudited: number;
  serversAudited: number;
  toolsAudited: number;
  bySeverity: Record<Severity, number>;
}

export interface AuditReport {
  target: string;
  configAudits: ConfigAudit[];
  toolFindings: Finding[];
  rugPull?: RugPullDiff;
  summary: ReportSummary;
  verdict: Severity;
}

export interface BaselineFile {
  version: 1;
  servers: Record<string, Record<string, string>>;
}
