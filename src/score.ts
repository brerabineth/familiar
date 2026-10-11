import type { Finding, ReportSummary, Severity } from './models.js';
import { maxSeverity } from './models.js';

const WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 22,
  medium: 12,
  low: 5,
  info: 0,
};

export function scoreFindings(findings: Finding[]): number {
  let score = 0;
  for (const f of findings) score += WEIGHTS[f.severity];
  return Math.min(100, score);
}

export function verdictOf(findings: Finding[]): Severity {
  const sev = maxSeverity(findings.map((f) => f.severity));
  if (sev === 'low' || sev === 'info') return 'low';
  return sev;
}

export function summarize(filesAudited: number, serversAudited: number, toolsAudited: number, findings: Finding[]): ReportSummary {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity]++;
  return { filesAudited, serversAudited, toolsAudited, bySeverity };
}

/** exit code policy: 0 clean/info only · 2 findings · 3 rug-pull drift · 10 critical · 1 operational error */
export function exitCodeFor(findings: Finding[], rugPullChanged: number): number {
  if (findings.some((f) => f.severity === 'critical')) return 10;
  if (rugPullChanged > 0) return 3;
  if (findings.some((f) => f.severity !== 'info')) return 2;
  return 0;
}
