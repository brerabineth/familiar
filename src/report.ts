import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { AuditReport } from './models.js';

export function writeJson(report: AuditReport, outPath: string): void {
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
}

export function writeMarkdown(report: AuditReport, outPath: string): void {
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, renderMarkdown(report), 'utf8');
}

export function renderMarkdown(report: AuditReport): string {
  const lines: string[] = [];
  const s = report.summary;

  lines.push('# familiar audit');
  lines.push('');
  lines.push(`target: \`${report.target}\``);
  lines.push('');
  lines.push(`files audited: ${s.filesAudited} · servers: ${s.serversAudited} · tools: ${s.toolsAudited}`);
  lines.push('');
  lines.push('| severity | count |');
  lines.push('|---|---|');
  lines.push(`| critical | ${s.bySeverity.critical} |`);
  lines.push(`| high | ${s.bySeverity.high} |`);
  lines.push(`| medium | ${s.bySeverity.medium} |`);
  lines.push(`| low | ${s.bySeverity.low} |`);
  lines.push(`| info | ${s.bySeverity.info} |`);
  lines.push('');
  lines.push(`verdict: **${report.verdict.toUpperCase()}**`);
  lines.push('');

  if (report.configAudits.length > 0) {
    lines.push('## configs');
    lines.push('');
    for (const ca of report.configAudits) {
      lines.push(`### ${ca.file} (${ca.configKind})`);
      if (ca.parseError) {
        lines.push('');
        lines.push(`- parse error: ${ca.parseError}`);
        continue;
      }
      for (const sa of ca.servers) {
        const score = scoreOf(sa.findings);
        lines.push('');
        lines.push(`- **${sa.name}** — score ${score}/100${sa.liveError ? ` — live check failed: ${sa.liveError}` : ''}`);
        for (const f of sa.findings) {
          if (f.severity === 'info') continue;
          lines.push(`  - \`${f.id}\` **${f.severity}** ${f.title}`);
        }
      }
      lines.push('');
    }
  }

  if (report.toolFindings.length > 0) {
    lines.push('## tool findings');
    lines.push('');
    for (const f of report.toolFindings) {
      lines.push(`- \`${f.id}\` **${f.severity}** ${f.title}${f.server ? ` — server \`${f.server}\`` : ''}${f.tool ? `, tool \`${f.tool}\`` : ''}`);
      lines.push(`  - ${f.detail}`);
    }
    lines.push('');
  }

  if (report.rugPull) {
    const r = report.rugPull;
    lines.push('## rug-pull diff');
    lines.push('');
    if (r.changed.length === 0 && r.added.length === 0 && r.removed.length === 0) {
      lines.push('no drift since baseline.');
    } else {
      if (r.changed.length > 0) {
        lines.push(`**changed definitions (${r.changed.length}) — treat as rug pull:**`);
        lines.push('');
        for (const c of r.changed) {
          lines.push(`- ${c.server} / ${c.tool}: \`${c.from.slice(0, 12)}…\` → \`${c.to.slice(0, 12)}…\``);
        }
        lines.push('');
      }
      if (r.added.length > 0) {
        lines.push(`**added (${r.added.length}):** ${r.added.map((a) => `${a.server}/${a.tool}`).join(', ')}`);
        lines.push('');
      }
      if (r.removed.length > 0) {
        lines.push(`**removed (${r.removed.length}):** ${r.removed.map((a) => `${a.server}/${a.tool}`).join(', ')}`);
        lines.push('');
      }
    }
  }

  return lines.join('\n');
}

function scoreOf(findings: { severity: string }[]): number {
  const weights: Record<string, number> = { critical: 40, high: 22, medium: 12, low: 5, info: 0 };
  let score = 0;
  for (const f of findings) score += weights[f.severity] ?? 0;
  return Math.min(100, score);
}
