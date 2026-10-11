import type { AuditReport, Finding, Severity } from './models.js';

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
  white: '\x1b[97m',
};

const SEV_STYLE: Record<Severity, { tag: string; color: string }> = {
  critical: { tag: 'CRITICAL', color: C.red },
  high: { tag: 'HIGH    ', color: C.red },
  medium: { tag: 'MEDIUM  ', color: C.yellow },
  low: { tag: 'LOW     ', color: C.cyan },
  info: { tag: 'INFO    ', color: C.gray },
};

export interface RenderOpts {
  plain?: boolean;
}

function colorize(plain: boolean | undefined, code: string, text: string): string {
  return plain ? text : `${code}${text}${C.reset}`;
}

export function renderBanner(plain?: boolean): string {
  const art = [
    '   ______ _       _     _                ',
    '  |  ____(_)     | |   | |               ',
    '  | |__   _ _ __ | |__ | | ___  _ __ ___ ',
    '  |  __| | | \'_ \\| \'_ \\| |/ _ \\| \'_ ` _ \\',
    '  | |    | | | | | | | | | (_) | | | | | |',
    '  |_|    |_|_| |_|_| |_|_|\\___/|_| |_| |_|',
  ];
  const lines = art.map((l) => colorize(plain, C.magenta, l));
  lines.push('');
  lines.push(colorize(plain, C.gray, '  what serves you may serve another. audit the familiars.'));
  return lines.join('\n');
}

function scoreOf(findings: Finding[]): number {
  const weights: Record<Severity, number> = { critical: 40, high: 22, medium: 12, low: 5, info: 0 };
  let s = 0;
  for (const f of findings) s += weights[f.severity];
  return Math.min(100, s);
}

function band(score: number, findings: Finding[]): { label: string; color: string } {
  const has = (s: Severity) => findings.some((f) => f.severity === s);
  if (has('critical')) return { label: 'HOSTILE', color: C.red };
  if (has('high')) return { label: 'SUSPICIOUS', color: C.red };
  if (has('medium')) return { label: 'WARN', color: C.yellow };
  if (score === 0) return { label: 'CLEAN', color: C.green };
  return { label: 'NOTED', color: C.cyan };
}

export function renderReport(report: AuditReport, plain?: boolean): string {
  const out: string[] = [];
  const s = report.summary;

  out.push('');
  out.push(renderBanner(plain));
  out.push('');

  out.push(colorize(plain, C.white, `  target    ${report.target}`));
  out.push(colorize(plain, C.gray, `  configs   ${s.filesAudited} file(s) · ${s.serversAudited} server(s) · ${s.toolsAudited} tool(s)`));
  out.push('');

  for (const ca of report.configAudits) {
    out.push(colorize(plain, C.dim, `  ── ${ca.file}  [${ca.configKind}]`));
    if (ca.parseError) {
      out.push(`     ${colorize(plain, C.yellow, 'MALFORMED')}  parse error: ${ca.parseError}`);
      continue;
    }
    if (ca.servers.length === 0) {
      out.push(`     ${colorize(plain, C.gray, 'no mcp servers in this config')}`);
    }
    for (const sa of ca.servers) {
      const score = scoreOf(sa.findings);
      const b = band(score, sa.findings);
      out.push(`     ${colorize(plain, C.bold, sa.name)}  ${colorize(plain, b.color, `${b.label} ${score}/100`)}${sa.liveError ? colorize(plain, C.yellow, `  live check failed: ${sa.liveError}`) : ''}`);
      const visible = sa.findings.filter((f) => f.severity !== 'info');
      if (visible.length === 0) {
        out.push(`       ${colorize(plain, C.gray, 'no config findings')}`);
      }
      for (const f of visible) {
        const style = SEV_STYLE[f.severity];
        const title = f.title.length > 76 ? f.title.slice(0, 75) + '…' : f.title;
        out.push(`       ${colorize(plain, style.color, style.tag)} ${colorize(plain, C.white, title)}`);
        for (const dl of wrapDetail(f.detail)) {
          out.push(`              ${colorize(plain, C.gray, dl)}`);
        }
      }
    }
    out.push('');
  }

  if (report.toolFindings.length > 0) {
    out.push(colorize(plain, C.dim, '  ── tool findings'));
    const poison = report.toolFindings.filter((f) => f.id.startsWith('FAM-PSN'));
    const shadow = report.toolFindings.filter((f) => f.id.startsWith('FAM-SHD'));
    const printF = (f: Finding) => {
      const style = SEV_STYLE[f.severity];
      const scope = [f.server, f.tool].filter(Boolean).join(' / ');
      const title = f.title.length > 78 ? f.title.slice(0, 77) + '…' : f.title;
      out.push(`     ${colorize(plain, style.color, style.tag)} ${colorize(plain, C.white, title)}`);
      if (scope) out.push(`              ${colorize(plain, C.gray, `@ ${scope}`)}`);
      for (const dl of wrapDetail(f.detail)) {
        out.push(`              ${colorize(plain, C.gray, dl)}`);
      }
    };
    for (const f of poison) printF(f);
    for (const f of shadow) printF(f);
    out.push('');
  }

  if (report.rugPull) {
    const r = report.rugPull;
    out.push(colorize(plain, C.dim, '  ── rug-pull diff'));
    if (r.changed.length === 0 && r.added.length === 0 && r.removed.length === 0) {
      out.push(`     ${colorize(plain, C.green, 'NO DRIFT')} definitions match baseline`);
    } else {
      for (const c of r.changed) {
        out.push(`     ${colorize(plain, C.red, 'RUG PULL')} ${colorize(plain, C.white, `${c.server} / ${c.tool}`)} — definition changed since baseline`);
        out.push(`              ${colorize(plain, C.gray, `${c.from.slice(0, 16)}… → ${c.to.slice(0, 16)}…`)}`);
      }
      for (const a of r.added) {
        out.push(`     ${colorize(plain, C.yellow, 'ADDED   ')} ${colorize(plain, C.white, `${a.server} / ${a.tool}`)}`);
      }
      for (const rem of r.removed) {
        out.push(`     ${colorize(plain, C.cyan, 'REMOVED ')} ${colorize(plain, C.white, `${rem.server} / ${rem.tool}`)}`);
      }
    }
    out.push('');
  }

  // summary strip
  const parts: string[] = [];
  const push = (n: number, sev: Severity) => {
    if (n > 0) parts.push(colorize(plain, SEV_STYLE[sev].color, `${n} ${sev}`));
  };
  push(s.bySeverity.critical, 'critical');
  push(s.bySeverity.high, 'high');
  push(s.bySeverity.medium, 'medium');
  push(s.bySeverity.low, 'low');
  if (report.rugPull && report.rugPull.changed.length > 0) {
    parts.push(colorize(plain, C.red, `${report.rugPull.changed.length} rug pull`));
  }
  if (parts.length === 0) {
    out.push(colorize(plain, C.green, '  VERDICT  CLEAN — nothing above info level'));
  } else {
    out.push(`  VERDICT  ${colorize(plain, C.bold, report.verdict.toUpperCase())}  ·  ${parts.join(colorize(plain, C.gray, ' · '))}`);
  }
  out.push('');

  return out.join('\n');
}

function wrap(text: string, width: number): string[] {
  // detail lines render with a 14-space indent; wrap so total stays < 100 cols
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let cur = '';
  for (const w of words) {
    if (cur.length === 0) cur = w;
    else if (cur.length + 1 + w.length <= width) cur += ' ' + w;
    else {
      lines.push(cur);
      cur = w;
    }
  }
  if (cur.length > 0) lines.push(cur);
  return lines;
}

function wrapDetail(text: string): string[] {
  return wrap(text, 80);
}
