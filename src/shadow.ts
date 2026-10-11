import type { Finding, ToolDef } from './models.js';

// names that agents and harnesses treat as privileged
const CORE_NAMES = [
  'execute_command', 'run_command', 'execute', 'shell', 'bash', 'terminal',
  'read_file', 'write_file', 'edit_file', 'list_dir', 'read_files',
  'fetch', 'http_request', 'web_fetch', 'browser_navigate', 'final_answer',
  'send_message', 'search_web', 'git_commit', 'apply_patch', 'eval',
];

function normalize(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

const CORE_NORMS = new Set(CORE_NAMES.map(normalize));

function levenshtein(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const prev = new Array(b.length + 1).fill(0).map((_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0]!;
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j]!;
      prev[j] = Math.min(
        prev[j]! + 1,
        prev[j - 1]! + 1,
        diag + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      diag = tmp;
    }
    if (Math.min(...prev) > max) return max + 1;
  }
  return prev[b.length]!;
}

export function auditShadowing(all: ToolDef[]): Finding[] {
  const findings: Finding[] = [];

  // 1) exact name collisions across different servers
  const byName = new Map<string, ToolDef[]>();
  for (const t of all) {
    const key = normalize(t.name);
    const list = byName.get(key) ?? [];
    list.push(t);
    byName.set(key, list);
  }
  for (const [key, defs] of byName) {
    const servers = [...new Set(defs.map((d) => d.server))];
    if (servers.length > 1) {
      findings.push({
        id: 'FAM-SHD-01',
        severity: 'medium',
        title: `tool name collision: "${defs[0]!.name}" on ${servers.length} servers`,
        detail: `servers ${servers.join(', ')} all expose a tool named "${key}". when the model picks one, the other is invisible — and which one wins is decided by the harness, not by you. rename one of them deliberately.`,
      });
    }
  }

  // 2) mimicry of privileged names
  for (const t of all) {
    const norm = normalize(t.name);
    if (CORE_NORMS.has(norm)) continue; // honest core name
    for (const core of CORE_NAMES) {
      const coreNorm = normalize(core);
      const dist = levenshtein(norm, coreNorm, 2);
      // decorated impersonation: core name with at most 2 extra characters
      const remainder = norm.length - coreNorm.length;
      const wraps = remainder >= -2 && remainder <= 2 && norm.includes(coreNorm) && norm !== coreNorm;
      if (dist <= 2 || wraps) {
        findings.push({
          id: 'FAM-SHD-02',
          severity: 'high',
          title: `tool mimics a privileged name: "${t.name}" ≈ "${core}"`,
          detail: `the name sits ${dist === 0 ? 'inside' : `${dist} edit(s) from`} the privileged name "${core}". agents route by name; a near-name is how a stranger's tool ends up where yours should be. verify this server's origin before trusting it.`,
          server: t.server,
          tool: t.name,
        });
        break;
      }
    }
  }

  return findings;
}
