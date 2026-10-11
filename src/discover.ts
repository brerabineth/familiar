import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';

export interface ConfigSource {
  path: string;
  kind: string;
}

interface Candidate {
  /** relative to home, or absolute-ish marker; empty string means cwd-relative */
  rel: string[];
  kind: string;
}

const HOME_CANDIDATES: Candidate[] = [
  { kind: 'claude-desktop', rel: ['Library/Application Support/Claude/claude_desktop_config.json'] },
  { kind: 'claude-desktop', rel: ['.config/claude/claude_desktop_config.json'] },
  { kind: 'claude-desktop', rel: ['AppData/Roaming/Claude/claude_desktop_config.json'] },
  { kind: 'claude-code', rel: ['.claude.json'] },
  { kind: 'cursor', rel: ['.cursor/mcp.json'] },
  { kind: 'windsurf', rel: ['.codeium/windsurf/mcp_config.json'] },
  { kind: 'vscode', rel: ['.vscode/mcp.json'] },
  { kind: 'gemini-cli', rel: ['.gemini/settings.json'] },
  { kind: 'zed', rel: ['.config/zed/settings.json'] },
  { kind: 'continue', rel: ['.continue/config.json'] },
  { kind: 'cline', rel: ['Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json'] },
  { kind: 'cline', rel: ['AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json'] },
];

const CWD_CANDIDATES: Candidate[] = [
  { kind: 'project', rel: ['.mcp.json'] },
  { kind: 'cursor', rel: ['.cursor/mcp.json'] },
  { kind: 'vscode', rel: ['.vscode/mcp.json'] },
];

/** every plausible MCP config on this machine, whether or not it exists */
export function candidateSources(home?: string, cwd?: string): ConfigSource[] {
  const h = home ?? homedir();
  const c = cwd ?? process.cwd();
  const out: ConfigSource[] = [];
  for (const cand of HOME_CANDIDATES) {
    out.push({ path: join(h, ...cand.rel), kind: cand.kind });
  }
  for (const cand of CWD_CANDIDATES) {
    out.push({ path: join(c, ...cand.rel), kind: cand.kind });
  }
  return out;
}

/** candidates that actually exist on disk (deduplicated by absolute path) */
export function discoverSources(home?: string, cwd?: string): ConfigSource[] {
  const seen = new Set<string>();
  const out: ConfigSource[] = [];
  for (const c of candidateSources(home, cwd)) {
    const key = resolve(c.path);
    if (seen.has(key)) continue;
    seen.add(key);
    if (existsSync(c.path)) out.push({ path: c.path, kind: c.kind });
  }
  return out;
}

/** normalize explicit paths from the CLI */
export function explicitSources(paths: string[]): ConfigSource[] {
  return paths.map((p) => {
    const abs = isAbsolute(p) ? p : resolve(p);
    return { path: abs, kind: kindFromFilename(abs) };
  });
}

function kindFromFilename(path: string): string {
  const base = path.split(/[\\/]/).pop() ?? path;
  if (base.includes('claude_desktop')) return 'claude-desktop';
  if (base.includes('claude')) return 'claude-code';
  if (base.includes('cline')) return 'cline';
  if (base === 'settings.json') return 'agent-settings';
  if (path.includes('.cursor')) return 'cursor';
  if (path.includes('windsurf') || path.includes('codeium')) return 'windsurf';
  if (path.includes('.vscode')) return 'vscode';
  if (path.includes('zed')) return 'zed';
  if (path.includes('continue')) return 'continue';
  if (path.includes('gemini')) return 'gemini-cli';
  return 'unknown';
}
