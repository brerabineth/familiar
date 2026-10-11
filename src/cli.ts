#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { once } from 'node:events';
import { dirname, isAbsolute, resolve } from 'node:path';
import { discoverSources, explicitSources, candidateSources } from './discover.js';
import { parseConfig } from './parse.js';
import { auditLauncher } from './launchers.js';
import { scanEnv } from './secrets.js';
import { auditTools } from './poison.js';
import { auditShadowing } from './shadow.js';
import { handshake } from './client.js';
import { buildBaseline, diffBaseline } from './baseline.js';
import { summarize, verdictOf, exitCodeFor } from './score.js';
import { writeJson, writeMarkdown } from './report.js';
import { renderReport } from './terminal.js';
import { forge } from './forge.js';
import { readJsonFile } from './util.js';
import type {
  AuditReport, ConfigAudit, ConfigServer, Finding, ToolDef,
} from './models.js';

export const VERSION = '0.1.0';

const USAGE = `familiar ${VERSION} — audit the familiars your agent keeps

usage:
  familiar scan [paths...]        audit every MCP config on this machine (or explicit files)
      --live                      also handshake each stdio server and audit its tools
      --json <file>               write machine report
      --md <file>                 write markdown report
  familiar tools                  handshake servers and audit their tool definitions
      --server <name>             audit one server from discovered configs
      --all                       audit every discovered stdio server
      --from "<cmd> [args...]"    handshake an explicit command
      --timeout <ms>              per-request timeout (default 10000)
  familiar baseline               fingerprint current tool definitions
      --out <file>                default: .familiar-baseline.json
  familiar check                  compare live tools against baseline (rug-pull detector)
      --baseline <file>
  familiar forge                  generate synthetic configs for demos and tests
      --scenario clean|dirty      default: dirty
      --out <dir>
  familiar paths                  list every config path familiar would check

short flags: -f --from · -o --out · -b --baseline · -s --scenario · -j --json · -m --md
flags: --plain (no ansi) · --home <dir> · --cwd <dir> (target discovery overrides)
exit codes: 0 clean · 1 error · 2 findings · 3 rug-pull drift · 10 critical
`;

interface Parsed {
  cmd: string;
  rest: string[];
  flags: Map<string, string | boolean>;
}

function parseArgs(argv: string[]): Parsed {
  const knownValue = new Set(['--json', '--md', '--server', '--from', '--timeout', '--out', '--baseline', '--scenario', '--home', '--cwd']);
  const aliases: Record<string, string> = { '-f': '--from', '-o': '--out', '-b': '--baseline', '-s': '--scenario', '-j': '--json', '-m': '--md' };
  const flags = new Map<string, string | boolean>();
  const rest: string[] = [];
  let cmd = '';
  for (let i = 0; i < argv.length; i++) {
    let a = argv[i]!;
    if (aliases[a]) a = aliases[a]!;
    if (a === '--version') { flags.set('--version', true); continue; }
    if (a === '-h' || a === '--help') { flags.set('--help', true); continue; }
    if (a === '--plain') { flags.set('--plain', true); continue; }
    if (a === '--live') { flags.set('--live', true); continue; }
    if (a === '--all') { flags.set('--all', true); continue; }
    if (knownValue.has(a)) {
      const v = argv[++i];
      if (v === undefined) { fail(`missing value for ${a}`); }
      flags.set(a, v);
      continue;
    }
    if (!a.startsWith('-') && cmd === '') { cmd = a; continue; }
    rest.push(a);
  }
  return { cmd, rest, flags };
}

function fail(msg: string): never {
  console.error(`familiar: ${msg}`);
  process.exit(1);
}

function str(flags: Map<string, string | boolean>, key: string): string | undefined {
  const v = flags.get(key);
  return typeof v === 'string' ? v : undefined;
}

// ───────────────────────────── scan ─────────────────────────────

function loadConfigs(sources: { path: string; kind: string }[]): { audits: ConfigAudit[]; servers: ConfigServer[] } {
  const audits: ConfigAudit[] = [];
  const servers: ConfigServer[] = [];
  for (const src of sources) {
    if (!existsSync(src.path)) continue;
    const { data, error } = readJsonFile(src.path);
    if (error !== undefined) {
      audits.push({ file: src.path, configKind: src.kind, servers: [], parseError: error });
      continue;
    }
    const parsed = parseConfig(data, src.path, src.kind);
    audits.push({ file: src.path, configKind: src.kind, servers: parsed.map((s) => ({ name: s.name, file: s.file, configKind: s.configKind, findings: [] })) });
    servers.push(...parsed);
  }
  return { audits, servers };
}

function auditConfigServers(servers: ConfigServer[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const s of servers) {
    const findings: Finding[] = [];
    if (s.disabled) {
      findings.push({ id: 'FAM-CFG-01', severity: 'info', title: 'server disabled', detail: 'entry is disabled in config. inert, but still readable — secrets inside are still at rest.', server: s.name, file: s.file });
    }
    findings.push(...auditLauncher(s));
    if (s.env) findings.push(...scanEnv(s.env, s.name));
    for (const f of findings) { if (f.file === undefined) f.file = s.file; }
    map.set(s.name, findings);
  }
  return map;
}

function cmdScan(p: Parsed): number {
  const home = str(p.flags, '--home');
  const cwd = str(p.flags, '--cwd');
  const sources = p.rest.length > 0 ? explicitSources(p.rest) : discoverSources(home, cwd);
  const { audits, servers } = loadConfigs(sources);
  const findingsByServer = auditConfigServers(servers);

  // attach findings into audits
  for (const ca of audits) {
    for (const sa of ca.servers) {
      sa.findings = findingsByServer.get(sa.name) ?? [];
    }
  }

  const toolFindings: Finding[] = [];
  const toolsAudited = 0;

  const allFindings: Finding[] = [
    ...[...findingsByServer.values()].flat(),
    ...toolFindings,
  ];
  const summary = summarize(audits.length, servers.length, toolsAudited, allFindings);
  const report: AuditReport = {
    target: p.rest.length > 0 ? p.rest.join(', ') : 'machine',
    configAudits: audits,
    toolFindings,
    summary,
    verdict: verdictOf(allFindings),
  };

  emit(report, p);
  return exitCodeFor(allFindings, 0);
}

// ───────────────────────────── tools ─────────────────────────────

interface ServerSelection {
  label: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  cwd?: string;
}

function fromSelection(from: string): ServerSelection {
  const parts = from.split(/\s+/).filter(Boolean);
  if (parts.length === 0) fail('--from needs a command');
  // label: prefer the server script's basename over the bare interpreter
  let label = parts[0]!;
  const script = parts.slice(1).find((a) => !a.startsWith('-') && a.includes('.'));
  if (script) {
    const base = script.split(/[\\/]/).pop() ?? script;
    label = base.replace(/\.(mjs|cjs|js|py|ts)$/, '');
  }
  return { label, command: parts[0]!, args: parts.slice(1) };
}

function selectServers(p: Parsed): ServerSelection[] {
  const home = str(p.flags, '--home');
  const cwd = str(p.flags, '--cwd');
  const from = str(p.flags, '--from');

  if (from) {
    return [fromSelection(from)];
  }

  const { servers } = loadConfigs(discoverSources(home, cwd));
  const stdio = servers.filter((s) => s.command && !s.disabled);
  const wanted = str(p.flags, '--server');
  if (wanted) {
    const match = stdio.find((s) => s.name === wanted);
    if (!match) fail(`no stdio server named "${wanted}" in discovered configs`);
    return [{ label: match.name, command: match.command!, args: match.args ?? [], ...(match.env ? { env: match.env } : {}), ...(match.cwd ? { cwd: match.cwd } : {}) }];
  }
  if (p.flags.get('--all')) {
    return stdio.map((s) => ({ label: s.name, command: s.command!, args: s.args ?? [], ...(s.env ? { env: s.env } : {}), ...(s.cwd ? { cwd: s.cwd } : {}) }));
  }
  fail('choose --server <name>, --all, or --from "<cmd> [args...]"');
}

async function collectTools(selections: ServerSelection[], timeoutMs: number): Promise<{ tools: ToolDef[]; errors: Array<{ label: string; error: string }> }> {
  const tools: ToolDef[] = [];
  const errors: Array<{ label: string; error: string }> = [];
  for (const sel of selections) {
    try {
      const res = await handshake({ command: sel.command, args: sel.args, ...(sel.env ? { env: sel.env } : {}), ...(sel.cwd ? { cwd: sel.cwd } : {}), timeoutMs });
      for (const t of res.tools) t.server = sel.label;
      tools.push(...res.tools);
    } catch (e) {
      errors.push({ label: sel.label, error: (e as Error).message });
    }
  }
  return { tools, errors };
}

async function cmdTools(p: Parsed): Promise<number> {
  const timeoutMs = Number(str(p.flags, '--timeout') ?? '10000');
  const selections = selectServers(p);
  const { tools, errors } = await collectTools(selections, timeoutMs);

  const poison = tools.flatMap((t) => auditTools([t]));
  const shadow = auditShadowing(tools);
  const toolFindings = [...poison, ...shadow];

  const summary = summarize(0, selections.length, tools.length, toolFindings);
  const report: AuditReport = {
    target: 'live tool definitions',
    configAudits: [],
    toolFindings,
    summary,
    verdict: verdictOf(toolFindings),
  };

  // live errors go in as low findings for visibility
  for (const err of errors) {
    report.toolFindings.push({ id: 'FAM-LIVE-01', severity: 'low', title: `server unreachable: ${err.label}`, detail: `handshake failed: ${err.error}` });
  }

  emit(report, p);
  return exitCodeFor(toolFindings, 0);
}

// ───────────────────────── baseline / check ─────────────────────────

async function collectForBaseline(p: Parsed): Promise<ToolDef[]> {
  const timeoutMs = Number(str(p.flags, '--timeout') ?? '10000');
  const home = str(p.flags, '--home');
  const cwd = str(p.flags, '--cwd');

  const from = str(p.flags, '--from');
  let selections: ServerSelection[];
  if (from) {
    selections = [fromSelection(from)];
  } else {
    const { servers } = loadConfigs(discoverSources(home, cwd));
    const stdio = servers.filter((s) => s.command && !s.disabled);
    const wanted = str(p.flags, '--server');
    selections = stdio
      .filter((s) => wanted === undefined || s.name === wanted)
      .map((s) => ({ label: s.name, command: s.command!, args: s.args ?? [], ...(s.env ? { env: s.env } : {}), ...(s.cwd ? { cwd: s.cwd } : {}) }));
  }
  const { tools } = await collectTools(selections, timeoutMs);
  return tools;
}

async function cmdBaseline(p: Parsed): Promise<number> {
  const out = str(p.flags, '--out') ?? '.familiar-baseline.json';
  const tools = await collectForBaseline(p);
  const baseline = buildBaseline(tools);
  mkdirSync(dirname(resolve(out)), { recursive: true });
  writeFileSync(out, JSON.stringify(baseline, null, 2) + '\n', 'utf8');
  const serverCount = Object.keys(baseline.servers).length;
  const toolCount = Object.values(baseline.servers).reduce((acc, m) => acc + Object.keys(m).length, 0);
  console.log(`baseline written: ${out} · ${serverCount} server(s) · ${toolCount} tool(s) fingerprinted`);
  return 0;
}

async function cmdCheck(p: Parsed): Promise<number> {
  const baselinePath = str(p.flags, '--baseline') ?? '.familiar-baseline.json';
  if (!existsSync(baselinePath)) fail(`baseline not found: ${baselinePath} (run "familiar baseline" first)`);
  const { data, error } = readJsonFile(baselinePath);
  if (error !== undefined) fail(`baseline unreadable: ${error}`);
  const current = await collectForBaseline(p);
  const diff = diffBaseline(current, data as Parameters<typeof diffBaseline>[1]);

  const summary = summarize(0, 0, current.length, []);
  const report: AuditReport = {
    target: `baseline check: ${baselinePath}`,
    configAudits: [],
    toolFindings: [],
    rugPull: diff,
    summary,
    verdict: diff.changed.length > 0 ? 'critical' : 'low',
  };
  emit(report, p);
  return exitCodeFor([], diff.changed.length);
}

// ───────────────────────────── misc ─────────────────────────────

function cmdForge(p: Parsed): number {
  const scenario = str(p.flags, '--scenario');
  const sc = scenario === 'clean' ? 'clean' : 'dirty';
  const outDir = str(p.flags, '--out');
  if (!outDir) fail('--out <dir> required');
  const res = forge(sc, resolve(outDir));
  for (const f of res.files) console.log(`forged: ${f}`);
  return 0;
}

function cmdPaths(p: Parsed): number {
  const home = str(p.flags, '--home');
  const cwd = str(p.flags, '--cwd');
  for (const c of candidateSources(home, cwd)) {
    const mark = existsSync(c.path) ? 'present' : 'absent ';
    console.log(`  [${mark}] ${c.path}  (${c.kind})`);
  }
  return 0;
}

function emit(report: AuditReport, p: Parsed): void {
  const plain = p.flags.get('--plain') === true;
  const jsonPath = str(p.flags, '--json');
  const mdPath = str(p.flags, '--md');

  if (jsonPath) writeJson(report, jsonPath);
  if (mdPath) writeMarkdown(report, mdPath);

  const text = renderReport(report, plain);
  process.stdout.write(text);
}

// ───────────────────────────── main ─────────────────────────────

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const p = parseArgs(argv);
  let code = 0;

  if (p.flags.get('--version')) { console.log(`familiar ${VERSION}`); return; }
  if (p.flags.get('--help') || p.cmd === '' ) { process.stdout.write(USAGE); await once(process.stdout, 'finish').catch(() => undefined); return; }

  switch (p.cmd) {
    case 'scan':
      code = p.flags.get('--live') ? await cmdScanLive(p) : cmdScan(p);
      break;
    case 'tools': code = await cmdTools(p); break;
    case 'baseline': code = await cmdBaseline(p); break;
    case 'check': code = await cmdCheck(p); break;
    case 'forge': code = cmdForge(p); break;
    case 'paths': code = cmdPaths(p); break;
    default: {
      console.error(`familiar: unknown command "${p.cmd}"`);
      process.stdout.write(USAGE);
      code = 1;
    }
  }
  // let stdout drain fully before exiting (pipe-safe)
  process.exitCode = code;
  await once(process.stdout, 'finish').catch(() => undefined);
}

/** scan with --live: config audit + per-server handshake + poison/shadow */
async function cmdScanLive(p: Parsed): Promise<number> {
  const home = str(p.flags, '--home');
  const cwd = str(p.flags, '--cwd');
  const timeoutMs = Number(str(p.flags, '--timeout') ?? '10000');
  const sources = p.rest.length > 0 ? explicitSources(p.rest) : discoverSources(home, cwd);
  const { audits, servers } = loadConfigs(sources);
  const findingsByServer = auditConfigServers(servers);

  for (const ca of audits) {
    for (const sa of ca.servers) {
      sa.findings = findingsByServer.get(sa.name) ?? [];
    }
  }

  const collected: ToolDef[] = [];
  for (const s of servers) {
    if (s.disabled || !s.command) continue;
    const sa = audits.find((a) => a.file === s.file)?.servers.find((x) => x.name === s.name);
    try {
      const res = await handshake({
        command: s.command,
        args: s.args ?? [],
        ...(s.env ? { env: s.env } : {}),
        ...(s.cwd ? { cwd: s.cwd } : {}),
        timeoutMs,
      });
      for (const t of res.tools) t.server = s.name;
      collected.push(...res.tools);
      if (sa) sa.tools = res.tools;
    } catch (e) {
      if (sa) sa.liveError = (e as Error).message;
    }
  }

  const poison = collected.flatMap((t) => auditTools([t]));
  const shadow = auditShadowing(collected);
  const toolFindings = [...poison, ...shadow];
  const allFindings = [...[...findingsByServer.values()].flat(), ...toolFindings];

  const summary = summarize(audits.length, servers.length, collected.length, allFindings);
  const report: AuditReport = {
    target: p.rest.length > 0 ? p.rest.join(', ') : 'machine (live)',
    configAudits: audits,
    toolFindings,
    summary,
    verdict: verdictOf(allFindings),
  };
  emit(report, p);
  return exitCodeFor(allFindings, 0);
}

main().catch((e: Error) => {
  console.error(`familiar: ${e.message}`);
  process.exit(1);
});
