import { spawn } from 'node:child_process';
import type { ToolDef } from './models.js';

export interface HandshakeResult {
  tools: ToolDef[];
  serverInfo?: { name?: string; version?: string };
  protocolVersion?: string;
  stderrTail?: string;
}

export interface LiveOptions {
  command: string;
  args: string[];
  env?: Record<string, string>;
  cwd?: string;
  /** ms; default 10000 */
  timeoutMs?: number;
  /** max tools to collect (safety) */
  maxTools?: number;
}

const PROTOCOL_VERSION = '2025-06-18';
const CLIENT_INFO = { name: 'familiar', version: '0.1.0' };

interface Pending {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

/**
 * minimal MCP client over stdio: line-delimited JSON-RPC.
 * initialize → notifications/initialized → tools/list (with pagination).
 * everything is bounded by timeouts; the server process is always killed.
 */
export async function handshake(opts: LiveOptions): Promise<HandshakeResult> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const maxTools = opts.maxTools ?? 500;

  const child = spawn(opts.command, opts.args, {
    cwd: opts.cwd,
    env: { ...minimalEnv(), ...(opts.env ?? {}) },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const pending = new Map<number, Pending>();
  const stderrChunks: Buffer[] = [];
  let stderrBytes = 0;
  let buf = '';

  let nextId = 1;

  const request = <T>(method: string, params: unknown, label: string): Promise<T> => {
    const id = nextId++;
    const body = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`${label}: timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      pending.set(id, { resolve: (v) => resolve(v as T), reject, timer });
      child.stdin.write(body, (err) => {
        if (err) {
          clearTimeout(timer);
          pending.delete(id);
          reject(new Error(`${label}: stdin write failed: ${err.message}`));
        }
      });
    });
  };

  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk: string) => {
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line === '') continue;
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(line) as Record<string, unknown>;
      } catch {
        continue; // non-JSON chatter on stdout — ignore
      }
      const id = msg.id;
      if (typeof id === 'number' && pending.has(id)) {
        const p = pending.get(id)!;
        pending.delete(id);
        clearTimeout(p.timer);
        if (msg.error !== undefined && msg.error !== null) {
          p.reject(new Error(`${JSON.stringify(msg.error).slice(0, 300)}`));
        } else {
          p.resolve(msg.result);
        }
      }
    }
  });

  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => {
    if (stderrBytes < 16_000) {
      stderrChunks.push(Buffer.from(chunk, 'utf8'));
      stderrBytes += Buffer.byteLength(chunk);
    }
  });

  const cleanup = () => {
    for (const [, p] of pending) clearTimeout(p.timer);
    pending.clear();
    try { child.stdin.destroy(); } catch { /* ignore */ }
    try { child.kill('SIGKILL'); } catch { /* ignore */ }
  };

  try {
    const initResult = await request<{
      protocolVersion?: string;
      serverInfo?: { name?: string; version?: string };
    }>(
      'initialize',
      { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO },
      'initialize',
    );

    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

    const tools: ToolDef[] = [];
    let cursor: string | undefined;
    do {
      const result = await request<{ tools?: unknown[]; nextCursor?: string }>(
        'tools/list',
        cursor !== undefined ? { cursor } : {},
        'tools/list',
      );
      const list = Array.isArray(result.tools) ? result.tools : [];
      for (const raw of list) {
        if (typeof raw !== 'object' || raw === null) continue;
        const t = raw as Record<string, unknown>;
        if (typeof t.name !== 'string') continue;
        tools.push({
          server: '',
          name: t.name,
          description: typeof t.description === 'string' ? t.description : '',
          ...(t.inputSchema !== undefined ? { inputSchema: t.inputSchema } : {}),
          ...(t.annotations !== undefined ? { annotations: t.annotations } : {}),
        });
        if (tools.length >= maxTools) break;
      }
      cursor = typeof result.nextCursor === 'string' ? result.nextCursor : undefined;
    } while (cursor !== undefined && tools.length < maxTools);

    for (const t of tools) t.server = opts.cwd ?? opts.command;

    return {
      tools,
      ...(initResult.serverInfo !== undefined ? { serverInfo: initResult.serverInfo } : {}),
      ...(initResult.protocolVersion !== undefined ? { protocolVersion: initResult.protocolVersion } : {}),
      ...(stderrBytes > 0 ? { stderrTail: Buffer.concat(stderrChunks).toString('utf8').slice(-2000) } : {}),
    };
  } finally {
    cleanup();
  }
}

function minimalEnv(): NodeJS.ProcessEnv {
  const keep = ['PATH', 'HOME', 'USER', 'TMPDIR', 'LANG', 'SystemRoot', 'TEMP', 'TMP', 'APPDATA', 'LOCALAPPDATA', 'USERPROFILE'];
  const out: NodeJS.ProcessEnv = {};
  for (const k of keep) {
    const v = process.env[k];
    if (v !== undefined) out[k] = v;
  }
  return out;
}
