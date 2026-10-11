import type { BaselineFile, RugPullDiff, ToolDef } from './models.js';
import { canonicalJson, sha256 } from './util.js';

export function fingerprintTool(server: string, tool: ToolDef): string {
  const payload = {
    server,
    tool: tool.name,
    description: tool.description ?? '',
    inputSchema: tool.inputSchema ?? null,
    annotations: tool.annotations ?? null,
  };
  return sha256(canonicalJson(payload));
}

export function buildBaseline(tools: ToolDef[]): BaselineFile {
  const servers: Record<string, Record<string, string>> = {};
  for (const t of tools) {
    const key = t.server || '(unknown)';
    servers[key] = servers[key] ?? {};
    servers[key]![t.name] = fingerprintTool(key, t);
  }
  return { version: 1, servers };
}

export function diffBaseline(current: ToolDef[], baseline: BaselineFile): RugPullDiff {
  const diff: RugPullDiff = { changed: [], added: [], removed: [] };

  const currentByServer = new Map<string, Map<string, string>>();
  for (const t of current) {
    const key = t.server || '(unknown)';
    if (!currentByServer.has(key)) currentByServer.set(key, new Map());
    currentByServer.get(key)!.set(t.name, fingerprintTool(key, t));
  }

  // changed + removed
  for (const [server, toolMap] of Object.entries(baseline.servers)) {
    const now = currentByServer.get(server);
    for (const [tool, hash] of Object.entries(toolMap)) {
      if (!now || !now.has(tool)) {
        diff.removed.push({ server, tool, hash });
        continue;
      }
      const nowHash = now.get(tool)!;
      if (nowHash !== hash) {
        diff.changed.push({ server, tool, from: hash, to: nowHash });
      }
    }
  }

  // added
  for (const [server, toolMap] of currentByServer) {
    const before = baseline.servers[server];
    if (!before) {
      for (const [tool, hash] of toolMap) {
        diff.added.push({ server, tool, hash });
      }
      continue;
    }
    for (const [tool, hash] of toolMap) {
      if (!(tool in before)) diff.added.push({ server, tool, hash });
    }
  }

  return diff;
}
