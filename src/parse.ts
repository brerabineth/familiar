import type { ConfigServer } from './models.js';

/**
 * tolerant extraction of mcpServers entries across dialects:
 *  - { "mcpServers": { name: {...} } }          (claude desktop / code, cursor, windsurf, project .mcp.json)
 *  - { "servers": { name: {...} } }             (vs code mcp.json)
 *  - { "context_servers": { name: {...} } }     (zed)
 *  - { "mcpServers": {...} } nested in settings (gemini cli settings.json)
 *  - { "mcpServers": {...}, "experimental": {...} } inside continue config
 */
export function parseConfig(data: unknown, file: string, kind: string): ConfigServer[] {
  if (data === null || typeof data !== 'object') return [];
  const root = data as Record<string, unknown>;
  const servers: ConfigServer[] = [];

  const roots: Array<[Record<string, unknown>, string]> = [];
  if (isObject(root.mcpServers)) roots.push([root.mcpServers, 'mcpServers']);
  if (isObject(root.servers)) roots.push([root.servers, 'servers']);
  if (isObject(root.context_servers)) roots.push([root.context_servers, 'context_servers']);
  // gemini: mcpServers can sit under top level; zed nested under settings
  if (isObject(root.settings) && isObject((root.settings as Record<string, unknown>).context_servers)) {
    roots.push([(root.settings as Record<string, unknown>).context_servers as Record<string, unknown>, 'context_servers']);
  }

  for (const [map, originKey] of roots) {
    for (const [name, rawValue] of Object.entries(map)) {
      if (!isObject(rawValue)) continue;
      const value = rawValue as Record<string, unknown>;

      // zed wraps the command in `source` / uses settings; vs code uses `type`
      const command = str(value.command) ?? str(value.cmd);
      const args = strArray(value.args) ?? strArray(value.arguments);
      const env = strMap(value.env) ?? strMap(value.environment);
      const url = str(value.url) ?? str(value.uri);
      const cwd = str(value.cwd) ?? str(value.workingDirectory);
      const disabled = value.disabled === true || value.enabled === false;

      const autoApprove =
        strArray(value.autoApprove) ??
        strArray(value.alwaysAllow) ??
        permissionsAllow(value.permissions) ??
        strArray(value.allowedTools) ??
        undefined;

      servers.push({
        file,
        configKind: kind,
        name,
        ...(command !== undefined ? { command } : {}),
        ...(args !== undefined ? { args } : {}),
        ...(env !== undefined ? { env } : {}),
        ...(url !== undefined ? { url } : {}),
        ...(cwd !== undefined ? { cwd } : {}),
        ...(autoApprove !== undefined ? { autoApprove } : {}),
        disabled,
      });
      void originKey;
    }
  }
  return servers;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function strArray(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out = v.filter((x): x is string => typeof x === 'string');
  return out.length > 0 ? out : undefined;
}

function strMap(v: unknown): Record<string, string> | undefined {
  if (!isObject(v)) return undefined;
  const out: Record<string, string> = {};
  for (const [k, val] of Object.entries(v)) {
    if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') {
      out[k] = String(val);
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function permissionsAllow(v: unknown): string[] | undefined {
  if (!isObject(v)) return undefined;
  const allow = (v as Record<string, unknown>).allow;
  if (Array.isArray(allow)) {
    return allow
      .map((x) => (typeof x === 'string' ? x : isObject(x) && typeof x.tool === 'string' ? x.tool : null))
      .filter((x): x is string => typeof x === 'string')
      .map((x) => x.replace(/\(.*/, '').trim())
      .filter((x) => x.length > 0);
  }
  return undefined;
}
