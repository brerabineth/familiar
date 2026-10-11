import type { ConfigServer, Finding } from './models.js';

interface LauncherInfo {
  kind:
    | 'npx' | 'uvx' | 'pipx' | 'bunx' | 'dlx'
    | 'node' | 'python' | 'docker' | 'shell' | 'binary' | 'unknown';
  packageSpec?: string;
}

const EXECUTORS: Record<string, LauncherInfo['kind']> = {
  npx: 'npx', 'npx.cmd': 'npx',
  uvx: 'uvx', 'uvx.exe': 'uvx',
  pipx: 'pipx', 'pipx.exe': 'pipx',
  bunx: 'bunx',
  dlx: 'dlx',
};

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe']);

function classifyLauncher(command: string, args: string[]): LauncherInfo {
  const base = (command.split(/[\\/]/).pop() ?? command).toLowerCase();
  if (EXECUTORS[base]) {
    const first = args.find((a) => !a.startsWith('-'));
    return { kind: EXECUTORS[base], packageSpec: first };
  }
  if (base === 'node' || base === 'node.exe') return { kind: 'node' };
  if (base === 'python' || base === 'python3' || base === 'python.exe' || base === 'py') return { kind: 'python' };
  if (base === 'docker') return { kind: 'docker' };
  if (SHELLS.has(base)) return { kind: 'shell' };
  if (command.includes('/') || command.includes('\\')) return { kind: 'binary' };
  if (base === '') return { kind: 'unknown' };
  return { kind: 'binary' };
}

/** is the package spec pinned to an explicit version? */
function isPinned(spec: string | undefined, kind: LauncherInfo['kind'], args: string[]): boolean {
  if (!spec) return false;
  if (kind === 'uvx' || kind === 'pipx') {
    // uvx pkg==1.2.3 / --from pkg==1.2.3
    if (args.some((a) => /==\d/.test(a))) return true;
    return false;
  }
  // npm style: @scope/name@1.2.3 or name@1.2.3
  const afterAt = spec.lastIndexOf('@');
  if (afterAt > 0) {
    const version = spec.slice(afterAt + 1);
    return /^\d+/.test(version);
  }
  return false;
}

const YOLO_FLAGS = [
  '--yolo', '--dangerously-skip-permissions', '--auto-approve', '--autoapprove',
  '--no-verify', '--force', '-y', '--yes', '--fearless',
];

const EXFIL_EXEC = /(?:curl|wget)[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh|(?:iwr|iex|invoke-webrequest|invoke-expression)/i;

export function auditLauncher(s: ConfigServer): Finding[] {
  const findings: Finding[] = [];
  const name = s.name;

  if (s.command) {
    const args = s.args ?? [];
    const info = classifyLauncher(s.command, args);

    // remote package executors: the supply chain front door
    if (info.kind === 'npx' || info.kind === 'uvx' || info.kind === 'pipx' || info.kind === 'bunx' || info.kind === 'dlx') {
      const pinned = isPinned(info.packageSpec, info.kind, args);
      const latest = info.packageSpec?.includes('@latest') || args.some((a) => a === '@latest');
      if (latest || !pinned) {
        findings.push({
          id: 'FAM-LAU-01',
          severity: 'high',
          title: `unpinned remote package execution: ${info.packageSpec ?? s.command}`,
          detail: `${info.kind} fetches and runs code from a public registry at every launch. a compromised publish token replaces this code silently (this exact vector hit agent CLIs in 2026). pin an exact version and verify it.`,
          server: name,
        });
      } else {
        findings.push({
          id: 'FAM-LAU-02',
          severity: 'info',
          title: `remote package execution, pinned: ${info.packageSpec}`,
          detail: `version is pinned, but the code still comes from a public registry. trust the registry, not the pin.`,
          server: name,
        });
      }
    }

    // shell wrappers
    if (info.kind === 'shell') {
      const joined = args.join(' ');
      if (EXFIL_EXEC.test(joined)) {
        findings.push({
          id: 'FAM-LAU-03',
          severity: 'critical',
          title: `pipe-to-shell in launch args`,
          detail: `the launch command downloads code and pipes it straight into a shell interpreter. this is the classic remote code execution bootstrap.`,
          server: name,
        });
      } else {
        findings.push({
          id: 'FAM-LAU-04',
          severity: 'high',
          title: `shell wrapper as launcher`,
          detail: `the server is started through a shell interpreter, which means the "command" is arbitrary script text. whatever it contains runs with your user's full authority.`,
          server: name,
        });
      }
    }

    // docker with dangerous mounts
    if (info.kind === 'docker') {
      const joined = args.join(' ');
      const mounts = args.filter((a) => a.startsWith('-v') || a.startsWith('--volume'));
      const dangerousMount = /(-v|--volume)\s+[^ ]*(\/:|\/home|\/root|\/etc)/.test(joined) || joined.includes('/:');
      if (dangerousMount || mounts.length > 0) {
        findings.push({
          id: 'FAM-LAU-05',
          severity: 'medium',
          title: `dockerized server with host mounts`,
          detail: `container mounts host paths into the server. every mounted path is readable (and possibly writable) by whatever the image contains. mounted: ${mounts.length} volume arg(s).`,
          server: name,
        });
      }
    }

    // sudo
    if (s.command === 'sudo' || args[0] === 'sudo' || info.kind === 'shell' && args.join(' ').includes('sudo ')) {
      findings.push({
        id: 'FAM-LAU-06',
        severity: 'critical',
        title: `server launched with sudo`,
        detail: `an agent-invoked tool running as root. every prompt injection in its tool descriptions now has root.`,
        server: name,
      });
    }

    // yolo flags
    const yolo = args.filter((a) => YOLO_FLAGS.includes(a.toLowerCase()));
    if (yolo.length > 0) {
      findings.push({
        id: 'FAM-LAU-07',
        severity: 'critical',
        title: `permission-bypass flag in launch args: ${yolo.join(' ')}`,
        detail: `the server (or the agent harness it spawns) is told to skip confirmations. combined with one poisoned tool, nothing will ask you before anything happens.`,
        server: name,
      });
    }

    // local code execution: informational
    if (info.kind === 'node' || info.kind === 'python' || info.kind === 'binary') {
      findings.push({
        id: 'FAM-LAU-08',
        severity: 'info',
        title: `local code server: ${s.command}`,
        detail: `runs code from your disk with your user's authority. you own this supply chain — review what it imports.`,
        server: name,
      });
    }
  }

  // remote url transport
  if (s.url) {
    let host = s.url;
    try {
      host = new URL(s.url).host;
    } catch { /* keep raw */ }
    if (/^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(host)) {
      findings.push({
        id: 'FAM-LAU-10',
        severity: 'info',
        title: `remote server on localhost: ${host}`,
        detail: `transport stays on the loopback interface. still a network peer — but not egress.`,
        server: name,
      });
    } else {
      findings.push({
        id: 'FAM-LAU-09',
        severity: 'medium',
        title: `remote MCP server: ${host}`,
        detail: `tool calls and their arguments leave the machine to this host. treat it as a third party watching every invocation.`,
        server: name,
      });
    }
  }

  // silent auto-approve
  if (s.autoApprove && s.autoApprove.length > 0) {
    findings.push({
      id: 'FAM-LAU-11',
      severity: 'medium',
      title: `auto-approved tools: ${s.autoApprove.length}`,
      detail: `these tool names skip human confirmation: ${s.autoApprove.slice(0, 8).join(', ')}${s.autoApprove.length > 8 ? ', …' : ''}. a renamed or shadowed tool in this list executes without asking.`,
      server: name,
    });
  }

  return findings;
}
