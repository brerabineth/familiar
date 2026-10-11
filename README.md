# familiar

audit the familiars your agent keeps.

your ai agent trusts every tool it summons. those tools are written by
strangers. their descriptions are read by the model — not by you.
that gap is where the attacks live.

microsoft now classifies mcp tool descriptions as supply-chain assets.
owasp lists tool poisoning in its mcp top 10. the mcp tox benchmark
measured 1,312 malicious cases against 45 live servers. this is not
theory anymore.

familiar reads what your agent actually runs, on your machine, offline,
with zero runtime dependencies.

```
what serves you may serve another.
```

## what it audits

**configs** — every place agents keep their familiars:

| source | path |
|---|---|
| claude desktop | `claude_desktop_config.json` |
| claude code | `~/.claude.json`, `.mcp.json` |
| cursor | `~/.cursor/mcp.json`, `./.cursor/mcp.json` |
| vs code | `.vscode/mcp.json` |
| windsurf | `~/.codeium/windsurf/mcp_config.json` |
| gemini cli | `~/.gemini/settings.json` |
| zed | `~/.config/zed/settings.json` |
| continue | `~/.continue/config.json` |
| cline | `cline_mcp_settings.json` |

per server: unpinned `npx`/`uvx`/`pipx` execution (the vector that
compromised agent clis in 2026), shell wrappers, pipe-to-shell bootstraps,
`--dangerously-skip-permissions` and friends, plaintext credentials in env
(30+ token formats, always masked), auto-approved tool lists, remote
transports, docker host mounts, sudo.

**tools** — a real mcp handshake over stdio (`initialize` → `tools/list`),
then every tool definition is read the way a model would read it:

- instruction override and concealment directives
- filesystem harvesting (~/.ssh, wallets, browser profiles, shell history)
- exfiltration directives and known callback hosts
- invisible unicode: zero-width, bidi controls, variation selectors, and
  the tag block (u+e0000–e007f) used to smuggle a second description
  past human review
- homoglyphs, base64 blobs, url callbacks
- tool shadowing: name collisions across servers, typo-squat mimicry of
  privileged names (`execute_commnad` ≈ `execute_command`)

**baseline** — fingerprint every tool definition, then watch them.

a tool you approved last week is not necessarily the tool that runs today.
`familiar check` diffs live definitions against your baseline and calls
the drift what it is: a rug pull. exit code 3.

## usage

```sh
# audit every config on this machine
familiar scan

# include a live handshake of every stdio server
familiar scan --live

# one file, json report
familiar scan ~/.cursor/mcp.json --json report.json

# audit live tool definitions of one server
familiar tools --server docs-search
familiar tools --from "node ./my-server.js"

# record a baseline of tool definitions
familiar baseline --all --out .familiar-baseline.json

# later: rug-pull check (exit 3 on drift)
familiar check --baseline .familiar-baseline.json --all
```

generate synthetic configs for demos and tests:

```sh
familiar forge --scenario dirty --out ./lab
familiar scan --home ./lab --cwd ./lab
```

## findings catalog

| id | severity | signal |
|---|---|---|
| fam-lau-01 | high | unpinned remote package execution |
| fam-lau-03 | critical | pipe-to-shell bootstrap |
| fam-lau-04 | high | shell wrapper launcher |
| fam-lau-05 | medium | docker host mounts |
| fam-lau-06 | critical | sudo |
| fam-lau-07 | critical | permission-bypass flags |
| fam-lau-09 | medium | remote transport |
| fam-lau-11 | medium | auto-approved tool list |
| fam-sec-01…12 | high–critical | plaintext credentials (masked) |
| fam-sec-21 | high | probable credential under secret name |
| fam-psn-01 | critical | instruction override directive |
| fam-psn-02 | critical | concealment directive |
| fam-psn-03 | critical | filesystem harvesting |
| fam-psn-04 | critical | exfiltration directive |
| fam-psn-05 | high | identity hijack |
| fam-psn-06 | high | tool precedence claim |
| fam-psn-10 | critical | invisible characters (smuggling channel) |
| fam-psn-12 | low–critical | external url / callback host |
| fam-psn-13 | high | base64 payload in description |
| fam-shd-01 | medium | tool name collision across servers |
| fam-shd-02 | high | typo-squat mimicry of privileged name |

## exit codes

```
0   clean (nothing above info)
1   operational error
2   findings
3   rug-pull drift
10  critical findings
```

build your cron around them.

## install

node >= 18. nothing else.

```sh
npm install -g familiar-mcp     # if published
# or run the single file from releases:
node familiar.cjs scan
```

## trust model

familiar reads config files and speaks json-rpc to servers you already
installed. it never sends your data anywhere: no api, no telemetry, no
accounts. the only network it touches is the servers you asked it to
handshake (`tools`, `--live`) — and those run on your machine.

live handshakes spawn the server process. that is the point — but know
it: auditing a stranger's tool executes the stranger's code. run in a
sandbox when the origin is unknown.

limitations, stated plainly: pattern analysis is not mind reading. a
clean result means no known signature fired, not that a tool is loyal.
baseline checks catch definition drift; they cannot catch a poisoned
server that was malicious from birth and never changes.

## license

mit
