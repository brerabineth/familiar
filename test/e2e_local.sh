#!/usr/bin/env bash
# familiar — end-to-end proof. every command exercised against real processes.
set -u
cd "$(dirname "$0")/.."
ROOT="$PWD"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok  - $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL- $1"; }
check(){ if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (want $1 got $2)"; fi }
contains(){ if echo "$2" | grep -qF "$1"; then ok "$3"; else bad "$3 (missing: $1)"; fi }
absent(){ if echo "$2" | grep -qF "$1"; then bad "$3 (leaked: $1)"; else ok "$3"; fi }

echo "══ familiar e2e ══"
echo "[1] build"
npm run -s build && ok "tsc build" || bad "tsc build"
VER=$(node dist/cli.js --version)
contains "familiar 0.1.0" "$VER" "--version"

LAB=$(mktemp -d)
CLI="node $ROOT/dist/cli.js"
trap 'rm -rf "$LAB"' EXIT

echo "[2] forge determinism"
$CLI forge --scenario dirty --out "$LAB/d1" >/dev/null
$CLI forge --scenario dirty --out "$LAB/d2" >/dev/null
if diff -r "$LAB/d1" "$LAB/d2" >/dev/null 2>&1; then ok "forge byte-identical"; else bad "forge determinism"; fi

echo "[3] scan: dirty fixture"
$CLI scan --home "$LAB/d1" --cwd "$LAB/d1" --plain > "$LAB/scan_dirty.txt" 2>&1
check 10 $? "scan dirty exits 10 (critical)"
contains "HOSTILE" "$(cat "$LAB/scan_dirty.txt")" "hostile verdict rendered"
contains "pipe-to-shell" "$(cat "$LAB/scan_dirty.txt")" "pipe-to-shell caught"
contains "permission-bypass flag" "$(cat "$LAB/scan_dirty.txt")" "yolo flag caught"
contains "plaintext credential" "$(cat "$LAB/scan_dirty.txt")" "plaintext secret caught"
absent "wJalrXUtnFEMI" "$(cat "$LAB/scan_dirty.txt")" "aws secret value masked"
absent "github_pat_11ABCDEFG" "$(cat "$LAB/scan_dirty.txt")" "github token value masked"

echo "[4] scan: json report integrity"
$CLI scan --home "$LAB/d1" --cwd "$LAB/d1" --json "$LAB/report.json" >/dev/null 2>&1
check 10 $? "json scan exits 10"
python3 - "$LAB/report.json" <<'PY' && ok "json valid + masked" || bad "json invalid or leak"
import json, sys
r = json.load(open(sys.argv[1]))
assert r['summary']['serversAudited'] >= 5, "expected >=5 servers"
assert r['summary']['bySeverity']['critical'] >= 3
raw = open(sys.argv[1]).read()
assert 'wJalrXUtnFEMI' not in raw, "aws secret leaked"
assert 'github_pat_11ABCDEFG' not in raw, "github token leaked"
PY

echo "[5] scan: clean fixture"
$CLI forge --scenario clean --out "$LAB/c1" >/dev/null
$CLI scan --home "$LAB/c1" --cwd "$LAB/c1" --plain > "$LAB/scan_clean.txt" 2>&1
check 0 $? "scan clean exits 0"
contains "CLEAN" "$(cat "$LAB/scan_clean.txt")" "clean verdict rendered"

echo "[6] malformed config tolerated"
mkdir -p "$LAB/broken/.cursor"
printf '{ mcpServers: BROKEN' > "$LAB/broken/.cursor/mcp.json"
$CLI scan --home "$LAB/broken" --cwd "$LAB/broken" --plain > "$LAB/scan_broken.txt" 2>&1
check 0 $? "malformed config does not crash"
contains "malformed JSON" "$(cat "$LAB/scan_broken.txt")" "parse error reported"

echo "[7] live handshake: honest tools"
$CLI tools --from "node $ROOT/test/fixture_stdio_server.mjs" --plain > "$LAB/tools_ok.txt" 2>&1
check 0 $? "honest toolset exits 0"
contains "3 tool(s)" "$(cat "$LAB/tools_ok.txt")" "three tools collected"

echo "[8] live handshake: poisoned tools"
$CLI tools --from "node $ROOT/test/fixture_stdio_server.mjs --poison" --plain > "$LAB/tools_poison.txt" 2>&1
check 10 $? "poisoned toolset exits 10"
contains "instruction override directive" "$(cat "$LAB/tools_poison.txt")" "override caught"
contains "invisible characters" "$(cat "$LAB/tools_poison.txt")" "unicode smuggling caught"
contains "known callback host" "$(cat "$LAB/tools_poison.txt")" "callback host caught"
$CLI tools --from "node $ROOT/test/fixture_stdio_server.mjs --added" --plain > "$LAB/tools_squat.txt" 2>&1
contains "mimics a privileged name" "$(cat "$LAB/tools_squat.txt")" "typo-squat mimicry caught"

echo "[9] rug-pull detector"
$CLI baseline --from "node $ROOT/test/fixture_stdio_server.mjs" --out "$LAB/base.json" >/dev/null
$CLI check --baseline "$LAB/base.json" --from "node $ROOT/test/fixture_stdio_server.mjs" --plain > "$LAB/chk_ok.txt" 2>&1
check 0 $? "check honest exits 0"
$CLI check --baseline "$LAB/base.json" --from "node $ROOT/test/fixture_stdio_server.mjs --poison" --plain > "$LAB/chk_bad.txt" 2>&1
check 3 $? "check poisoned exits 3 (rug pull)"
contains "RUG PULL" "$(cat "$LAB/chk_bad.txt")" "rug pull rendered"
contains "system_diagnostics" "$(cat "$LAB/chk_bad.txt")" "changed tool named"

echo "[10] paths command"
$CLI paths --home "$LAB/d1" --cwd "$LAB/d1" --plain > "$LAB/paths.txt" 2>&1
contains ".cursor/mcp.json" "$(cat "$LAB/paths.txt")" "candidate list includes cursor"

echo "[11] markdown report"
$CLI scan --home "$LAB/d1" --cwd "$LAB/d1" --md "$LAB/report.md" >/dev/null 2>&1
contains "# familiar audit" "$(cat "$LAB/report.md")" "markdown header present"

echo "[12] host-path hygiene (persona gate)"
ALL_OUT=$(cat "$LAB"/scan_*.txt "$LAB"/tools_*.txt "$LAB"/chk_*.txt "$LAB"/report.json 2>/dev/null)
absent "/home/z" "$ALL_OUT" "no /home/z in any output"

echo ""
echo "══ e2e result: $PASS passed · $FAIL failed ══"
[ "$FAIL" = "0" ] || exit 1
exit 0
