#!/usr/bin/env bash
# End-to-end smoke test: starts the deliberately weak fixture API, runs Vörðr,
# and asserts that the expected findings and report artefacts exist.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${VORDR_TEST_PORT:-8099}"
OUT="$(mktemp -d)"
FIXTURE_LOG="$(mktemp)"

cleanup() {
  [[ -n "${FIXTURE_PID:-}" ]] && kill "$FIXTURE_PID" 2>/dev/null || true
  rm -rf "$OUT" "$FIXTURE_LOG"
}
trap cleanup EXIT

cd "$ROOT"

# Prefer the interpreter that already has the dependencies (a venv, usually);
# fall back to uv so the test works in a bare checkout too.
if python3 -c "import httpx, openpyxl, yaml" 2>/dev/null; then
  VORDR=(python3 vordr.py)
elif command -v uv >/dev/null 2>&1; then
  VORDR=(uv run vordr.py)
else
  echo "FAIL: dependencies not installed and uv is unavailable" >&2
  echo "      run: python3 -m pip install -r requirements.txt" >&2
  exit 1
fi

python3 tests/fixture_api.py "$PORT" >"$FIXTURE_LOG" 2>&1 &
FIXTURE_PID=$!

for _ in $(seq 1 40); do
  if curl -sf -o /dev/null "http://127.0.0.1:${PORT}/health"; then break; fi
  sleep 0.1
done

"${VORDR[@]}" "http://127.0.0.1:${PORT}" \
  -e examples/endpoints.csv \
  --i-have-authorization \
  --allow-private \
  --param id=1 \
  --no-color \
  --author "smoke-test" \
  --out "$OUT" >"$OUT/stdout.txt"

fail=0
expect() {
  if ! grep -q -- "$1" "$2"; then
    echo "FAIL: expected '$1' in $2" >&2
    fail=1
  fi
}

expect "auth enforced" "$OUT/stdout.txt"
expect "Anonymous access returned data" "$OUT/stdout.txt"
expect "Authorization bypass via path normalization" "$OUT/stdout.txt"
expect "CORS reflects arbitrary Origin with credentials" "$OUT/stdout.txt"
expect "Sensitive field names" "$OUT/stdout.txt"
expect "write method POST" "$OUT/stdout.txt"

for artefact in report.md report.xlsx findings.json evidence.jsonl; do
  [[ -s "$OUT/$artefact" ]] || { echo "FAIL: missing $artefact" >&2; fail=1; }
done

python3 - "$OUT/findings.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
titles = {f["title"] for f in data["findings"]}
required = {
    "Anonymous access returned data (HTTP 200)",
    "Authorization bypass via path normalization",
    "CORS reflects an arbitrary Origin with credentials",
}
missing = required - titles
assert not missing, f"missing findings: {missing}"
assert data["summary"]["critical"] >= 1, "expected at least one critical finding"
assert all(f["severity"] in {"critical", "high", "medium", "low", "info"} for f in data["findings"])
print(f"findings: {len(data['findings'])}, critical: {data['summary']['critical']}, "
      f"requests: {data['requests_sent']}")
PY

# --url: manual endpoints, no inventory file, with a placeholder
"${VORDR[@]}" "http://127.0.0.1:${PORT}" \
  --i-have-authorization --allow-private --no-color \
  -u /v1/users -u "/v1/orders/{id}" --param id=1 \
  --out "$OUT/url" >"$OUT/url.txt"
expect "manual (-u/--url)" "$OUT/url.txt"
expect "GET /v1/orders/1" "$OUT/url.txt"
expect "auth enforced" "$OUT/url.txt"

# stdin: pasted list, one endpoint per line, method prefixes allowed
printf 'GET /v1/users\n/v1/products\n# comment\n\nPOST /v1/users\n' | \
  "${VORDR[@]}" "http://127.0.0.1:${PORT}" \
  --i-have-authorization --allow-private --no-color \
  --out "$OUT/stdin" >"$OUT/stdin.txt"
expect "sheet 'stdin'" "$OUT/stdin.txt"
expect "GET /v1/products" "$OUT/stdin.txt"
expect "write method POST" "$OUT/stdin.txt"

if [[ "$fail" -ne 0 ]]; then
  echo "SMOKE TEST FAILED" >&2
  exit 1
fi
echo "SMOKE TEST PASSED"
