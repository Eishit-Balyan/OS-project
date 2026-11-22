#!/usr/bin/env bash
set -e

# ==============================================================================
# Warden Integration Test: T17 - Forensic Web Ledger API & SSE Streaming
# ==============================================================================

TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$HOME/.warden/warden.pid"

WATCH_PID=""
WEB_PID=""
STREAM_PID=""

cleanup() {
    if [ -n "$STREAM_PID" ]; then kill "$STREAM_PID" 2>/dev/null || true; fi
    if [ -n "$WEB_PID" ]; then kill -SIGINT "$WEB_PID" 2>/dev/null || true; fi
    if [ -n "$WATCH_PID" ]; then kill -SIGINT "$WATCH_PID" 2>/dev/null || true; fi
    wait 2>/dev/null || true
    rm -rf "$TEST_DIR" "$HOME"
}
trap cleanup EXIT

# 1. Select a free ephemeral port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')

# 2. Setup protected directory and baseline
mkdir -p "$TEST_DIR/watched"
echo "initial_seed_content" > "$TEST_DIR/watched/seed.txt"
./warden add "$TEST_DIR/watched" > /dev/null 2>&1
./warden baseline > /dev/null 2>&1

# 3. Start watch in background
./warden watch > /dev/null 2>&1 &
WATCH_PID=$!
sleep 1.2

if [ ! -f "$PID_FILE" ]; then
    echo "[FAIL] T17: Daemon PID file was not created by watch"
    exit 1
fi

# 4. Start web server in background
./warden web --port "$PORT" --web-dir "$ROOT_DIR/web" > /dev/null 2>&1 &
WEB_PID=$!
sleep 1.2

# 5. Check GET /api/status returns valid JSON, reports running daemon & correct port
curl -s "http://127.0.0.1:$PORT/api/status" > "$TEST_DIR/status.json"
if ! python3 -m json.tool "$TEST_DIR/status.json" > /dev/null 2>&1; then
    echo "[FAIL] T17: /api/status returned invalid JSON"
    exit 1
fi

python3 -c "
import json, sys
with open('$TEST_DIR/status.json') as f:
    d = json.load(f)
assert d['daemon']['running'] is True, 'daemon not running'
assert d['server']['port'] == $PORT, 'port mismatch'
assert d['baseline']['seal'] == 'sealed', 'seal not sealed'
" || { echo "[FAIL] T17: Status fields validation failed"; exit 1; }

# 6. Append an event, verify in GET /api/events
echo "test1_payload" > "$TEST_DIR/watched/test1.txt"
sleep 1.2

curl -s "http://127.0.0.1:$PORT/api/events?limit=10" > "$TEST_DIR/events.json"
python3 -m json.tool "$TEST_DIR/events.json" > /dev/null

python3 -c "
import json
with open('$TEST_DIR/events.json') as f:
    evs = json.load(f)
assert any('test1.txt' in ev['path'] for ev in evs), 'test1.txt event not found in /api/events'
" || { echo "[FAIL] T17: Appended event not listed in /api/events"; exit 1; }

# 7. Test SSE stream (GET /api/stream)
curl -N -s "http://127.0.0.1:$PORT/api/stream" > "$TEST_DIR/stream.out" 2>/dev/null &
STREAM_PID=$!
sleep 0.5

echo "stream_entry_payload" > "$TEST_DIR/watched/stream_ev.txt"
sleep 1.2
kill "$STREAM_PID" 2>/dev/null || true
STREAM_PID=""

if ! grep -q "event: entry" "$TEST_DIR/stream.out"; then
    echo "[FAIL] T17: /api/stream did not output SSE 'event: entry' frame"
    exit 1
fi

if ! grep -q "stream_ev.txt" "$TEST_DIR/stream.out"; then
    echo "[FAIL] T17: SSE stream did not contain stream_ev.txt event data"
    exit 1
fi

# 8. Test file tampering & drift
echo "tampered" >> "$TEST_DIR/watched/seed.txt"
sleep 1.2

curl -s "http://127.0.0.1:$PORT/api/status" > "$TEST_DIR/status_drift.json"
python3 -c "
import json
with open('$TEST_DIR/status_drift.json') as f:
    d = json.load(f)
assert d['baseline']['drift_count'] >= 1, 'drift_count not detected'
" || { echo "[FAIL] T17: Drift count not reflected in /api/status"; exit 1; }

# Tamper baseline directly
echo "tamper_database_content" >> "$HOME/.warden/baseline.db"
curl -s "http://127.0.0.1:$PORT/api/status" > "$TEST_DIR/status_tampered.json"
python3 -c "
import json
with open('$TEST_DIR/status_tampered.json') as f:
    d = json.load(f)
assert d['baseline']['seal'] == 'tampered', 'seal not reported as tampered'
" || { echo "[FAIL] T17: Baseline tampering not detected"; exit 1; }

# 9. Path traversal protection check
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/../../etc/passwd")
if [ "$HTTP_CODE" = "200" ]; then
    echo "[FAIL] T17: Path traversal returned HTTP 200 instead of 403/404"
    exit 1
fi

# 10. Attacker-controlled file naming & JSON escaping check
touch "$TEST_DIR/watched/x\"<b>y</b>.txt"
sleep 1.2
curl -s "http://127.0.0.1:$PORT/api/events?limit=20" > "$TEST_DIR/events_escape.json"
if ! python3 -m json.tool "$TEST_DIR/events_escape.json" > /dev/null 2>&1; then
    echo "[FAIL] T17: Special character filename broke JSON escaping in /api/events"
    exit 1
fi

# 11. Clean shutdown of both processes
kill -SIGINT "$WEB_PID"
kill -SIGINT "$WATCH_PID"
wait "$WEB_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true
WEB_PID=""
WATCH_PID=""

# Check PID file removed
if [ -f "$PID_FILE" ]; then
    echo "[FAIL] T17: PID file remained after clean SIGINT"
    exit 1
fi

echo "[PASS] T17: Web server decoupled API, SSE stream, tamper detection, traversal rejection and clean shutdown"
exit 0
