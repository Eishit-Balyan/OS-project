#!/usr/bin/env bash
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
PID_FILE="$HOME/.sentinelfs/sentinelfs.pid"
trap 'kill $(cat "$PID_FILE" 2>/dev/null) 2>/dev/null || true; rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/watched"
echo "data" > "$TEST_DIR/watched/f.txt"
./sentinelfs add "$TEST_DIR/watched" > /dev/null 2>&1
./sentinelfs baseline > /dev/null 2>&1

./sentinelfs watch > /dev/null 2>&1 &
WATCH_PID=$!
sleep 1

if [ ! -f "$PID_FILE" ]; then
    echo "[FAIL] T15: PID file was not created on startup"
    exit 1
fi

DAEMON_PID=$(cat "$PID_FILE")
kill -SIGINT "$DAEMON_PID"
wait "$WATCH_PID" 2>/dev/null || true

if [ -f "$PID_FILE" ]; then
    echo "[FAIL] T15: PID file was not cleaned up after SIGINT"
    exit 1
fi

# Confirm no lingering processes
if kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "[FAIL] T15: Process still running after SIGINT"
    exit 1
fi

echo "[PASS] T15: SIGINT stopped watch cleanly, removed pidfile with no zombie threads"
exit 0
