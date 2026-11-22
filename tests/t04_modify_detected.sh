#!/usr/bin/env bash
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'kill $(cat "$HOME/.sentinelfs/sentinelfs.pid" 2>/dev/null) 2>/dev/null || true; rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/watched"
echo "original version" > "$TEST_DIR/watched/file.txt"
./sentinelfs add "$TEST_DIR/watched" > /dev/null 2>&1
./sentinelfs baseline > /dev/null 2>&1

./sentinelfs watch > /dev/null 2>&1 &
WATCH_PID=$!
sleep 1

echo "tampered content" >> "$TEST_DIR/watched/file.txt"
sleep 1

kill -SIGINT "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true

LOG_FILE="$HOME/.sentinelfs/events.log"
if [ -f "$LOG_FILE" ] && grep -q "MODIFIED" "$LOG_FILE" && grep -q "file.txt" "$LOG_FILE"; then
    echo "[PASS] T04: File modification correctly detected and logged"
    exit 0
else
    echo "[FAIL] T04: File modification not captured in events.log"
    exit 1
fi
