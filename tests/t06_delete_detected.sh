#!/usr/bin/env bash
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'kill $(cat "$HOME/.warden/warden.pid" 2>/dev/null) 2>/dev/null || true; rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/watched"
echo "delete me" > "$TEST_DIR/watched/target.txt"
./warden add "$TEST_DIR/watched" > /dev/null 2>&1
./warden baseline > /dev/null 2>&1

./warden watch > /dev/null 2>&1 &
WATCH_PID=$!
sleep 1

rm -f "$TEST_DIR/watched/target.txt"
sleep 1

kill -SIGINT "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true

LOG_FILE="$HOME/.warden/events.log"
if [ -f "$LOG_FILE" ] && grep -q "DELETED" "$LOG_FILE" && grep -q "target.txt" "$LOG_FILE"; then
    echo "[PASS] T06: File deletion detected and logged"
    exit 0
else
    echo "[FAIL] T06: File deletion event not recorded"
    exit 1
fi
