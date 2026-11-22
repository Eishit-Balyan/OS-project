#!/usr/bin/env bash
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'kill $(cat "$HOME/.warden/warden.pid" 2>/dev/null) 2>/dev/null || true; rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/watched"
echo "data" > "$TEST_DIR/watched/old_name.txt"
./warden add "$TEST_DIR/watched" > /dev/null 2>&1
./warden baseline > /dev/null 2>&1

./warden watch > /dev/null 2>&1 &
WATCH_PID=$!
sleep 1

mv "$TEST_DIR/watched/old_name.txt" "$TEST_DIR/watched/new_name.txt"
sleep 1

kill -SIGINT "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true

LOG_FILE="$HOME/.warden/events.log"
if [ -f "$LOG_FILE" ] && grep -q "MOVED" "$LOG_FILE" && grep -q "old_name.txt" "$LOG_FILE"; then
    echo "[PASS] T07: Rename detected and paired as MOVED event"
    exit 0
else
    echo "[FAIL] T07: File rename MOVED event not recorded"
    exit 1
fi
