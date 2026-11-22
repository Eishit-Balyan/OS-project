#!/usr/bin/env bash
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'kill $(cat "$HOME/.warden/warden.pid" 2>/dev/null) 2>/dev/null || true; rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/watched"
./warden add "$TEST_DIR/watched" > /dev/null 2>&1
./warden baseline > /dev/null 2>&1

./warden watch > /dev/null 2>&1 &
WATCH_PID=$!
sleep 1

touch "$TEST_DIR/watched/new_file.txt"
sleep 1

kill -SIGINT "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true

LOG_FILE="$HOME/.warden/events.log"
if [ -f "$LOG_FILE" ] && grep -q "CREATED" "$LOG_FILE" && grep -q "new_file.txt" "$LOG_FILE"; then
    echo "[PASS] T05: New file creation detected and logged"
    exit 0
else
    echo "[FAIL] T05: File creation event not recorded"
    exit 1
fi
