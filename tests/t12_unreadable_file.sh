#!/usr/bin/env bash
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'chmod 644 "$TEST_DIR/watched/unreadable.txt" 2>/dev/null || true; kill $(cat "$HOME/.sentinelfs/sentinelfs.pid" 2>/dev/null) 2>/dev/null || true; rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/watched"
echo "secret" > "$TEST_DIR/watched/unreadable.txt"
chmod 000 "$TEST_DIR/watched/unreadable.txt"

./sentinelfs add "$TEST_DIR/watched" > /dev/null 2>&1
# Baseline creation should record error and continue without crashing
./sentinelfs baseline > /dev/null 2>&1

./sentinelfs watch > /dev/null 2>&1 &
WATCH_PID=$!
sleep 1

touch "$TEST_DIR/watched/normal.txt"
sleep 1

kill -SIGINT "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true

LOG_FILE="$HOME/.sentinelfs/events.log"
if [ -f "$LOG_FILE" ] && grep -q "normal.txt" "$LOG_FILE"; then
    echo "[PASS] T12: Unreadable file did not crash monitoring engine"
    exit 0
else
    echo "[FAIL] T12: Unreadable file stopped monitoring"
    exit 1
fi
