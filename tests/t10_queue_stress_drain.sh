#!/usr/bin/env bash
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'kill $(cat "$HOME/.sentinelfs/sentinelfs.pid" 2>/dev/null) 2>/dev/null || true; rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/watched"
./sentinelfs add "$TEST_DIR/watched" > /dev/null 2>&1
./sentinelfs baseline > /dev/null 2>&1

./sentinelfs watch > /dev/null 2>&1 &
WATCH_PID=$!
sleep 1

# Generate high event volume
for i in $(seq 1 500); do
    echo "val" >> "$TEST_DIR/watched/stream_$i.txt"
done
sleep 3

kill -SIGINT "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true

LOG_FILE="$HOME/.sentinelfs/events.log"
COUNT=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)

if [ "$COUNT" -gt 0 ]; then
    echo "[PASS] T10: Queue handled high event volume without crash ($COUNT events processed)"
    exit 0
else
    echo "[FAIL] T10: High event volume caused failure"
    exit 1
fi
