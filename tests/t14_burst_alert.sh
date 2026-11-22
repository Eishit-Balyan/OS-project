#!/usr/bin/env bash
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'kill $(cat "$HOME/.sentinelfs/sentinelfs.pid" 2>/dev/null) 2>/dev/null || true; rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/watched"
for i in $(seq 1 15); do
    echo "init $i" > "$TEST_DIR/watched/burst_$i.txt"
done

./sentinelfs add "$TEST_DIR/watched" > /dev/null 2>&1

# Set burst threshold lower for quick testing
sed -i 's/burst_threshold=.*/burst_threshold=5/' "$HOME/.sentinelfs/config" 2>/dev/null || true
echo "burst_threshold=5" >> "$HOME/.sentinelfs/config"

./sentinelfs baseline > /dev/null 2>&1

./sentinelfs watch > /dev/null 2>&1 &
WATCH_PID=$!
sleep 1

# Trigger burst of edits
for i in $(seq 1 10); do
    echo "burst change $i" >> "$TEST_DIR/watched/burst_$i.txt"
done
sleep 2

kill -SIGINT "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true

LOG_FILE="$HOME/.sentinelfs/events.log"
if [ -f "$LOG_FILE" ] && (grep -q "BURST" "$LOG_FILE" || grep -q "mass-tamper" "$LOG_FILE"); then
    echo "[PASS] T14: Burst modification threshold triggered CRITICAL burst anomaly alert"
    exit 0
else
    echo "[FAIL] T14: Burst alert not detected"
    exit 1
fi
