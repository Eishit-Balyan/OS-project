#!/usr/bin/env bash
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'kill $(cat "$HOME/.sentinelfs/sentinelfs.pid" 2>/dev/null) 2>/dev/null || true; rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/watched"
for i in $(seq 1 20); do
    echo "initial $i" > "$TEST_DIR/watched/f_$i.txt"
done

./sentinelfs add "$TEST_DIR/watched" > /dev/null 2>&1
./sentinelfs baseline > /dev/null 2>&1

./sentinelfs watch > /dev/null 2>&1 &
WATCH_PID=$!
sleep 1

for i in $(seq 1 20); do
    echo "rapid edit $i" >> "$TEST_DIR/watched/f_$i.txt"
done
sleep 2

kill -SIGINT "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true

LOG_FILE="$HOME/.sentinelfs/events.log"
CAPTURED=$(grep -c "MODIFIED" "$LOG_FILE" 2>/dev/null || echo 0)

if [ "$CAPTURED" -ge 20 ]; then
    echo "[PASS] T09: Rapid modifications all captured ($CAPTURED events)"
    exit 0
else
    echo "[FAIL] T09: Missed rapid modifications (got $CAPTURED, expected >=20)"
    exit 1
fi
