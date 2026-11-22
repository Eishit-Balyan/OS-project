#!/usr/bin/env bash
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/watched"
echo "persistent" > "$TEST_DIR/watched/p.txt"
./sentinelfs add "$TEST_DIR/watched" > /dev/null 2>&1
./sentinelfs baseline > /dev/null 2>&1

DB="$HOME/.sentinelfs/baseline.db"
HASH1=$(sha256sum "$DB" | awk '{print $1}')
SIDECAR_HASH=$(cat "$HOME/.sentinelfs/baseline.db.sha256" | tr -d ' \r\n')

if [ "$HASH1" = "$SIDECAR_HASH" ] && ./sentinelfs verify > /dev/null 2>&1; then
    echo "[PASS] T13: Baseline survives restart with valid cryptographic sidecar"
    exit 0
else
    echo "[FAIL] T13: Baseline verification or sidecar check failed"
    exit 1
fi
