#!/usr/bin/env bash
set -e
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/data"
echo "sample content" > "$TEST_DIR/data/sample.txt"
./sentinelfs add "$TEST_DIR/data" > /dev/null 2>&1
./sentinelfs baseline > /dev/null 2>&1

DB_FILE="$HOME/.sentinelfs/baseline.db"
SIDECAR_FILE="$HOME/.sentinelfs/baseline.db.sha256"

if [ -f "$DB_FILE" ] && [ -s "$DB_FILE" ] && [ -f "$SIDECAR_FILE" ] && [ -s "$SIDECAR_FILE" ]; then
    echo "[PASS] T03: Baseline and sidecar SHA-256 created successfully"
    exit 0
else
    echo "[FAIL] T03: Baseline creation missing DB or sidecar file"
    exit 1
fi
