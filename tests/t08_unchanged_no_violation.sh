#!/usr/bin/env bash
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/watched"
echo "clean state" > "$TEST_DIR/watched/clean.txt"
./sentinelfs add "$TEST_DIR/watched" > /dev/null 2>&1
./sentinelfs baseline > /dev/null 2>&1

if ./sentinelfs verify > /dev/null 2>&1; then
    echo "[PASS] T08: Unchanged files report clean verification"
    exit 0
else
    echo "[FAIL] T08: False alarm on unchanged files"
    exit 1
fi
