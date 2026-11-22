#!/usr/bin/env bash
set -e
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$TEST_DIR/valid_dir"
./warden add "$TEST_DIR/valid_dir" > /dev/null 2>&1

if ./warden list | grep -q "$TEST_DIR/valid_dir"; then
    echo "[PASS] T01: Add valid directory"
    exit 0
else
    echo "[FAIL] T01: Add valid directory failed"
    exit 1
fi
