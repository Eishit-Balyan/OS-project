#!/usr/bin/env bash
export HOME=$(mktemp -d)
trap 'rm -rf "$HOME"' EXIT

if ./sentinelfs add /path/to/definitely_non_existent_directory_99999 > /dev/null 2>&1; then
    echo "[FAIL] T02: Add nonexistent directory should have failed"
    exit 1
else
    echo "[PASS] T02: Add nonexistent directory correctly rejected with error"
    exit 0
fi
