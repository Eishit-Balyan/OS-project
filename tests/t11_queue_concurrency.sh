#!/usr/bin/env bash
if [ ! -f "./build/test_queue" ]; then
    make test-queue > /dev/null 2>&1 || true
fi

if [ -f "./build/test_queue" ] && ./build/test_queue; then
    echo "[PASS] T11: Concurrent queue stress test passed"
    exit 0
else
    echo "[FAIL] T11: Concurrent queue test failed"
    exit 1
fi
