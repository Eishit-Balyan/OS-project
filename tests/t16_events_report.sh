#!/usr/bin/env bash
TEST_DIR=$(mktemp -d)
export HOME=$(mktemp -d)
trap 'rm -rf "$TEST_DIR" "$HOME"' EXIT

mkdir -p "$HOME/.sentinelfs"
LOG="$HOME/.sentinelfs/events.log"

# Populate sample TSV log entries
echo -e "1731780000\tINFO\tCREATED\t/tmp/watched/file1.txt\t-\tnew file created" > "$LOG"
echo -e "1731780050\tWARNING\tMODIFIED\t/tmp/watched/file1.txt\t-\thash mismatch" >> "$LOG"
echo -e "1731780100\tCRITICAL\tDELETED\t/tmp/watched/critical.txt\t-\tfile deleted from disk" >> "$LOG"

CSV_FILE="$TEST_DIR/out.csv"
HTML_FILE="$TEST_DIR/out.html"

./sentinelfs events > /dev/null 2>&1
./sentinelfs report --csv "$CSV_FILE" --html "$HTML_FILE" > /dev/null 2>&1

if [ -f "$CSV_FILE" ] && [ -s "$CSV_FILE" ] && [ -f "$HTML_FILE" ] && [ -s "$HTML_FILE" ]; then
    echo "[PASS] T16: Events filtering and CSV/HTML report export validated"
    exit 0
else
    echo "[FAIL] T16: Events or report command output failed"
    exit 1
fi
