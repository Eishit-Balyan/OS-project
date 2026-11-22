#!/usr/bin/env bash
set -u

echo "========================================================"
echo "      Warden Integration Test Suite Runner         "
echo "========================================================"

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/.." && pwd)"

cd "$ROOT_DIR"

if [ ! -f "./warden" ]; then
    echo "Executable './warden' not found. Building with make..."
    make
fi

chmod +x "$TEST_DIR"/t*.sh 2>/dev/null || true

TEST_SCRIPTS=(
    "tests/t01_add_valid_dir.sh"
    "tests/t02_add_nonexistent_dir.sh"
    "tests/t03_baseline_created.sh"
    "tests/t04_modify_detected.sh"
    "tests/t05_create_detected.sh"
    "tests/t06_delete_detected.sh"
    "tests/t07_rename_moved.sh"
    "tests/t08_unchanged_no_violation.sh"
    "tests/t09_rapid_modifications.sh"
    "tests/t10_queue_stress_drain.sh"
    "tests/t11_queue_concurrency.sh"
    "tests/t12_unreadable_file.sh"
    "tests/t13_baseline_restart.sh"
    "tests/t14_burst_alert.sh"
    "tests/t15_sigint_clean_stop.sh"
    "tests/t16_events_report.sh"
    "tests/t17_web_api.sh"
)

TOTAL=0
PASSED=0
FAILED=0
RESULTS=()

for script in "${TEST_SCRIPTS[@]}"; do
    NAME=$(basename "$script" .sh)
    TOTAL=$((TOTAL + 1))
    
    if bash "$script"; then
        PASSED=$((PASSED + 1))
        RESULTS+=("PASS | $NAME")
    else
        FAILED=$((FAILED + 1))
        RESULTS+=("FAIL | $NAME")
    fi
done

echo ""
echo "================== Test Results Summary =================="
printf "%-8s | %s\n" "STATUS" "TEST CASE"
echo "----------------------------------------------------------"
for res in "${RESULTS[@]}"; do
    STATUS=$(echo "$res" | awk -F' \\| ' '{print $1}')
    TNAME=$(echo "$res" | awk -F' \\| ' '{print $2}')
    if [ "$STATUS" = "PASS" ]; then
        printf "\033[32m%-8s\033[0m | %s\n" "$STATUS" "$TNAME"
    else
        printf "\033[31m%-8s\033[0m | %s\n" "$STATUS" "$TNAME"
    fi
done
echo "=========================================================="
echo "Total: $TOTAL | Passed: $PASSED | Failed: $FAILED"

if [ "$FAILED" -eq 0 ]; then
    echo "ALL TESTS PASSED!"
    exit 0
else
    echo "SOME TESTS FAILED."
    exit 1
fi
