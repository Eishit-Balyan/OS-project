#!/usr/bin/env bash
# ==============================================================================
# SentinelFS - Live Tamper & Attack Simulation Script
# Purpose: Simulates realistic ransomware / unauthorized tampering behavior
#          for live demonstrations: mass modification burst, permission changes,
#          file deletions, and renames.
# ==============================================================================

if [ -z "$1" ]; then
    echo "Usage: $0 <target_directory>"
    exit 1
fi

TARGET_DIR="$1"
mkdir -p "$TARGET_DIR"

echo "=== [Phase 1] Staging Sample Files in $TARGET_DIR ==="
for i in $(seq 1 30); do
    echo "Important document payload #$i" > "$TARGET_DIR/document_$i.dat"
done
sleep 1

echo "=== [Phase 2] Simulating Ransomware Mass Modification Burst ==="
for i in $(seq 1 25); do
    echo "ENCRYPTED_DATA_AES_GCM_$i" >> "$TARGET_DIR/document_$i.dat"
done
echo ">>> Mass rewrite finished (should trigger SentinelFS BURST ALERT)."
sleep 2

echo "=== [Phase 3] Simulating Permission Tampering (Backdoor Dropper) ==="
chmod 0777 "$TARGET_DIR/document_1.dat" 2>/dev/null || true
chmod 0600 "$TARGET_DIR/document_2.dat" 2>/dev/null || true
sleep 1

echo "=== [Phase 4] Simulating Data Destruction & Renaming ==="
rm -f "$TARGET_DIR/document_28.dat" "$TARGET_DIR/document_29.dat" "$TARGET_DIR/document_30.dat"
mv "$TARGET_DIR/document_5.dat" "$TARGET_DIR/document_5.dat.locked"
sleep 1

echo "=== Attack Simulation Completed Successfully ==="
echo "Inspect events using: ./sentinelfs events --tail --limit 20"
echo "Inspect report using: ./sentinelfs report"
