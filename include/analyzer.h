#ifndef SENTINELFS_ANALYZER_H
#define SENTINELFS_ANALYZER_H

/**
 * ============================================================================
 * SentinelFS - Behavioral Anomaly Analyzer Module
 * Module Purpose: Real sliding-window burst detection for rapid modification
 *                 bursts (ransomware/mass-tamper activity), with repeat alert
 *                 suppression within the window.
 * Owner: Arjun & Ayaansh
 * ============================================================================
 */

#include "common.h"

// THREAD-SAFETY: Mutex-protected sliding window deque of modification timestamps.

// Records an incoming event and raises ONE CRITICAL burst alert when threshold is exceeded
void analyzer_record(const ClassifiedEvent& event, const Config& config);

// Resets internal burst analyzer state
void analyzer_reset();

#endif // SENTINELFS_ANALYZER_H
