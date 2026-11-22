#ifndef WARDEN_ANALYZER_H
#define WARDEN_ANALYZER_H

/**
 * ============================================================================
 * Warden - Behavioral Anomaly Analyzer Module
 * Module Purpose: Real sliding-window burst detection for rapid modification
 *                 bursts (ransomware/mass-tamper activity), with repeat alert
 *                 suppression within the window.
 * Owner: Eishit
 * ============================================================================
 */

#include "common.h"

// THREAD-SAFETY: Mutex-protected sliding window deque of modification timestamps.

// Records an incoming event and raises ONE CRITICAL burst alert when threshold is exceeded
void analyzer_record(const ClassifiedEvent& event, const Config& config);

// Resets internal burst analyzer state
void analyzer_reset();

#endif // WARDEN_ANALYZER_H
