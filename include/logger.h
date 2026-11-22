#ifndef SENTINELFS_LOGGER_H
#define SENTINELFS_LOGGER_H

/**
 * ============================================================================
 * SentinelFS - Logging and Alerting Module
 * Module Purpose: Mutex-protected append-only logging to ~/.sentinelfs/events.log
 *                 using the 6-field TSV format, visual ANSI terminal alerts,
 *                 and syslog dispatch on CRITICAL severity events.
 * Owner: Ayaansh
 * ============================================================================
 */

#include "common.h"
#include <string>

// Returns default event log path (~/.sentinelfs/events.log)
std::string logger_get_default_path();

// Writes a classified event to events.log under mutex lock, triggers UI alert,
// and notifies syslog(LOG_ALERT) if severity is CRITICAL
void log_event(const ClassifiedEvent& event);

#endif // SENTINELFS_LOGGER_H
