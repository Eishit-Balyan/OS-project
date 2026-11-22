#ifndef WARDEN_LOGGER_H
#define WARDEN_LOGGER_H

/**
 * ============================================================================
 * Warden - Logging and Alerting Module
 * Module Purpose: Mutex-protected append-only logging to ~/.warden/events.log
 *                 using the 6-field TSV format, visual ANSI terminal alerts,
 *                 and syslog dispatch on CRITICAL severity events.
 * Owner: Aviral
 * ============================================================================
 */

#include "common.h"
#include <string>

// Returns default event log path (~/.warden/events.log)
std::string logger_get_default_path();

// Writes a classified event to events.log under mutex lock, triggers UI alert,
// and notifies syslog(LOG_ALERT) if severity is CRITICAL
void log_event(const ClassifiedEvent& event);

#endif // WARDEN_LOGGER_H
