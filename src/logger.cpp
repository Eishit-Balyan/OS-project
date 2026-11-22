/**
 * ============================================================================
 * SentinelFS - Logging and Alerting Implementation
 * Module Purpose: Real TSV event persistence to events.log, live terminal
 *                 alerting, and syslog dispatch for CRITICAL events.
 * Owner: Ayaansh
 * ============================================================================
 */

#include "logger.h"
#include "config.h"
#include "ui.h"

#include <iostream>
#include <fstream>
#include <pthread.h>
#include <syslog.h>
#include <unistd.h>

static pthread_mutex_t g_logger_mutex = PTHREAD_MUTEX_INITIALIZER;

std::string logger_get_default_path() {
    return config_get_default_dir() + "/events.log";
}

void log_event(const ClassifiedEvent& event) {
    pthread_mutex_lock(&g_logger_mutex);

    // 1. Terminal Alert via UI (only when live dashboard is not active to prevent screen tearing)
    if (!ui_is_dashboard_active()) {
        ui_print_alert_line(event);
    }

    // 2. Append TSV to events.log
    config_ensure_dir_exists();
    std::string log_file = logger_get_default_path();

    std::ofstream out(log_file, std::ios::app);
    if (out.is_open()) {
        out << classified_event_to_line(event) << "\n";
        out.flush();
    } else {
        std::cerr << ui_error_mark() << " Failed to write to event log "
                  << log_file << std::endl;
    }

    // 3. Syslog dispatch on CRITICAL security events
    if (event.severity == CRITICAL) {
        openlog("sentinelfs", LOG_PID | LOG_CONS, LOG_DAEMON);
        syslog(LOG_ALERT, "[CRITICAL] %s: %s (%s)",
               event_type_to_string(event.ev.type).c_str(),
               event.ev.path.c_str(),
               event.detail.c_str());
        closelog();
    }

    pthread_mutex_unlock(&g_logger_mutex);
}
