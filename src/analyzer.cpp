/**
 * ============================================================================
 * Warden - Behavioral Anomaly Analyzer Implementation
 * Module Purpose: Real sliding-window timestamp tracking for burst detection.
 *                 Triggers high-priority CRITICAL alerts on rapid mass tamper.
 * Owner: Eishit
 * ============================================================================
 */

#include "analyzer.h"
#include "logger.h"
#include "ui.h"

#include <iostream>
#include <deque>
#include <pthread.h>

static pthread_mutex_t g_analyzer_mutex = PTHREAD_MUTEX_INITIALIZER;
static std::deque<time_t> g_mod_timestamps;
static time_t g_last_burst_alert = 0;

void analyzer_reset() {
    pthread_mutex_lock(&g_analyzer_mutex);
    g_mod_timestamps.clear();
    g_last_burst_alert = 0;
    pthread_mutex_unlock(&g_analyzer_mutex);
}

void analyzer_record(const ClassifiedEvent& event, const Config& config) {
    if (event.ev.type != MODIFIED) {
        return;
    }

    pthread_mutex_lock(&g_analyzer_mutex);

    time_t now = event.ev.timestamp;
    if (now == 0) now = time(nullptr);

    // Evict timestamps older than burst window
    int window = (config.burst_window_sec > 0) ? config.burst_window_sec : 10;
    time_t window_start = now - window;
    while (!g_mod_timestamps.empty() && g_mod_timestamps.front() < window_start) {
        g_mod_timestamps.pop_front();
    }

    g_mod_timestamps.push_back(now);

    int threshold = (config.burst_threshold > 0) ? config.burst_threshold : 20;

    if (g_mod_timestamps.size() >= static_cast<size_t>(threshold)) {
        // Only trigger one alert per burst window to prevent log flooding
        if (now >= g_last_burst_alert + window) {
            g_last_burst_alert = now;

            ClassifiedEvent alert_ev;
            alert_ev.ev.timestamp = now;
            alert_ev.severity = CRITICAL;
            alert_ev.ev.type = MODIFIED;
            alert_ev.ev.path = "[BURST ALERT: " + std::to_string(g_mod_timestamps.size()) +
                               " modifications in " + std::to_string(window) + "s]";
            alert_ev.ev.old_path = "-";
            alert_ev.detail = "possible mass-tamper / ransomware-like burst detected (threshold=" +
                              std::to_string(threshold) + ")";

            // Unlock before calling log_event to prevent lock inversion
            pthread_mutex_unlock(&g_analyzer_mutex);
            log_event(alert_ev);
            ui_stats_record_event(alert_ev, 0);
            return;
        }
    }

    pthread_mutex_unlock(&g_analyzer_mutex);
}
