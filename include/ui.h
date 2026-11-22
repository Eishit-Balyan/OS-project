#ifndef SENTINELFS_UI_H
#define SENTINELFS_UI_H

/**
 * ============================================================================
 * SentinelFS - Modern Terminal UI & Formatting Module
 * Module Purpose: Terminal capability detection, 256-color / ANSI palettes,
 *                 modern rounded UTF-8 box drawing, badges, progress bars,
 *                 table rendering, visual width calculations, and live TUI dashboard.
 * Owner: Shared
 * ============================================================================
 */

#include "common.h"
#include <string>
#include <vector>
#include <cstdint>

// Terminal capability detection
bool ui_is_tty();
bool ui_colors_enabled();

// Dashboard active mode flag (prevents stdout collision during live dashboard)
void ui_set_dashboard_active(bool active);
bool ui_is_dashboard_active();

// Visual text width helpers (strips ANSI escape codes when computing length)
size_t ui_visible_len(const std::string& str);
std::string ui_pad_right(const std::string& str, size_t target_width);
std::string ui_pad_left(const std::string& str, size_t target_width);

// Modern Banner and Branding
void ui_print_banner();
void ui_print_version();

// Badges and status indicators (modern pill badge style)
std::string ui_badge(Severity severity);
std::string ui_event_badge(EventType type);
std::string ui_success_mark();
std::string ui_error_mark();
std::string ui_warn_mark();

// Formatting helpers
std::string ui_truncate_path(const std::string& path, size_t max_len);
std::string ui_human_size(off_t bytes);
std::string ui_human_time_ago(time_t epoch_sec);

// Drawing primitives (modern rounded corners: ╭─╮ ╰─╯)
void ui_draw_box(const std::string& title, const std::vector<std::string>& lines);
void ui_draw_table(const std::vector<std::string>& headers,
                   const std::vector<std::vector<std::string>>& rows,
                   const std::vector<size_t>& widths);
void ui_draw_progress_bar(size_t done, size_t total, const std::string& prefix = "");
std::string ui_horizontal_bar(size_t value, size_t max_val, size_t bar_width = 20);

// Terminal cursor management
void ui_hide_cursor();
void ui_show_cursor();
void ui_clear_screen();

// Live watch dashboard structures & functions
struct DashboardStats {
    time_t start_time;
    size_t dirs_watched;
    size_t baseline_files;
    int worker_count;
    size_t queue_depth;
    size_t queue_capacity;
    size_t total_events;
    size_t dropped_events;
    size_t counts_by_type[8];     // Indexed by EventType
    size_t counts_by_severity[3]; // Indexed by Severity
    std::vector<ClassifiedEvent> recent_alerts; // Ring buffer of recent alerts
    pthread_mutex_t mutex;
};

// Global dashboard stats handle
extern DashboardStats g_stats;

void ui_stats_init();
void ui_stats_record_event(const ClassifiedEvent& ce, size_t current_q_depth);
void ui_render_dashboard();
void ui_print_alert_line(const ClassifiedEvent& ce);
void ui_stats_dump_summary();

#endif // SENTINELFS_UI_H
