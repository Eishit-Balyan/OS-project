/**
 * ============================================================================
 * Warden - Modern Terminal UI & Formatting Implementation
 * Module Purpose: Real terminal capability checking, 256-color ANSI palettes,
 *                 UTF-8 rounded boxes (╭─╮ ╰─╯), visual cell-width alignment,
 *                 and a modern, tear-free live monitoring TUI dashboard.
 * Owner: Eishit + Ashutosh
 * ============================================================================
 */

#include "ui.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <unistd.h>
#include <pthread.h>

DashboardStats g_stats;
static std::atomic<bool> g_dashboard_active{false};

void ui_set_dashboard_active(bool active) {
    g_dashboard_active.store(active, std::memory_order_relaxed);
}

bool ui_is_dashboard_active() {
    return g_dashboard_active.load(std::memory_order_relaxed);
}

bool ui_is_tty() {
    return isatty(STDOUT_FILENO) == 1;
}

bool ui_colors_enabled() {
    if (!ui_is_tty()) return false;
    const char* no_color = std::getenv("NO_COLOR");
    if (no_color && no_color[0] != '\0') return false;
    const char* term = std::getenv("TERM");
    if (term && std::strcmp(term, "dumb") == 0) return false;
    return true;
}

size_t ui_visible_len(const std::string& str) {
    size_t len = 0;
    bool in_esc = false;
    for (size_t i = 0; i < str.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(str[i]);
        if (c == '\033') {
            in_esc = true;
            continue;
        }
        if (in_esc) {
            if (c == 'm' || c == 'H' || c == 'J' || c == 'l' || c == 'h' || c == 'K') {
                in_esc = false;
            }
            continue;
        }
        // Ignore UTF-8 continuation bytes (0x80 to 0xBF)
        if ((c & 0xC0) == 0x80) {
            continue;
        }
        len++;
    }
    return len;
}

std::string ui_pad_right(const std::string& str, size_t target_width) {
    size_t vlen = ui_visible_len(str);
    if (vlen >= target_width) return str;
    return str + std::string(target_width - vlen, ' ');
}

std::string ui_pad_left(const std::string& str, size_t target_width) {
    size_t vlen = ui_visible_len(str);
    if (vlen >= target_width) return str;
    return std::string(target_width - vlen, ' ') + str;
}

void ui_print_banner() {
    if (!ui_colors_enabled()) {
        std::cout << "========================================================\n"
                  << "  Warden - Real-Time File Integrity Monitor v1.0.0\n"
                  << "========================================================\n";
        return;
    }
    std::cout << "\033[38;5;67m"
              << "  ╭────────────────────────────────────────────────────────────╮\n"
              << "  │   \033[38;5;81m    ░█░░░█░█▀▀█░█▀▀▄░█▀▀▄░█▀▀▀░█▀▀▄░    \033[38;5;67m   \033[1;38;5;141mv1.0.0\033[38;5;67m        │\n"
              << "  │   \033[38;5;117m    ░█░█░█░█▄▄█░█▄▄▀░█░░█░█▀▀░░█░░█░    \033[38;5;67m   \033[38;5;244mLinux Host    \033[38;5;67m│\n"
              << "  │   \033[38;5;123m    ░▀▄▀▄▀░▀░░▀░▀░░▀░▀▀▀░░▀▀▀▀░▀░░▀░    \033[38;5;67m   \033[38;5;250mIntegrity     \033[38;5;67m│\n"
              << "  ╰────────────────────────────────────────────────────────────╯\033[0m\n";
}

void ui_print_version() {
    std::cout << "Warden v1.0.0 (Linux x86_64 POSIX inotify engine)\n";
}

std::string ui_badge(Severity severity) {
    if (!ui_colors_enabled()) {
        switch (severity) {
            case INFO:     return "[INFO]";
            case WARNING:  return "[WARN]";
            case CRITICAL: return "[CRIT]";
            default:       return "[INFO]";
        }
    }
    switch (severity) {
        case INFO:     return "\033[38;5;232;48;5;74m ℹ INFO \033[0m";
        case WARNING:  return "\033[38;5;232;48;5;215m ⚠ WARN \033[0m";
        case CRITICAL: return "\033[1;38;5;231;48;5;197m ✖ CRIT \033[0m";
        default:       return "\033[38;5;232;48;5;74m ℹ INFO \033[0m";
    }
}

std::string ui_event_badge(EventType type) {
    std::string s = event_type_to_string(type);
    if (!ui_colors_enabled()) {
        return "[" + s + "]";
    }
    switch (type) {
        case CREATED:       return "\033[38;5;120m+ CREATE\033[0m";
        case MODIFIED:      return "\033[38;5;222m~ MODIFY\033[0m";
        case DELETED:       return "\033[38;5;203m- DELETE\033[0m";
        case MOVED:         return "\033[38;5;183m→ MOVED \033[0m";
        case PERM_CHANGED:  return "\033[38;5;214m⚙ PERMS \033[0m";
        case OWNER_CHANGED: return "\033[38;5;208m👤 OWNER \033[0m";
        case UNKNOWN:
        default:            return "\033[38;5;244m? UNKNOWN\033[0m";
    }
}

std::string ui_success_mark() {
    return ui_colors_enabled() ? "\033[1;38;5;120m✔\033[0m" : "[OK]";
}

std::string ui_error_mark() {
    return ui_colors_enabled() ? "\033[1;38;5;203m✖\033[0m" : "[ERROR]";
}

std::string ui_warn_mark() {
    return ui_colors_enabled() ? "\033[1;38;5;215m▲\033[0m" : "[WARN]";
}

std::string ui_truncate_path(const std::string& path, size_t max_len) {
    if (path.size() <= max_len || max_len < 5) {
        return path;
    }
    size_t half = (max_len - 3) / 2;
    size_t second_half = max_len - 3 - half;
    return path.substr(0, half) + "…" + path.substr(path.size() - second_half);
}

std::string ui_human_size(off_t bytes) {
    if (bytes < 1024) {
        return std::to_string(bytes) + " B";
    }
    const char* units[] = {"KB", "MB", "GB", "TB"};
    double size = bytes / 1024.0;
    int idx = 0;
    while (size >= 1024.0 && idx < 3) {
        size /= 1024.0;
        idx++;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size << " " << units[idx];
    return oss.str();
}

std::string ui_human_time_ago(time_t epoch_sec) {
    time_t now = time(nullptr);
    if (epoch_sec > now) return "now";
    long diff = now - epoch_sec;
    if (diff < 2) return "now";
    if (diff < 60) return std::to_string(diff) + "s ago";
    if (diff < 3600) return std::to_string(diff / 60) + "m ago";
    if (diff < 86400) return std::to_string(diff / 3600) + "h ago";
    return std::to_string(diff / 86400) + "d ago";
}

void ui_draw_box(const std::string& title, const std::vector<std::string>& lines) {
    size_t width = ui_visible_len(title) + 6;
    for (const auto& l : lines) {
        size_t vl = ui_visible_len(l) + 4;
        if (vl > width) width = vl;
    }
    if (width < 50) width = 50;

    std::string b_col = ui_colors_enabled() ? "\033[38;5;67m" : "";
    std::string t_col = ui_colors_enabled() ? "\033[1;38;5;81m" : "";
    std::string rst = ui_colors_enabled() ? "\033[0m" : "";

    std::cout << b_col << "╭─ " << t_col << title << b_col << " ";
    size_t header_len = ui_visible_len(title) + 4;
    for (size_t i = header_len; i < width - 1; ++i) std::cout << "─";
    std::cout << "╮" << rst << "\n";

    for (const auto& l : lines) {
        std::cout << b_col << "│ " << rst << ui_pad_right(l, width - 4) << b_col << " │" << rst << "\n";
    }

    std::cout << b_col << "╰";
    for (size_t i = 1; i < width - 1; ++i) std::cout << "─";
    std::cout << "╯" << rst << "\n";
}

void ui_draw_table(const std::vector<std::string>& headers,
                   const std::vector<std::vector<std::string>>& rows,
                   const std::vector<size_t>& widths) {
    if (headers.size() != widths.size()) return;

    std::string b_col = ui_colors_enabled() ? "\033[38;5;239m" : "";
    std::string h_col = ui_colors_enabled() ? "\033[1;38;5;81m" : "";
    std::string rst = ui_colors_enabled() ? "\033[0m" : "";

    // Top border
    std::cout << b_col << "╭";
    for (size_t i = 0; i < widths.size(); ++i) {
        for (size_t j = 0; j < widths[i] + 2; ++j) std::cout << "─";
        if (i + 1 < widths.size()) std::cout << "┬";
    }
    std::cout << "╮" << rst << "\n";

    // Header labels
    std::cout << b_col << "│" << rst;
    for (size_t i = 0; i < headers.size(); ++i) {
        std::cout << " " << h_col << ui_pad_right(headers[i], widths[i]) << rst << b_col << " │" << rst;
    }
    std::cout << "\n";

    // Divider
    std::cout << b_col << "├";
    for (size_t i = 0; i < widths.size(); ++i) {
        for (size_t j = 0; j < widths[i] + 2; ++j) std::cout << "─";
        if (i + 1 < widths.size()) std::cout << "┼";
    }
    std::cout << "┤" << rst << "\n";

    // Rows
    for (const auto& row : rows) {
        std::cout << b_col << "│" << rst;
        for (size_t i = 0; i < widths.size(); ++i) {
            std::string cell = (i < row.size()) ? row[i] : "";
            std::cout << " " << ui_pad_right(cell, widths[i]) << b_col << " │" << rst;
        }
        std::cout << "\n";
    }

    // Bottom border
    std::cout << b_col << "╰";
    for (size_t i = 0; i < widths.size(); ++i) {
        for (size_t j = 0; j < widths[i] + 2; ++j) std::cout << "─";
        if (i + 1 < widths.size()) std::cout << "┴";
    }
    std::cout << "╯" << rst << "\n";
}

void ui_draw_progress_bar(size_t done, size_t total, const std::string& prefix) {
    size_t bar_width = 24;
    float frac = (total == 0) ? 1.0f : static_cast<float>(done) / total;
    if (frac > 1.0f) frac = 1.0f;
    size_t filled = static_cast<size_t>(frac * bar_width);

    std::string bar_col = "\033[38;5;81m";
    std::string track_col = "\033[38;5;238m";
    std::string rst = "\033[0m";

    std::cout << "\r" << prefix << " [";
    for (size_t i = 0; i < bar_width; ++i) {
        if (i < filled) std::cout << bar_col << "▰";
        else std::cout << track_col << "▱";
    }
    int percent = static_cast<int>(frac * 100);
    std::cout << rst << "] \033[1;37m" << std::setw(3) << percent << "%\033[0m ("
              << done << "/" << total << ")" << std::flush;
    if (done >= total) {
        std::cout << "\n";
    }
}

std::string ui_horizontal_bar(size_t value, size_t max_val, size_t bar_width) {
    if (max_val == 0) return "";
    float frac = static_cast<float>(value) / max_val;
    if (frac > 1.0f) frac = 1.0f;
    size_t filled = static_cast<size_t>(frac * bar_width);
    std::string s;
    for (size_t i = 0; i < filled; ++i) s += "█";
    return s;
}

void ui_hide_cursor() {
    if (ui_is_tty()) std::cout << "\033[?25l" << std::flush;
}

void ui_show_cursor() {
    if (ui_is_tty()) std::cout << "\033[?25h" << std::flush;
}

void ui_clear_screen() {
    if (ui_is_tty()) std::cout << "\033[2J\033[H" << std::flush;
}

void ui_stats_init() {
    g_stats.start_time = time(nullptr);
    g_stats.dirs_watched = 0;
    g_stats.baseline_files = 0;
    g_stats.worker_count = 0;
    g_stats.queue_depth = 0;
    g_stats.queue_capacity = 1024;
    g_stats.total_events = 0;
    g_stats.dropped_events = 0;
    for (int i = 0; i < 8; ++i) g_stats.counts_by_type[i] = 0;
    for (int i = 0; i < 3; ++i) g_stats.counts_by_severity[i] = 0;
    g_stats.recent_alerts.clear();
    pthread_mutex_init(&g_stats.mutex, nullptr);
}

void ui_stats_record_event(const ClassifiedEvent& ce, size_t current_q_depth) {
    pthread_mutex_lock(&g_stats.mutex);
    g_stats.total_events++;
    g_stats.queue_depth = current_q_depth;

    int type_idx = static_cast<int>(ce.ev.type);
    if (type_idx >= 0 && type_idx < 8) g_stats.counts_by_type[type_idx]++;

    int sev_idx = static_cast<int>(ce.severity);
    if (sev_idx >= 0 && sev_idx < 3) g_stats.counts_by_severity[sev_idx]++;

    // Ring buffer of last 10 events (newest first)
    g_stats.recent_alerts.insert(g_stats.recent_alerts.begin(), ce);
    if (g_stats.recent_alerts.size() > 10) {
        g_stats.recent_alerts.pop_back();
    }
    pthread_mutex_unlock(&g_stats.mutex);
}

void ui_print_alert_line(const ClassifiedEvent& ce) {
    std::string time_str = format_time(ce.ev.timestamp);
    std::string t_col = "\033[38;5;244m";
    std::string rst = "\033[0m";

    std::cout << t_col << "[" << time_str << "]" << rst << " "
              << ui_badge(ce.severity) << " "
              << ui_event_badge(ce.ev.type) << " "
              << "\033[1;37m" << ce.ev.path << rst;
    if (!ce.ev.old_path.empty()) {
        std::cout << " \033[38;5;183m(from " << ce.ev.old_path << ")\033[0m";
    }
    if (!ce.detail.empty()) {
        std::cout << " \033[38;5;250m- " << ce.detail << rst;
    }
    std::cout << "\n";
}

void ui_render_dashboard() {
    if (!ui_is_tty()) return;

    pthread_mutex_lock(&g_stats.mutex);
    time_t uptime = time(nullptr) - g_stats.start_time;
    if (uptime < 1) uptime = 1;
    double eps = static_cast<double>(g_stats.total_events) / uptime;

    const size_t BOX_WIDTH = 84;
    const std::string b_col = "\033[38;5;67m";
    const std::string t_col = "\033[1;38;5;81m";
    const std::string s_col = "\033[38;5;244m";
    const std::string v_col = "\033[1;38;5;255m";
    const std::string rst = "\033[0m";

    std::ostringstream buf;

    // Move cursor to top-left (without full screen flash)
    buf << "\033[H";

    // Header bar
    buf << b_col << "╭─ " << t_col << "Warden Host Integrity Daemon "
        << "\033[38;5;120m● ACTIVE "
        << b_col;
    size_t top_len = ui_visible_len("Warden Host Integrity Daemon ● ACTIVE ") + 4;
    for (size_t i = top_len; i < BOX_WIDTH - 1; ++i) buf << "─";
    buf << "╮\n";

    // Row 1: Vitals
    std::ostringstream r1;
    r1 << s_col << "Uptime: " << v_col << uptime << "s"
       << s_col << "  │  Roots: " << v_col << g_stats.dirs_watched
       << s_col << "  │  Files: " << v_col << g_stats.baseline_files
       << s_col << "  │  Workers: " << v_col << g_stats.worker_count
       << s_col << "  │  Ingest Rate: " << v_col << std::fixed << std::setprecision(1) << eps << " ev/s";
    buf << b_col << "│  " << rst << ui_pad_right(r1.str(), BOX_WIDTH - 4) << b_col << "│\n";

    // Row 2: Queue Depth Gauge
    std::ostringstream r2;
    float q_frac = (g_stats.queue_capacity == 0) ? 0.0f
        : static_cast<float>(g_stats.queue_depth) / g_stats.queue_capacity;
    size_t q_bar_len = 22;
    size_t filled = static_cast<size_t>(q_frac * q_bar_len);

    std::string q_color = "\033[38;5;120m"; // Green
    if (q_frac > 0.5f) q_color = "\033[38;5;215m"; // Orange
    if (q_frac > 0.8f) q_color = "\033[38;5;203m"; // Red

    r2 << s_col << "Queue: [" << q_color;
    for (size_t i = 0; i < q_bar_len; ++i) {
        if (i < filled) r2 << "▰";
        else r2 << "\033[38;5;238m▱";
    }
    r2 << rst << s_col << "] " << v_col << g_stats.queue_depth << s_col << "/" << g_stats.queue_capacity
       << s_col << "  │  Total Events Processed: " << v_col << g_stats.total_events;
    buf << b_col << "│  " << rst << ui_pad_right(r2.str(), BOX_WIDTH - 4) << b_col << "│\n";

    // Divider: Statistics
    buf << b_col << "├─ " << t_col << "Security Telemetry " << b_col;
    size_t d1_len = ui_visible_len("Security Telemetry ") + 4;
    for (size_t i = d1_len; i < BOX_WIDTH - 1; ++i) buf << "─";
    buf << "┤\n";

    // Row 3: Severity Counters
    std::ostringstream r3;
    r3 << ui_badge(INFO) << " " << v_col << std::setw(5) << g_stats.counts_by_severity[INFO] << "  "
       << ui_badge(WARNING) << " " << v_col << std::setw(5) << g_stats.counts_by_severity[WARNING] << "  "
       << ui_badge(CRITICAL) << " " << v_col << std::setw(5) << g_stats.counts_by_severity[CRITICAL];
    buf << b_col << "│  " << rst << ui_pad_right(r3.str(), BOX_WIDTH - 4) << b_col << "│\n";

    // Row 4: Event Types breakdown
    std::ostringstream r4;
    r4 << "\033[38;5;120mCREATE:\033[0m " << v_col << g_stats.counts_by_type[CREATED]
       << s_col << " │ \033[38;5;222mMODIFY:\033[0m " << v_col << g_stats.counts_by_type[MODIFIED]
       << s_col << " │ \033[38;5;203mDELETE:\033[0m " << v_col << g_stats.counts_by_type[DELETED]
       << s_col << " │ \033[38;5;183mMOVE:\033[0m " << v_col << g_stats.counts_by_type[MOVED]
       << s_col << " │ \033[38;5;214mATTRIB:\033[0m " << v_col
       << (g_stats.counts_by_type[PERM_CHANGED] + g_stats.counts_by_type[OWNER_CHANGED]);
    buf << b_col << "│  " << rst << ui_pad_right(r4.str(), BOX_WIDTH - 4) << b_col << "│\n";

    // Divider: Live Alerts
    buf << b_col << "├─ " << t_col << "Live Activity Feed (Last 10 Events) " << b_col;
    size_t d2_len = ui_visible_len("Live Activity Feed (Last 10 Events) ") + 4;
    for (size_t i = d2_len; i < BOX_WIDTH - 1; ++i) buf << "─";
    buf << "┤\n";

    // Alert Feed Rows (Strictly bounded and formatted to avoid horizontal overflow)
    for (size_t idx = 0; idx < 10; ++idx) {
        std::ostringstream a_line;
        if (idx < g_stats.recent_alerts.size()) {
            const auto& a = g_stats.recent_alerts[idx];
            std::string time_ago = ui_human_time_ago(a.ev.timestamp);
            a_line << ui_badge(a.severity) << " "
                   << ui_event_badge(a.ev.type) << " "
                   << v_col << ui_truncate_path(a.ev.path, 34) << rst;
            if (!a.detail.empty()) {
                a_line << s_col << " (" << ui_truncate_path(a.detail, 20) << ")" << rst;
            }
            a_line << s_col << " " << std::right << std::setw(6) << time_ago << rst;
        } else {
            a_line << s_col << "•";
        }
        buf << b_col << "│  " << rst << ui_pad_right(a_line.str(), BOX_WIDTH - 4) << b_col << "│\n";
    }

    // Bottom border with interactive controls
    buf << b_col << "╰";
    for (size_t i = 1; i < BOX_WIDTH - 1; ++i) buf << "─";
    buf << "╯\n";
    buf << "  \033[38;5;244m[Ctrl+C] Clean Shutdown  │  [SIGHUP] Reload Config  │  [SIGUSR1] Stats Dump\033[0m\033[K\n";

    std::cout << buf.str() << std::flush;
    pthread_mutex_unlock(&g_stats.mutex);
}

void ui_stats_dump_summary() {
    pthread_mutex_lock(&g_stats.mutex);
    std::vector<std::string> lines;
    lines.push_back("Total Execution Uptime: " + std::to_string(time(nullptr) - g_stats.start_time) + "s");
    lines.push_back("Total Filesystem Events: " + std::to_string(g_stats.total_events));
    lines.push_back("INFO: " + std::to_string(g_stats.counts_by_severity[INFO]) +
                    " | WARNING: " + std::to_string(g_stats.counts_by_severity[WARNING]) +
                    " | CRITICAL: " + std::to_string(g_stats.counts_by_severity[CRITICAL]));
    lines.push_back("Peak Queue Depth: " + std::to_string(g_stats.queue_depth));
    ui_draw_box("Warden Shutdown Summary", lines);
    pthread_mutex_unlock(&g_stats.mutex);
}
