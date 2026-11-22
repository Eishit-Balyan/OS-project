/**
 * ============================================================================
 * SentinelFS - Audit Reporting and History Implementation
 * Module Purpose: Real audit log parsing, multi-criteria filtering (--type,
 *                 --severity, --since, --path, --limit, --tail), ASCII/ANSI
 *                 summary tables with block charts, CSV and self-contained
 *                 dark-mode HTML export.
 * Owner: Arjun & Ayaansh
 * ============================================================================
 */

#include "report.h"
#include "ui.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <map>
#include <algorithm>
#include <ctime>

time_t report_parse_since(const std::string& str) {
    if (str.empty()) return 0;
    char unit = str.back();
    std::string num_part = str.substr(0, str.size() - 1);
    long val = 0;
    try {
        val = std::stol(num_part);
    } catch (...) {
        return 0;
    }

    long secs = 0;
    if (unit == 's' || unit == 'S') secs = val;
    else if (unit == 'm' || unit == 'M') secs = val * 60;
    else if (unit == 'h' || unit == 'H') secs = val * 3600;
    else if (unit == 'd' || unit == 'D') secs = val * 86400;
    else {
        // Assume raw minutes if no unit
        try {
            secs = std::stol(str) * 60;
        } catch (...) {
            secs = 0;
        }
    }

    time_t now = time(nullptr);
    return (now > secs) ? (now - secs) : 0;
}

bool report_load_events(const std::string& log_path, std::vector<ClassifiedEvent>& out_events) {
    out_events.clear();
    std::ifstream in(log_path);
    if (!in.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        ClassifiedEvent ce;
        if (line_to_classified_event(line, ce)) {
            out_events.push_back(ce);
        }
    }
    return true;
}

std::vector<ClassifiedEvent> report_filter(const std::vector<ClassifiedEvent>& events,
                                           const ReportFilterOptions& options) {
    std::vector<ClassifiedEvent> filtered;
    time_t since_epoch = report_parse_since(options.since_str);

    for (const auto& ce : events) {
        if (!options.type_str.empty()) {
            if (event_type_to_string(ce.ev.type) != options.type_str) {
                continue;
            }
        }

        if (!options.severity_str.empty()) {
            if (severity_to_string(ce.severity) != options.severity_str) {
                continue;
            }
        }

        if (since_epoch > 0) {
            if (ce.ev.timestamp < since_epoch) {
                continue;
            }
        }

        if (!options.path_substring.empty()) {
            if (ce.ev.path.find(options.path_substring) == std::string::npos &&
                ce.ev.old_path.find(options.path_substring) == std::string::npos) {
                continue;
            }
        }

        filtered.push_back(ce);
    }
    return filtered;
}

void report_print_events_table(const std::vector<ClassifiedEvent>& events,
                               int limit,
                               bool tail) {
    if (events.empty()) {
        std::cout << "No matching filesystem events found.\n";
        return;
    }

    std::vector<ClassifiedEvent> display_list = events;
    if (limit > 0 && static_cast<size_t>(limit) < display_list.size()) {
        if (tail) {
            display_list.erase(display_list.begin(), display_list.end() - limit);
        } else {
            display_list.resize(limit);
        }
    }

    std::vector<std::string> headers = {"Timestamp", "Severity", "Type", "File Path", "Detail"};
    std::vector<size_t> widths = {19, 10, 10, 35, 30};
    std::vector<std::vector<std::string>> rows;

    for (const auto& ce : display_list) {
        rows.push_back({
            format_time(ce.ev.timestamp),
            ui_badge(ce.severity),
            ui_event_badge(ce.ev.type),
            ui_truncate_path(ce.ev.path, 33),
            ce.detail
        });
    }

    ui_draw_table(headers, rows, widths);
    std::cout << "Displaying " << display_list.size() << " of " << events.size() << " total events.\n";
}

void report_print_comprehensive_summary(const std::vector<ClassifiedEvent>& events) {
    if (events.empty()) {
        std::cout << "No audit events logged yet. (Run 'watch' to capture filesystem activity).\n";
        return;
    }

    size_t sev_counts[3] = {0, 0, 0};
    size_t type_counts[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    std::unordered_map<std::string, size_t> path_counts;
    std::map<std::string, size_t> hourly_buckets;
    std::vector<ClassifiedEvent> burst_events;

    size_t max_sev = 0;
    size_t max_type = 0;

    for (const auto& ce : events) {
        int s = static_cast<int>(ce.severity);
        if (s >= 0 && s < 3) {
            sev_counts[s]++;
            if (sev_counts[s] > max_sev) max_sev = sev_counts[s];
        }

        int t = static_cast<int>(ce.ev.type);
        if (t >= 0 && t < 8) {
            type_counts[t]++;
            if (type_counts[t] > max_type) max_type = type_counts[t];
        }

        path_counts[ce.ev.path]++;

        // Hourly timeline aggregation
        std::string t_str = format_time(ce.ev.timestamp);
        std::string hour_key = t_str.substr(0, 13) + ":00";
        hourly_buckets[hour_key]++;

        if (ce.detail.find("burst") != std::string::npos ||
            ce.ev.path.find("BURST") != std::string::npos) {
            burst_events.push_back(ce);
        }
    }

    std::cout << "\n\033[1;36m==================== SentinelFS Security Audit Report ====================\033[0m\n\n";

    // 1. Severity Distribution
    std::cout << "\033[1;37m[1] Severity Distribution:\033[0m\n";
    std::cout << "  INFO:     " << std::setw(6) << sev_counts[INFO] << "  "
              << ui_horizontal_bar(sev_counts[INFO], max_sev, 30) << "\n";
    std::cout << "  WARNING:  " << std::setw(6) << sev_counts[WARNING] << "  "
              << ui_horizontal_bar(sev_counts[WARNING], max_sev, 30) << "\n";
    std::cout << "  CRITICAL: " << std::setw(6) << sev_counts[CRITICAL] << "  "
              << ui_horizontal_bar(sev_counts[CRITICAL], max_sev, 30) << "\n\n";

    // 2. Change Type Distribution
    std::cout << "\033[1;37m[2] Event Types Breakdown:\033[0m\n";
    const char* t_names[] = {"CREATED", "MODIFIED", "DELETED", "MOVED", "PERM_CHANGED", "OWNER_CHANGED", "UNKNOWN"};
    for (int i = 0; i < 7; ++i) {
        std::cout << "  " << std::left << std::setw(14) << t_names[i] << ": "
                  << std::right << std::setw(6) << type_counts[i] << "  "
                  << ui_horizontal_bar(type_counts[i], max_type, 30) << "\n";
    }
    std::cout << "\n";

    // 3. Top 5 Most Changed Files
    std::vector<std::pair<std::string, size_t>> sorted_paths(path_counts.begin(), path_counts.end());
    std::sort(sorted_paths.begin(), sorted_paths.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });

    std::cout << "\033[1;37m[3] Top Most-Modified Targets:\033[0m\n";
    size_t top_n = std::min<size_t>(5, sorted_paths.size());
    for (size_t i = 0; i < top_n; ++i) {
        std::cout << "  #" << (i + 1) << " " << std::setw(5) << sorted_paths[i].second << " events - "
                  << sorted_paths[i].first << "\n";
    }
    std::cout << "\n";

    // 4. Hourly Timeline
    std::cout << "\033[1;37m[4] Hourly Activity Timeline:\033[0m\n";
    size_t max_hourly = 0;
    for (const auto& kv : hourly_buckets) {
        if (kv.second > max_hourly) max_hourly = kv.second;
    }
    for (const auto& kv : hourly_buckets) {
        std::cout << "  " << kv.first << " │ " << std::setw(5) << kv.second << "  "
                  << ui_horizontal_bar(kv.second, max_hourly, 25) << "\n";
    }
    std::cout << "\n";

    // 5. Burst / Mass Tamper Alerts
    std::cout << "\033[1;37m[5] Anomaly Burst Alerts (" << burst_events.size() << " detected):\033[0m\n";
    if (burst_events.empty()) {
        std::cout << "  No abnormal mass-tamper activity detected.\n";
    } else {
        for (const auto& be : burst_events) {
            std::cout << "  " << ui_badge(CRITICAL) << " [" << format_time(be.ev.timestamp)
                      << "] " << be.detail << "\n";
        }
    }
    std::cout << std::endl;
}

static std::string escape_csv_cell(const std::string& cell) {
    if (cell.find_first_of(",\"\r\n") == std::string::npos) {
        return cell;
    }
    std::string escaped = "\"";
    for (char c : cell) {
        if (c == '"') escaped += "\"\"";
        else escaped += c;
    }
    escaped += "\"";
    return escaped;
}

bool report_export_csv(const std::string& csv_path, const std::vector<ClassifiedEvent>& events) {
    std::ofstream out(csv_path);
    if (!out.is_open()) {
        std::cerr << ui_error_mark() << " Failed to write CSV export to " << csv_path << std::endl;
        return false;
    }

    out << "Timestamp,Epoch,Severity,Type,Path,OldPath,Detail\n";
    for (const auto& ce : events) {
        out << escape_csv_cell(format_time(ce.ev.timestamp)) << ","
            << ce.ev.timestamp << ","
            << escape_csv_cell(severity_to_string(ce.severity)) << ","
            << escape_csv_cell(event_type_to_string(ce.ev.type)) << ","
            << escape_csv_cell(ce.ev.path) << ","
            << escape_csv_cell(ce.ev.old_path) << ","
            << escape_csv_cell(ce.detail) << "\n";
    }
    return true;
}

bool report_export_html(const std::string& html_path, const std::vector<ClassifiedEvent>& events) {
    std::ofstream out(html_path);
    if (!out.is_open()) {
        std::cerr << ui_error_mark() << " Failed to write HTML export to " << html_path << std::endl;
        return false;
    }

    size_t info_cnt = 0, warn_cnt = 0, crit_cnt = 0;
    for (const auto& e : events) {
        if (e.severity == INFO) info_cnt++;
        else if (e.severity == WARNING) warn_cnt++;
        else if (e.severity == CRITICAL) crit_cnt++;
    }

    out << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        << "<meta charset=\"UTF-8\">\n"
        << "<title>SentinelFS Audit Report</title>\n"
        << "<style>\n"
        << "  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; "
        << "         background-color: #11111b; color: #cdd6f4; margin: 0; padding: 25px; }\n"
        << "  h1, h2, h3 { color: #89b4fa; margin-top: 0; }\n"
        << "  .cards { display: flex; gap: 20px; margin-bottom: 25px; }\n"
        << "  .card { flex: 1; background: #1e1e2e; border: 1px solid #313244; border-radius: 8px; padding: 20px; }\n"
        << "  .card h3 { margin: 0 0 10px 0; font-size: 14px; text-transform: uppercase; color: #a6adc8; }\n"
        << "  .card .val { font-size: 32px; font-weight: bold; }\n"
        << "  .val.info { color: #89dceb; }\n"
        << "  .val.warn { color: #f9e2af; }\n"
        << "  .val.crit { color: #f38ba8; }\n"
        << "  table { width: 100%; border-collapse: collapse; background: #1e1e2e; border-radius: 8px; overflow: hidden; }\n"
        << "  th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #313244; font-size: 14px; }\n"
        << "  th { background-color: #181825; color: #bac2de; }\n"
        << "  tr:hover { background-color: #262738; }\n"
        << "  .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }\n"
        << "  .badge.INFO { background: #044352; color: #89dceb; }\n"
        << "  .badge.WARNING { background: #594602; color: #f9e2af; }\n"
        << "  .badge.CRITICAL { background: #610d1f; color: #f38ba8; }\n"
        << "</style>\n</head>\n<body>\n"
        << "  <h1>🛡️ SentinelFS - Integrity Audit Report</h1>\n"
        << "  <p style=\"color: #a6adc8;\">Report generated at: " << format_time(time(nullptr))
        << " | Total recorded events: " << events.size() << "</p>\n"
        << "  <div class=\"cards\">\n"
        << "    <div class=\"card\"><h3>Total Events</h3><div class=\"val\">" << events.size() << "</div></div>\n"
        << "    <div class=\"card\"><h3>Info Events</h3><div class=\"val info\">" << info_cnt << "</div></div>\n"
        << "    <div class=\"card\"><h3>Warnings</h3><div class=\"val warn\">" << warn_cnt << "</div></div>\n"
        << "    <div class=\"card\"><h3>Critical Alerts</h3><div class=\"val crit\">" << crit_cnt << "</div></div>\n"
        << "  </div>\n"
        << "  <h2>Filesystem Activity Log</h2>\n"
        << "  <table>\n"
        << "    <thead><tr><th>Timestamp</th><th>Severity</th><th>Event Type</th><th>File Path</th><th>Change Detail</th></tr></thead>\n"
        << "    <tbody>\n";

    for (const auto& ce : events) {
        std::string sev_str = severity_to_string(ce.severity);
        out << "    <tr>"
            << "<td>" << format_time(ce.ev.timestamp) << "</td>"
            << "<td><span class=\"badge " << sev_str << "\">" << sev_str << "</span></td>"
            << "<td>" << event_type_to_string(ce.ev.type) << "</td>"
            << "<td><code>" << escape_field(ce.ev.path) << "</code></td>"
            << "<td>" << escape_field(ce.detail) << "</td>"
            << "</tr>\n";
    }

    out << "    </tbody>\n  </table>\n</body>\n</html>\n";
    return true;
}
