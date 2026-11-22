#ifndef WARDEN_REPORT_H
#define WARDEN_REPORT_H

/**
 * ============================================================================
 * Warden - Audit Reporting and History Module
 * Module Purpose: Real audit log parsing, multi-criteria filtering (--type,
 *                 --severity, --since, --path, --limit, --tail), ASCII/ANSI
 *                 summary tables with block charts, CSV and self-contained
 *                 dark-mode HTML export.
 * Owner: Krishna + Aviral
 * ============================================================================
 */

#include "common.h"
#include <string>
#include <vector>

// Filter criteria flags for 'events' and 'report' subcommands
struct ReportFilterOptions {
    std::string type_str;
    std::string severity_str;
    std::string since_str;        // e.g. "10m", "2h", "1d"
    std::string path_substring;
    int limit = 0;
    bool tail = false;
};

// Parses relative time strings like "10m", "2h", "1d" into lower-bound epoch timestamp
time_t report_parse_since(const std::string& str);

// Loads and parses all classified events from events.log into out_events
bool report_load_events(const std::string& log_path, std::vector<ClassifiedEvent>& out_events);

// Filters events by the specified options
std::vector<ClassifiedEvent> report_filter(const std::vector<ClassifiedEvent>& events,
                                           const ReportFilterOptions& options);

// Displays formatted tabular output of events to stdout (with limit and tail support)
void report_print_events_table(const std::vector<ClassifiedEvent>& events,
                               int limit,
                               bool tail);

// Prints comprehensive audit report: type/severity bar charts, top 5 files, timeline, burst alerts
void report_print_comprehensive_summary(const std::vector<ClassifiedEvent>& events);

// Exports events to comma-separated values (CSV) format
bool report_export_csv(const std::string& csv_path, const std::vector<ClassifiedEvent>& events);

// Exports events to a self-contained single-file dark-themed HTML report with inline CSS
bool report_export_html(const std::string& html_path, const std::vector<ClassifiedEvent>& events);

#endif // WARDEN_REPORT_H
