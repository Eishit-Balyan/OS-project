/**
 * ============================================================================
 * SentinelFS - Shared Helper Implementations
 * Module Purpose: Real implementations for enum-string serialization, TSV field
 *                 escaping/unescaping, record line parsing/formatting, and
 *                 default configuration initialization.
 * Owner: Shared
 * ============================================================================
 */

#include "common.h"
#include <iostream>
#include <sstream>
#include <iomanip>

Config default_config() {
    Config cfg;
    cfg.worker_count = 4;
    cfg.queue_capacity = 1024;
    cfg.burst_threshold = 20;
    cfg.burst_window_sec = 10;
    cfg.ignore_patterns = { "*.swp", "*.tmp", "*~" };
    cfg.critical_paths = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config"
    };
    cfg.protected_dirs.clear();
    return cfg;
}

std::string event_type_to_string(EventType type) {
    switch (type) {
        case CREATED:       return "CREATED";
        case MODIFIED:      return "MODIFIED";
        case DELETED:       return "DELETED";
        case MOVED:         return "MOVED";
        case PERM_CHANGED:  return "PERM_CHANGED";
        case OWNER_CHANGED: return "OWNER_CHANGED";
        case UNKNOWN:
        default:            return "UNKNOWN";
    }
}

bool string_to_event_type(const std::string& str, EventType& out_type) {
    if (str == "CREATED") {
        out_type = CREATED;
        return true;
    } else if (str == "MODIFIED") {
        out_type = MODIFIED;
        return true;
    } else if (str == "DELETED") {
        out_type = DELETED;
        return true;
    } else if (str == "MOVED") {
        out_type = MOVED;
        return true;
    } else if (str == "PERM_CHANGED") {
        out_type = PERM_CHANGED;
        return true;
    } else if (str == "OWNER_CHANGED") {
        out_type = OWNER_CHANGED;
        return true;
    } else if (str == "UNKNOWN") {
        out_type = UNKNOWN;
        return true;
    }
    out_type = UNKNOWN;
    return false;
}

std::string severity_to_string(Severity severity) {
    switch (severity) {
        case INFO:     return "INFO";
        case WARNING:  return "WARNING";
        case CRITICAL: return "CRITICAL";
        default:       return "INFO";
    }
}

bool string_to_severity(const std::string& str, Severity& out_severity) {
    if (str == "INFO") {
        out_severity = INFO;
        return true;
    } else if (str == "WARNING") {
        out_severity = WARNING;
        return true;
    } else if (str == "CRITICAL") {
        out_severity = CRITICAL;
        return true;
    }
    out_severity = INFO;
    return false;
}

std::string escape_field(const std::string& field) {
    std::string out;
    out.reserve(field.size() + 16);
    for (char c : field) {
        if (c == '\\') {
            out.push_back('\\');
            out.push_back('\\');
        } else if (c == '\t') {
            out.push_back('\\');
            out.push_back('t');
        } else if (c == '\n') {
            out.push_back('\\');
            out.push_back('n');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

std::string unescape_field(const std::string& field) {
    std::string out;
    out.reserve(field.size());
    for (size_t i = 0; i < field.size(); ++i) {
        if (field[i] == '\\' && i + 1 < field.size()) {
            char next = field[i + 1];
            if (next == '\\') {
                out.push_back('\\');
                ++i;
            } else if (next == 't') {
                out.push_back('\t');
                ++i;
            } else if (next == 'n') {
                out.push_back('\n');
                ++i;
            } else {
                out.push_back(field[i]);
            }
        } else {
            out.push_back(field[i]);
        }
    }
    return out;
}

static std::vector<std::string> split_tsv(const std::string& line) {
    std::vector<std::string> tokens;
    size_t start = 0;
    while (start <= line.size()) {
        size_t pos = line.find('\t', start);
        if (pos == std::string::npos) {
            tokens.push_back(line.substr(start));
            break;
        } else {
            tokens.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }
    }
    return tokens;
}

std::string baseline_record_to_line(const BaselineRecord& rec) {
    std::ostringstream oss;
    oss << escape_field(rec.path) << '\t'
        << rec.size << '\t'
        << std::oct << rec.mode << std::dec << '\t'
        << rec.uid << '\t'
        << rec.gid << '\t'
        << rec.mtime << '\t'
        << rec.ctime << '\t'
        << rec.inode << '\t'
        << escape_field(rec.sha256);
    return oss.str();
}

bool line_to_baseline_record(const std::string& line, BaselineRecord& out_rec) {
    if (line.empty() || line[0] == '#') {
        return false;
    }
    auto tokens = split_tsv(line);
    if (tokens.size() != 9) {
        return false;
    }
    try {
        size_t idx = 0;
        out_rec.path = unescape_field(tokens[0]);

        out_rec.size = static_cast<off_t>(std::stoll(tokens[1], &idx, 10));
        if (idx != tokens[1].size()) return false;

        out_rec.mode = static_cast<mode_t>(std::stoul(tokens[2], &idx, 8));
        if (idx != tokens[2].size()) return false;

        out_rec.uid = static_cast<uid_t>(std::stoul(tokens[3], &idx, 10));
        if (idx != tokens[3].size()) return false;

        out_rec.gid = static_cast<gid_t>(std::stoul(tokens[4], &idx, 10));
        if (idx != tokens[4].size()) return false;

        out_rec.mtime = static_cast<time_t>(std::stoll(tokens[5], &idx, 10));
        if (idx != tokens[5].size()) return false;

        out_rec.ctime = static_cast<time_t>(std::stoll(tokens[6], &idx, 10));
        if (idx != tokens[6].size()) return false;

        out_rec.inode = static_cast<ino_t>(std::stoull(tokens[7], &idx, 10));
        if (idx != tokens[7].size()) return false;

        out_rec.sha256 = unescape_field(tokens[8]);
        return true;
    } catch (...) {
        return false;
    }
}

std::string classified_event_to_line(const ClassifiedEvent& event) {
    std::ostringstream oss;
    std::string old_p = event.ev.old_path.empty() ? "-" : escape_field(event.ev.old_path);
    oss << event.ev.timestamp << '\t'
        << severity_to_string(event.severity) << '\t'
        << event_type_to_string(event.ev.type) << '\t'
        << escape_field(event.ev.path) << '\t'
        << old_p << '\t'
        << escape_field(event.detail);
    return oss.str();
}

bool line_to_classified_event(const std::string& line, ClassifiedEvent& out_event) {
    if (line.empty() || line[0] == '#') {
        return false;
    }
    auto tokens = split_tsv(line);
    if (tokens.size() != 6) {
        return false;
    }
    try {
        size_t idx = 0;
        out_event.ev.timestamp = static_cast<time_t>(std::stoll(tokens[0], &idx, 10));
        if (idx != tokens[0].size()) return false;

        if (!string_to_severity(tokens[1], out_event.severity)) {
            return false;
        }
        if (!string_to_event_type(tokens[2], out_event.ev.type)) {
            return false;
        }

        out_event.ev.path = unescape_field(tokens[3]);
        if (tokens[4] == "-") {
            out_event.ev.old_path = "";
        } else {
            out_event.ev.old_path = unescape_field(tokens[4]);
        }
        out_event.detail = unescape_field(tokens[5]);
        out_event.ev.raw_mask = 0;
        return true;
    } catch (...) {
        return false;
    }
}

std::string format_time(time_t t) {
    struct tm tm_buf;
#if defined(_WIN32)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return std::string(buf);
}
