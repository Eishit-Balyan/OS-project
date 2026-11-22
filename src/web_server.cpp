/**
 * ============================================================================
 * Warden - Decoupled HTTP API & Forensic Web Ledger Server
 * Module Purpose: Standalone C++17 POSIX socket HTTP server serving JSON APIs,
 *                 Server-Sent Events (SSE) tailing events.log, CSV exports,
 *                 and offline static forensic ledger frontend files.
 * ============================================================================
 */

#include "web_server.h"
#include "common.h"
#include "config.h"
#include "baseline.h"
#include "logger.h"
#include "report.h"
#include "ui.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <ctime>

#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/evp.h>

extern volatile sig_atomic_t g_shutdown;

// Connection limit tracking
static pthread_mutex_t g_conn_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_active_connections = 0;

// Escape strings for JSON output
std::string json_escape(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 16);
    size_t i = 0;
    size_t len = input.size();

    while (i < len) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c == '"') {
            out += "\\\"";
            i++;
        } else if (c == '\\') {
            out += "\\\\";
            i++;
        } else if (c == '\b') {
            out += "\\b";
            i++;
        } else if (c == '\f') {
            out += "\\f";
            i++;
        } else if (c == '\n') {
            out += "\\n";
            i++;
        } else if (c == '\r') {
            out += "\\r";
            i++;
        } else if (c == '\t') {
            out += "\\t";
            i++;
        } else if (c < 0x20) {
            char hex[8];
            snprintf(hex, sizeof(hex), "\\u%04x", c);
            out += hex;
            i++;
        } else if (c < 0x80) {
            out += static_cast<char>(c);
            i++;
        } else {
            // Multi-byte UTF-8 validation
            int extra = 0;
            if ((c & 0xE0) == 0xC0) extra = 1;
            else if ((c & 0xF0) == 0xE0) extra = 2;
            else if ((c & 0xF8) == 0xF0) extra = 3;
            else extra = -1;

            bool valid = (extra > 0 && (i + extra < len));
            if (valid) {
                for (int j = 1; j <= extra; ++j) {
                    if ((static_cast<unsigned char>(input[i + j]) & 0xC0) != 0x80) {
                        valid = false;
                        break;
                    }
                }
            }

            if (valid) {
                for (int j = 0; j <= extra; ++j) {
                    out += input[i + j];
                }
                i += 1 + extra;
            } else {
                // Invalid UTF-8 replaced with U+FFFD (UTF-8: \xEF\xBF\xBD)
                out += "\xEF\xBF\xBD";
                i++;
            }
        }
    }
    return out;
}

// URL decoding utility
static std::string url_decode(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            char h1 = in[i + 1];
            char h2 = in[i + 2];
            int v1 = (h1 >= '0' && h1 <= '9') ? (h1 - '0') :
                     (h1 >= 'a' && h1 <= 'f') ? (h1 - 'a' + 10) :
                     (h1 >= 'A' && h1 <= 'F') ? (h1 - 'A' + 10) : -1;
            int v2 = (h2 >= '0' && h2 <= '9') ? (h2 - '0') :
                     (h2 >= 'a' && h2 <= 'f') ? (h2 - 'a' + 10) :
                     (h2 >= 'A' && h2 <= 'F') ? (h2 - 'A' + 10) : -1;
            if (v1 >= 0 && v2 >= 0) {
                out += static_cast<char>((v1 << 4) | v2);
                i += 2;
                continue;
            }
        } else if (in[i] == '+') {
            out += ' ';
            continue;
        }
        out += in[i];
    }
    return out;
}

// Parse query string into key-value map
static std::unordered_map<std::string, std::string> parse_query(const std::string& qs) {
    std::unordered_map<std::string, std::string> params;
    size_t start = 0;
    while (start < qs.size()) {
        size_t amp = qs.find('&', start);
        std::string pair = (amp == std::string::npos) ? qs.substr(start) : qs.substr(start, amp - start);
        size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            std::string key = url_decode(pair.substr(0, eq));
            std::string val = url_decode(pair.substr(eq + 1));
            params[key] = val;
        } else if (!pair.empty()) {
            params[url_decode(pair)] = "";
        }
        if (amp == std::string::npos) break;
        start = amp + 1;
    }
    return params;
}

// Resolve static files directory
static std::string resolve_web_dir(const std::string& config_web_dir) {
    if (!config_web_dir.empty()) {
        return config_web_dir;
    }
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        std::string p(buf);
        size_t last_slash = p.rfind('/');
        if (last_slash != std::string::npos) {
            return p.substr(0, last_slash) + "/web";
        }
    }
    return "./web";
}

// MIME type detection
static std::string get_mime_type(const std::string& path) {
    size_t dot = path.rfind('.');
    if (dot != std::string::npos) {
        std::string ext = path.substr(dot);
        if (ext == ".html" || ext == ".htm") return "text/html; charset=utf-8";
        if (ext == ".css") return "text/css; charset=utf-8";
        if (ext == ".js") return "application/javascript; charset=utf-8";
        if (ext == ".json") return "application/json; charset=utf-8";
        if (ext == ".svg") return "image/svg+xml";
        if (ext == ".woff2") return "font/woff2";
        if (ext == ".woff") return "font/woff";
        if (ext == ".ttf") return "font/ttf";
        if (ext == ".csv") return "text/csv; charset=utf-8";
        if (ext == ".ico") return "image/x-icon";
        if (ext == ".png") return "image/png";
        if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
        if (ext == ".txt") return "text/plain; charset=utf-8";
    }
    return "application/octet-stream";
}

// SHA256 helper for baseline database
static bool compute_file_sha256(const std::string& path, std::string& out_hex) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        close(fd);
        return false;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        close(fd);
        return false;
    }

    const size_t CHUNK = 64 * 1024;
    std::vector<unsigned char> buf(CHUNK);
    ssize_t n = 0;
    while ((n = read(fd, buf.data(), CHUNK)) > 0) {
        if (EVP_DigestUpdate(ctx, buf.data(), static_cast<size_t>(n)) != 1) {
            EVP_MD_CTX_free(ctx);
            close(fd);
            return false;
        }
    }
    close(fd);

    if (n < 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < md_len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md[i]);
    }
    out_hex = oss.str();
    return true;
}

// Internal event representation with byte offset ID
struct ParsedLogEvent {
    uint64_t id = 0; // byte offset of line in events.log
    time_t ts = 0;
    std::string severity;
    std::string type;
    std::string path;
    std::string old_path;
    std::string detail;
};

// Parse a single TSV line into ParsedLogEvent
static bool parse_tsv_line(const std::string& line, uint64_t byte_id, ParsedLogEvent& out) {
    if (line.empty() || line[0] == '#') return false;
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= line.size()) {
        size_t pos = line.find('\t', start);
        if (pos == std::string::npos) {
            parts.push_back(line.substr(start));
            break;
        } else {
            parts.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }
    }
    if (parts.size() != 6) return false;

    try {
        out.id = byte_id;
        out.ts = static_cast<time_t>(std::stoll(parts[0]));
        out.severity = parts[1];
        out.type = parts[2];
        out.path = unescape_field(parts[3]);
        out.old_path = (parts[4] == "-") ? "" : unescape_field(parts[4]);
        out.detail = unescape_field(parts[5]);
        return true;
    } catch (...) {
        return false;
    }
}

// Read and parse events.log
static std::vector<ParsedLogEvent> read_all_events(const std::string& log_path) {
    std::vector<ParsedLogEvent> events;
    int fd = open(log_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return events;

    std::string buffer;
    const size_t CHUNK = 64 * 1024;
    std::vector<char> chunk(CHUNK);
    ssize_t bytes = 0;
    uint64_t current_file_offset = 0;
    uint64_t line_start_offset = 0;

    while ((bytes = read(fd, chunk.data(), CHUNK)) > 0) {
        for (ssize_t i = 0; i < bytes; ++i) {
            char c = chunk[i];
            if (c == '\n') {
                ParsedLogEvent ev;
                if (parse_tsv_line(buffer, line_start_offset, ev)) {
                    events.push_back(ev);
                }
                buffer.clear();
                line_start_offset = current_file_offset + i + 1;
            } else {
                buffer.push_back(c);
            }
        }
        current_file_offset += bytes;
    }

    if (!buffer.empty()) {
        ParsedLogEvent ev;
        if (parse_tsv_line(buffer, line_start_offset, ev)) {
            events.push_back(ev);
        }
    }

    close(fd);
    return events;
}

// Calculate drift count from events.log (distinct files modified/deleted/moved/perm/owner changed)
static size_t calculate_drift_count(const std::vector<ParsedLogEvent>& events) {
    std::unordered_set<std::string> drifted_paths;
    for (const auto& ev : events) {
        if (ev.type == "MODIFIED" || ev.type == "DELETED" || ev.type == "MOVED" ||
            ev.type == "PERM_CHANGED" || ev.type == "OWNER_CHANGED") {
            drifted_paths.insert(ev.path);
        }
    }
    return drifted_paths.size();
}

// Convert ParsedLogEvent to JSON object string
static std::string event_to_json(const ParsedLogEvent& ev) {
    std::ostringstream ss;
    ss << "{"
       << "\"id\":" << ev.id << ","
       << "\"ts\":" << ev.ts << ","
       << "\"severity\":\"" << json_escape(ev.severity) << "\","
       << "\"type\":\"" << json_escape(ev.type) << "\","
       << "\"path\":\"" << json_escape(ev.path) << "\","
       << "\"old_path\":\"" << json_escape(ev.old_path) << "\","
       << "\"detail\":\"" << json_escape(ev.detail) << "\""
       << "}";
    return ss.str();
}

// Send standard HTTP response
static void send_response(int fd, int code, const std::string& status,
                          const std::string& content_type, const std::string& body,
                          const std::string& extra_headers = "") {
    std::ostringstream ss;
    ss << "HTTP/1.1 " << code << " " << status << "\r\n"
       << "Content-Type: " << content_type << "\r\n"
       << "Content-Length: " << body.size() << "\r\n"
       << "Access-Control-Allow-Origin: *\r\n"
       << "Connection: close\r\n";
    if (!extra_headers.empty()) {
        ss << extra_headers;
    }
    ss << "\r\n" << body;

    std::string resp = ss.str();
    ssize_t total = 0;
    while (total < (ssize_t)resp.size()) {
        ssize_t n = write(fd, resp.data() + total, resp.size() - total);
        if (n <= 0) break;
        total += n;
    }
}

// Serve static file
static void serve_static_file(int client_fd, const std::string& resolved_web_dir, const std::string& rel_path) {
    // Path traversal check
    if (rel_path.find("..") != std::string::npos || rel_path.find('\0') != std::string::npos) {
        send_response(client_fd, 403, "Forbidden", "text/plain", "Forbidden");
        return;
    }

    std::string safe_rel = rel_path;
    while (!safe_rel.empty() && safe_rel[0] == '/') {
        safe_rel.erase(0, 1);
    }
    if (safe_rel.empty()) {
        safe_rel = "index.html";
    }

    std::string full_path = resolved_web_dir + "/" + safe_rel;

    struct stat st;
    if (stat(full_path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        send_response(client_fd, 404, "Not Found", "text/plain", "File Not Found");
        return;
    }

    int file_fd = open(full_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (file_fd < 0) {
        send_response(client_fd, 500, "Internal Server Error", "text/plain", "Cannot open file");
        return;
    }

    std::string mime = get_mime_type(full_path);
    std::ostringstream ss;
    ss << "HTTP/1.1 200 OK\r\n"
       << "Content-Type: " << mime << "\r\n"
       << "Content-Length: " << st.st_size << "\r\n"
       << "Access-Control-Allow-Origin: *\r\n"
       << "Connection: close\r\n\r\n";
    std::string hdr = ss.str();
    write(client_fd, hdr.data(), hdr.size());

    char buf[16384];
    ssize_t bytes = 0;
    while ((bytes = read(file_fd, buf, sizeof(buf))) > 0) {
        ssize_t sent = 0;
        while (sent < bytes) {
            ssize_t n = write(client_fd, buf + sent, bytes - sent);
            if (n <= 0) break;
            sent += n;
        }
        if (sent < bytes) break;
    }
    close(file_fd);
}

// Connection worker thread args
struct ClientWorkerArg {
    int client_fd;
    WebServerConfig config;
};

// Route: GET /api/status
static void handle_api_status(int client_fd, const WebServerConfig& config) {
    time_t now = time(nullptr);

    // 1. Daemon check via pidfile + kill(pid, 0)
    pid_t daemon_pid = 0;
    bool is_running = false;
    std::string pid_path = config_get_default_dir() + "/warden.pid";
    std::ifstream pid_in(pid_path);
    if (pid_in.is_open()) {
        pid_in >> daemon_pid;
        pid_in.close();
        if (daemon_pid > 0 && kill(daemon_pid, 0) == 0) {
            is_running = true;
        }
    }

    long threads = 0;
    long rss_kb = 0;
    long daemon_uptime_sec = 0;

    if (is_running) {
        // Read /proc/<pid>/status
        std::string proc_status = "/proc/" + std::to_string(daemon_pid) + "/status";
        std::ifstream proc_in(proc_status);
        if (proc_in.is_open()) {
            std::string line;
            while (std::getline(proc_in, line)) {
                if (line.rfind("Threads:", 0) == 0) {
                    try { threads = std::stol(line.substr(8)); } catch (...) {}
                } else if (line.rfind("VmRSS:", 0) == 0) {
                    try { rss_kb = std::stol(line.substr(6)); } catch (...) {}
                }
            }
        }

        // Read /proc/<pid>/stat for start time and uptime
        std::string proc_stat = "/proc/" + std::to_string(daemon_pid) + "/stat";
        std::ifstream stat_in(proc_stat);
        if (stat_in.is_open()) {
            std::string token;
            int idx = 1;
            long long starttime_ticks = 0;
            while (stat_in >> token && idx <= 22) {
                if (idx == 22) {
                    try { starttime_ticks = std::stoll(token); } catch (...) {}
                }
                idx++;
            }
            if (starttime_ticks > 0) {
                std::ifstream up_in("/proc/uptime");
                double sys_uptime = 0.0;
                if (up_in >> sys_uptime) {
                    long clk_tck = sysconf(_SC_CLK_TCK);
                    if (clk_tck > 0) {
                        double process_start_sec = static_cast<double>(starttime_ticks) / clk_tck;
                        daemon_uptime_sec = static_cast<long>(sys_uptime - process_start_sec);
                        if (daemon_uptime_sec < 0) daemon_uptime_sec = 0;
                    }
                }
            }
        }
    }

    // 2. Read ~/.warden/stats.json
    std::string stats_path = config_get_default_dir() + "/stats.json";
    bool has_live_stats = false;
    long stats_age_sec = -1;
    std::string raw_stats_json = "{}";

    struct stat stats_st;
    if (stat(stats_path.c_str(), &stats_st) == 0) {
        stats_age_sec = (now >= stats_st.st_mtime) ? (now - stats_st.st_mtime) : 0;
        if (stats_age_sec <= 3) {
            std::ifstream sin(stats_path);
            if (sin.is_open()) {
                std::stringstream buffer;
                buffer << sin.rdbuf();
                std::string content = buffer.str();
                if (!content.empty()) {
                    has_live_stats = true;
                    raw_stats_json = content;
                }
            }
        }
    }

    // 3. Protected roots from config
    Config cfg;
    config_load(config_get_default_path(), cfg);

    // 4. Baseline database & sidecar SHA256 check
    std::string baseline_path = baseline_get_default_path();
    std::string seal = "missing";
    time_t baseline_created = 0;
    size_t baseline_file_count = 0;
    std::string baseline_hash = "";

    struct stat bst;
    if (stat(baseline_path.c_str(), &bst) == 0) {
        baseline_created = bst.st_mtime;
        // Count baseline files
        std::ifstream b_in(baseline_path);
        std::string bline;
        while (std::getline(b_in, bline)) {
            if (!bline.empty() && bline[0] != '#') {
                baseline_file_count++;
            }
        }

        std::string actual_hash;
        if (compute_file_sha256(baseline_path, actual_hash)) {
            baseline_hash = actual_hash;
            std::string sidecar_path = baseline_path + ".sha256";
            std::ifstream sc_in(sidecar_path);
            if (sc_in.is_open()) {
                std::string expected_hash;
                sc_in >> expected_hash;
                if (!expected_hash.empty() && expected_hash == actual_hash) {
                    seal = "sealed";
                } else {
                    seal = "tampered";
                }
            } else {
                seal = "tampered";
            }
        } else {
            seal = "tampered";
        }
    }

    // Compute drift count from events.log
    auto all_events = read_all_events(logger_get_default_path());
    size_t drift_count = calculate_drift_count(all_events);

    // Build JSON output
    std::ostringstream ss;
    ss << "{\n"
       << "  \"daemon\": {\n"
       << "    \"running\": " << (is_running ? "true" : "false") << ",\n"
       << "    \"pid\": " << daemon_pid << ",\n"
       << "    \"uptime_sec\": " << daemon_uptime_sec << ",\n"
       << "    \"threads\": " << threads << ",\n"
       << "    \"rss_kb\": " << rss_kb << "\n"
       << "  },\n"
       << "  \"stats\": {\n"
       << "    \"has_live_stats\": " << (has_live_stats ? "true" : "false") << ",\n"
       << "    \"stats_age_sec\": " << stats_age_sec << ",\n"
       << "    \"data\": " << raw_stats_json << "\n"
       << "  },\n"
       << "  \"protected_roots\": [";
    for (size_t i = 0; i < cfg.protected_dirs.size(); ++i) {
        ss << "\"" << json_escape(cfg.protected_dirs[i]) << "\"";
        if (i + 1 < cfg.protected_dirs.size()) ss << ", ";
    }
    ss << "],\n"
       << "  \"burst_config\": {\n"
       << "    \"threshold\": " << cfg.burst_threshold << ",\n"
       << "    \"window_sec\": " << cfg.burst_window_sec << ",\n"
       << "    \"rate_threshold\": " << (cfg.burst_window_sec > 0 ? (static_cast<double>(cfg.burst_threshold) / cfg.burst_window_sec) : 0.0) << "\n"
       << "  },\n"
       << "  \"baseline\": {\n"
       << "    \"seal\": \"" << seal << "\",\n"
       << "    \"created\": " << baseline_created << ",\n"
       << "    \"files\": " << baseline_file_count << ",\n"
       << "    \"hash\": \"" << baseline_hash << "\",\n"
       << "    \"drift_count\": " << drift_count << "\n"
       << "  },\n"
       << "  \"server\": {\n"
       << "    \"port\": " << config.port << ",\n"
       << "    \"web_dir\": \"" << json_escape(resolve_web_dir(config.web_dir)) << "\"\n"
       << "  }\n"
       << "}\n";

    send_response(client_fd, 200, "OK", "application/json; charset=utf-8", ss.str());
}

// Route: GET /api/events
static void handle_api_events(int client_fd, const std::unordered_map<std::string, std::string>& query) {
    auto events = read_all_events(logger_get_default_path());

    std::string f_type = query.count("type") ? query.at("type") : "";
    std::string f_sev = query.count("severity") ? query.at("severity") : "";
    std::string f_path = query.count("path") ? query.at("path") : "";
    std::string f_since = query.count("since") ? query.at("since") : "";
    std::string f_limit = query.count("limit") ? query.at("limit") : "";
    std::string f_before = query.count("before") ? query.at("before") : "";
    std::string f_after = query.count("after") ? query.at("after") : "";

    time_t since_ts = 0;
    if (!f_since.empty()) {
        since_ts = report_parse_since(f_since);
        if (since_ts == 0) {
            try { since_ts = std::stoll(f_since); } catch (...) {}
        }
    }

    uint64_t before_id = 0;
    if (!f_before.empty()) {
        try { before_id = std::stoull(f_before); } catch (...) {}
    }

    uint64_t after_id = 0;
    if (!f_after.empty()) {
        try { after_id = std::stoull(f_after); } catch (...) {}
    }

    size_t limit = 50;
    if (!f_limit.empty()) {
        try { limit = std::stoul(f_limit); } catch (...) {}
    }

    // Filter events
    std::vector<ParsedLogEvent> filtered;
    for (const auto& ev : events) {
        if (before_id > 0 && ev.id >= before_id) continue;
        if (after_id > 0 && ev.id <= after_id) continue;
        if (!f_type.empty() && ev.type != f_type) continue;
        if (!f_sev.empty() && ev.severity != f_sev) continue;
        if (since_ts > 0 && ev.ts < since_ts) continue;
        if (!f_path.empty() && ev.path.find(f_path) == std::string::npos &&
            ev.old_path.find(f_path) == std::string::npos) continue;

        filtered.push_back(ev);
    }

    // Sort newest first
    std::reverse(filtered.begin(), filtered.end());

    if (limit > 0 && filtered.size() > limit) {
        filtered.resize(limit);
    }

    std::ostringstream ss;
    ss << "[\n";
    for (size_t i = 0; i < filtered.size(); ++i) {
        ss << "  " << event_to_json(filtered[i]);
        if (i + 1 < filtered.size()) ss << ",";
        ss << "\n";
    }
    ss << "]\n";

    send_response(client_fd, 200, "OK", "application/json; charset=utf-8", ss.str());
}

// Route: GET /api/summary
static void handle_api_summary(int client_fd, const std::unordered_map<std::string, std::string>& query) {
    auto events = read_all_events(logger_get_default_path());

    std::string f_since = query.count("since") ? query.at("since") : "";
    time_t since_ts = 0;
    if (!f_since.empty()) {
        since_ts = report_parse_since(f_since);
        if (since_ts == 0) {
            try { since_ts = std::stoll(f_since); } catch (...) {}
        }
    }

    time_t now = time(nullptr);
    std::unordered_map<std::string, size_t> type_counts;
    std::unordered_map<std::string, size_t> sev_counts;
    std::unordered_map<std::string, size_t> path_counts;
    std::map<time_t, size_t> hourly_buckets;
    int events_last_60s[60] = {0};
    size_t drift_count = 0;
    std::unordered_set<std::string> drifted_paths;

    size_t total_matched = 0;
    for (const auto& ev : events) {
        if (since_ts > 0 && ev.ts < since_ts) continue;
        total_matched++;

        type_counts[ev.type]++;
        sev_counts[ev.severity]++;
        path_counts[ev.path]++;

        // Hourly bucket (round down to hour)
        time_t hour_key = (ev.ts / 3600) * 3600;
        hourly_buckets[hour_key]++;

        // Last 60 seconds
        if (ev.ts <= now && ev.ts > (now - 60)) {
            int sec_ago = static_cast<int>(now - ev.ts); // 0 .. 59
            if (sec_ago >= 0 && sec_ago < 60) {
                events_last_60s[59 - sec_ago]++;
            }
        }

        if (ev.type == "MODIFIED" || ev.type == "DELETED" || ev.type == "MOVED" ||
            ev.type == "PERM_CHANGED" || ev.type == "OWNER_CHANGED") {
            drifted_paths.insert(ev.path);
        }
    }
    drift_count = drifted_paths.size();

    // Top 5 paths
    std::vector<std::pair<std::string, size_t>> sorted_paths(path_counts.begin(), path_counts.end());
    std::sort(sorted_paths.begin(), sorted_paths.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });
    if (sorted_paths.size() > 5) sorted_paths.resize(5);

    std::ostringstream ss;
    ss << "{\n"
       << "  \"total_events\": " << total_matched << ",\n"
       << "  \"drift_count\": " << drift_count << ",\n"
       << "  \"counts_by_type\": {\n";
    size_t t_idx = 0;
    for (const auto& pair : type_counts) {
        ss << "    \"" << json_escape(pair.first) << "\": " << pair.second;
        if (++t_idx < type_counts.size()) ss << ",";
        ss << "\n";
    }
    ss << "  },\n"
       << "  \"counts_by_severity\": {\n";
    size_t s_idx = 0;
    for (const auto& pair : sev_counts) {
        ss << "    \"" << json_escape(pair.first) << "\": " << pair.second;
        if (++s_idx < sev_counts.size()) ss << ",";
        ss << "\n";
    }
    ss << "  },\n"
       << "  \"top_paths\": [\n";
    for (size_t i = 0; i < sorted_paths.size(); ++i) {
        ss << "    {\"path\": \"" << json_escape(sorted_paths[i].first)
           << "\", \"count\": " << sorted_paths[i].second << "}";
        if (i + 1 < sorted_paths.size()) ss << ",";
        ss << "\n";
    }
    ss << "  ],\n"
       << "  \"pulse_60s\": [";
    for (int i = 0; i < 60; ++i) {
        ss << events_last_60s[i];
        if (i + 1 < 60) ss << ", ";
    }
    ss << "],\n"
       << "  \"hourly\": [\n";
    size_t h_idx = 0;
    for (const auto& pair : hourly_buckets) {
        ss << "    {\"timestamp\": " << pair.first << ", \"count\": " << pair.second << "}";
        if (++h_idx < hourly_buckets.size()) ss << ",";
        ss << "\n";
    }
    ss << "  ]\n"
       << "}\n";

    send_response(client_fd, 200, "OK", "application/json; charset=utf-8", ss.str());
}

// Route: GET /api/export.csv
static void handle_api_export_csv(int client_fd, const std::unordered_map<std::string, std::string>& query) {
    auto events = read_all_events(logger_get_default_path());

    std::string f_type = query.count("type") ? query.at("type") : "";
    std::string f_sev = query.count("severity") ? query.at("severity") : "";
    std::string f_path = query.count("path") ? query.at("path") : "";
    std::string f_since = query.count("since") ? query.at("since") : "";

    time_t since_ts = 0;
    if (!f_since.empty()) {
        since_ts = report_parse_since(f_since);
        if (since_ts == 0) {
            try { since_ts = std::stoll(f_since); } catch (...) {}
        }
    }

    std::ostringstream ss;
    ss << "id,timestamp,datetime,severity,type,path,old_path,detail\n";

    // Newest first
    for (auto it = events.rbegin(); it != events.rend(); ++it) {
        if (!f_type.empty() && it->type != f_type) continue;
        if (!f_sev.empty() && it->severity != f_sev) continue;
        if (since_ts > 0 && it->ts < since_ts) continue;
        if (!f_path.empty() && it->path.find(f_path) == std::string::npos &&
            it->old_path.find(f_path) == std::string::npos) continue;

        ss << it->id << ","
           << it->ts << ","
           << "\"" << format_time(it->ts) << "\","
           << "\"" << it->severity << "\","
           << "\"" << it->type << "\","
           << "\"" << it->path << "\","
           << "\"" << it->old_path << "\","
           << "\"" << it->detail << "\"\n";
    }

    std::string extra = "Content-Disposition: attachment; filename=\"warden-events.csv\"\r\n";
    send_response(client_fd, 200, "OK", "text/csv; charset=utf-8", ss.str(), extra);
}

// Route: GET /api/report.html
static void handle_api_report_html(int client_fd) {
    std::vector<ClassifiedEvent> all_events;
    report_load_events(logger_get_default_path(), all_events);

    std::string tmp_path = config_get_default_dir() + "/web_report_tmp_" + std::to_string(getpid()) + ".html";
    if (report_export_html(tmp_path, all_events)) {
        std::ifstream in(tmp_path);
        std::stringstream ss;
        ss << in.rdbuf();
        in.close();
        unlink(tmp_path.c_str());
        send_response(client_fd, 200, "OK", "text/html; charset=utf-8", ss.str());
    } else {
        send_response(client_fd, 500, "Internal Server Error", "text/plain", "Report generation failed");
    }
}

// Route: GET /api/stream (Server-Sent Events)
static void handle_api_stream(int client_fd) {
    std::string headers =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n\r\n";

    if (write(client_fd, headers.data(), headers.size()) <= 0) {
        return;
    }

    std::string log_path = logger_get_default_path();
    int log_fd = open(log_path.c_str(), O_RDONLY | O_CLOEXEC);
    off_t current_offset = 0;
    ino_t current_inode = 0;

    if (log_fd >= 0) {
        struct stat st;
        if (fstat(log_fd, &st) == 0) {
            current_inode = st.st_ino;
            current_offset = lseek(log_fd, 0, SEEK_END);
        }
    }

    time_t last_heartbeat = time(nullptr);
    std::string line_buf;

    while (!g_shutdown) {
        // Poll client connection
        struct pollfd pfd;
        pfd.fd = client_fd;
        pfd.events = POLLOUT | POLLERR | POLLHUP | POLLRDHUP;
        int pret = poll(&pfd, 1, 500);
        if (pret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLRDHUP)) {
            break; // Client closed connection
        }

        time_t now = time(nullptr);

        // Send 15s heartbeat comment
        if (now - last_heartbeat >= 15) {
            const char* hb = ": heartbeat\n\n";
            if (write(client_fd, hb, strlen(hb)) <= 0) break;
            last_heartbeat = now;
        }

        // Check if log file exists / was rotated / truncated
        struct stat st;
        if (stat(log_path.c_str(), &st) == 0) {
            if (log_fd < 0 || st.st_ino != current_inode || st.st_size < current_offset) {
                if (log_fd >= 0) close(log_fd);
                log_fd = open(log_path.c_str(), O_RDONLY | O_CLOEXEC);
                current_offset = 0;
                if (log_fd >= 0) {
                    current_inode = st.st_ino;
                }
            }
        } else {
            if (log_fd >= 0) {
                close(log_fd);
                log_fd = -1;
            }
        }

        // Read newly appended log events
        if (log_fd >= 0) {
            lseek(log_fd, current_offset, SEEK_SET);
            char read_buf[4096];
            ssize_t n = read(log_fd, read_buf, sizeof(read_buf));
            if (n > 0) {
                for (ssize_t i = 0; i < n; ++i) {
                    char c = read_buf[i];
                    if (c == '\n') {
                        uint64_t ev_id = current_offset - line_buf.size();
                        ParsedLogEvent ev;
                        if (parse_tsv_line(line_buf, ev_id, ev)) {
                            std::string sse_msg = "event: entry\ndata: " + event_to_json(ev) + "\n\n";
                            if (write(client_fd, sse_msg.data(), sse_msg.size()) <= 0) {
                                if (log_fd >= 0) close(log_fd);
                                return;
                            }
                            last_heartbeat = now;
                        }
                        line_buf.clear();
                    } else {
                        line_buf.push_back(c);
                    }
                    current_offset++;
                }
            }
        }
    }

    if (log_fd >= 0) {
        close(log_fd);
    }
}

// Client connection routine (runs in detached pthread)
static void* client_thread_routine(void* arg) {
    std::unique_ptr<ClientWorkerArg> warg(static_cast<ClientWorkerArg*>(arg));
    int client_fd = warg->client_fd;
    WebServerConfig config = warg->config;

    // Set 10-second timeout on client socket for reading request
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    std::string req_buffer;
    char chunk[2048];
    while (req_buffer.find("\r\n\r\n") == std::string::npos && req_buffer.size() < 16384) {
        ssize_t n = read(client_fd, chunk, sizeof(chunk));
        if (n <= 0) break;
        req_buffer.append(chunk, n);
    }

    if (!req_buffer.empty()) {
        std::istringstream req_stream(req_buffer);
        std::string method, raw_uri, version;
        req_stream >> method >> raw_uri >> version;

        if (method != "GET") {
            send_response(client_fd, 405, "Method Not Allowed", "text/plain",
                          "Method Not Allowed", "Allow: GET\r\n");
        } else {
            // Split raw_uri into path and query
            std::string path = raw_uri;
            std::string qs = "";
            size_t qmark = raw_uri.find('?');
            if (qmark != std::string::npos) {
                path = raw_uri.substr(0, qmark);
                qs = raw_uri.substr(qmark + 1);
            }

            auto query = parse_query(qs);

            if (path == "/api/status") {
                handle_api_status(client_fd, config);
            } else if (path == "/api/events") {
                handle_api_events(client_fd, query);
            } else if (path == "/api/stream") {
                handle_api_stream(client_fd);
            } else if (path == "/api/summary") {
                handle_api_summary(client_fd, query);
            } else if (path == "/api/export.csv") {
                handle_api_export_csv(client_fd, query);
            } else if (path == "/api/report.html") {
                handle_api_report_html(client_fd);
            } else {
                // Static file serving from resolved web_dir
                std::string resolved_web = resolve_web_dir(config.web_dir);
                serve_static_file(client_fd, resolved_web, path);
            }
        }
    }

    close(client_fd);

    pthread_mutex_lock(&g_conn_mutex);
    g_active_connections--;
    pthread_mutex_unlock(&g_conn_mutex);

    return nullptr;
}

int web_server_run(const WebServerConfig& config) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cerr << ui_error_mark() << " Failed to create web server socket: "
                  << std::strerror(errno) << "\n";
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv_addr;
    std::memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Strict 127.0.0.1 bind
    serv_addr.sin_port = htons(config.port);

    if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) < 0) {
        std::cerr << ui_error_mark() << " Failed to bind web server to 127.0.0.1:"
                  << config.port << ": " << std::strerror(errno) << "\n";
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, MAX_WEB_CONNECTIONS) < 0) {
        std::cerr << ui_error_mark() << " Failed to listen on socket: "
                  << std::strerror(errno) << "\n";
        close(listen_fd);
        return 1;
    }

    std::string web_dir = resolve_web_dir(config.web_dir);
    std::cout << ui_success_mark() << " Warden Forensic Web Ledger running on http://127.0.0.1:"
              << config.port << "\n"
              << "  -> Static web directory: " << web_dir << "\n"
              << "  -> Cap connections: " << MAX_WEB_CONNECTIONS << "\n"
              << "  -> Bound to loopback 127.0.0.1 only (Press Ctrl+C to exit)\n";

    while (!g_shutdown) {
        struct pollfd pfd;
        pfd.fd = listen_fd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 500); // 500ms timeout for clean SIGINT / g_shutdown check
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) {
            continue; // Timeout, loop back to check g_shutdown
        }

        if (pfd.revents & POLLIN) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(listen_fd, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
            if (client_fd < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                break;
            }

            pthread_mutex_lock(&g_conn_mutex);
            if (g_active_connections >= MAX_WEB_CONNECTIONS) {
                pthread_mutex_unlock(&g_conn_mutex);
                const char* busy =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Retry-After: 1\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 26\r\n"
                    "Connection: close\r\n\r\n"
                    "Server connection cap reached";
                write(client_fd, busy, strlen(busy));
                close(client_fd);
                continue;
            }
            g_active_connections++;
            pthread_mutex_unlock(&g_conn_mutex);

            ClientWorkerArg* warg = new ClientWorkerArg{client_fd, config};
            pthread_t tid;
            if (pthread_create(&tid, nullptr, client_thread_routine, warg) == 0) {
                pthread_detach(tid);
            } else {
                delete warg;
                close(client_fd);
                pthread_mutex_lock(&g_conn_mutex);
                g_active_connections--;
                pthread_mutex_unlock(&g_conn_mutex);
            }
        }
    }

    close(listen_fd);
    std::cout << ui_success_mark() << " Warden Web Server stopped cleanly.\n";
    return 0;
}
