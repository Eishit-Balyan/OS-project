#ifndef SENTINELFS_COMMON_H
#define SENTINELFS_COMMON_H

/**
 * ============================================================================
 * SentinelFS - Shared Types and Declarations
 * Module Purpose: Common data structures, enumerations, configuration records,
 *                 and serialization contracts shared across all SentinelFS
 *                 modules.
 * Owner: Shared
 * ============================================================================
 */

#include <string>
#include <vector>
#include <cstdint>
#include <ctime>
#include <csignal>
#include <sys/types.h>

// Global shutdown flag set by POSIX signal handlers (SIGINT, SIGTERM).
// Defined in src/main.cpp.
extern volatile sig_atomic_t g_shutdown;

/**
 * EventType: Categorizes filesystem changes captured from inotify.
 */
enum EventType {
    CREATED,
    MODIFIED,
    DELETED,
    MOVED,
    PERM_CHANGED,
    OWNER_CHANGED,
    UNKNOWN
};

/**
 * Severity: Security risk level assigned to a detected event by the classifier.
 */
enum Severity {
    INFO,
    WARNING,
    CRITICAL
};

/**
 * BaselineRecord: Snapshot of file metadata and cryptographic hash.
 * Stored during baseline generation and used for integrity verification.
 */
struct BaselineRecord {
    std::string path;       // Canonical path to the file
    off_t size;             // Size of file in bytes
    mode_t mode;            // POSIX file mode / permissions (octal representation in TSV)
    uid_t uid;              // User ID of file owner
    gid_t gid;              // Group ID of file owner
    time_t mtime;           // Last modification timestamp (epoch seconds)
    time_t ctime;           // Last status change timestamp (epoch seconds)
    ino_t inode;            // Inode number
    std::string sha256;     // Hexadecimal SHA-256 digest string
};

/**
 * Event: Normalized filesystem notification event produced by the monitor.
 */
struct Event {
    time_t timestamp;       // Timestamp when event was observed (epoch seconds)
    std::string path;       // Target file/directory path
    std::string old_path;   // Source path if moved or renamed
    EventType type;         // Normalized event type
    uint32_t raw_mask;      // Raw inotify event mask
};

/**
 * ClassifiedEvent: Enriched event containing security assessment and human-readable detail.
 */
struct ClassifiedEvent {
    Event ev;               // The underlying filesystem event
    Severity severity;      // Calculated security severity
    std::string detail;     // Descriptive explanation of anomaly or change
};

/**
 * Config: Runtime configuration container holding directories, patterns, and thresholds.
 */
struct Config {
    std::vector<std::string> protected_dirs;  // List of monitored directory paths
    std::vector<std::string> ignore_patterns; // Wildcard patterns to exclude
    std::vector<std::string> critical_paths;  // High-sensitivity paths triggering CRITICAL severity
    int worker_count;                         // Number of worker consumer threads
    int queue_capacity;                       // Capacity of bounded in-memory event queue
    int burst_threshold;                      // Anomaly alert threshold for rapid changes
    int burst_window_sec;                     // Time window (seconds) for burst calculation
};

// Returns a Config initialized with default values
Config default_config();

// Converts EventType to string representation
std::string event_type_to_string(EventType type);

// Parses string into EventType; returns false on invalid input
bool string_to_event_type(const std::string& str, EventType& out_type);

// Converts Severity to string representation
std::string severity_to_string(Severity severity);

// Parses string into Severity; returns false on invalid input
bool string_to_severity(const std::string& str, Severity& out_severity);

// Escapes backslash, tab, and newline for TSV storage
std::string escape_field(const std::string& field);

// Unescapes backslash sequences back into raw bytes
std::string unescape_field(const std::string& field);

// Serializes BaselineRecord into a single TSV line (9 fields)
std::string baseline_record_to_line(const BaselineRecord& rec);

// Parses a TSV line into a BaselineRecord; returns false if malformed
bool line_to_baseline_record(const std::string& line, BaselineRecord& out_rec);

// Serializes ClassifiedEvent into a single TSV line (6 fields)
std::string classified_event_to_line(const ClassifiedEvent& event);

// Parses a TSV line into a ClassifiedEvent; returns false if malformed
bool line_to_classified_event(const std::string& line, ClassifiedEvent& out_event);

// Formats epoch timestamp to local "YYYY-MM-DD HH:MM:SS"
std::string format_time(time_t t);

#endif // SENTINELFS_COMMON_H
