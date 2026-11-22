# SentinelFS - Architecture & Design Specification

SentinelFS is a real-time file integrity monitoring and tamper detection daemon for Linux. It combines POSIX filesystem metadata observation, recursive directory inotify event streaming, OpenSSL cryptographic baseline verification, and sliding-window anomaly analysis.

---

## 1. Directory and File Layout

All persistent runtime state, configuration, and audit trails reside under a dedicated directory in the user's home folder:

```text
~/.sentinelfs/
├── config        # Key-value configuration file
├── baseline.db   # Snapshot database of monitored files & cryptographic hashes
└── events.log    # Append-only tab-separated audit log of detected events
```

The home directory path is resolved dynamically at runtime from the `HOME` environment variable, falling back to `getpwuid(getuid())->pw_dir` if `HOME` is unset or empty.

---

## 2. File Formats

### 2.1 Configuration File (`~/.sentinelfs/config`)

The configuration file uses line-oriented `key=value` pairs.
- Empty lines and lines starting with `#` are treated as comments and ignored.
- Leading and trailing whitespace around keys and values is trimmed.
- Repeatable keys (`protected`, `ignore`, `critical`) append entries to their respective lists.

#### Supported Configuration Keys:
- `protected=<abs path>`: Absolute path of a directory to monitor recursively (repeatable).
- `ignore=<glob>`: Filename or wildcard pattern to exclude from monitoring (repeatable).
- `critical=<abs path>`: Absolute path of a high-priority file triggering CRITICAL severity on change (repeatable).
- `worker_count=<int>`: Number of consumer threads in the event processing pool.
- `queue_capacity=<int>`: Maximum capacity of the bounded in-memory event queue.
- `burst_threshold=<int>`: Number of events within the burst window triggering an anomaly alert.
- `burst_window_sec=<int>`: Sliding time window (seconds) for burst detection.

#### Default Settings:
```ini
# SentinelFS Default Configuration
worker_count=4
queue_capacity=1024
burst_threshold=20
burst_window_sec=10

# Default ignore patterns
ignore=*.swp
ignore=*.tmp
ignore=*~

# Default critical security paths
critical=/etc/passwd
critical=/etc/shadow
critical=/etc/sudoers
critical=/etc/ssh/sshd_config
```

---

### 2.2 Baseline Database (`~/.sentinelfs/baseline.db`)

The baseline database stores a cryptographic snapshot of the protected directories.
- Line 1: Header identifying format and version: `#SENTINELFS-BASELINE v1`
- Line 2: Creation timestamp metadata: `#CREATED <epoch>`
- Subsequent lines: One record per file encoded as 9 Tab-Separated Values (TSV).

#### TSV Record Schema (9 Fields):
| Column | Field Name | Format / Representation | Description |
| :--- | :--- | :--- | :--- |
| 1 | `path` | Escaped string | Absolute canonical path to the file |
| 2 | `size` | Decimal integer | File size in bytes (`off_t`) |
| 3 | `mode` | Octal integer | File permissions and type flags (`st_mode`) |
| 4 | `uid` | Decimal integer | User ID of the owner (`uid_t`) |
| 5 | `gid` | Decimal integer | Group ID of the owner (`gid_t`) |
| 6 | `mtime` | Decimal integer (epoch) | Last modification timestamp (`time_t`) |
| 7 | `ctime` | Decimal integer (epoch) | Last inode status change timestamp (`time_t`) |
| 8 | `inode` | Decimal integer | Filesystem inode number (`ino_t`) |
| 9 | `sha256` | Hex string (64 chars) | Streaming OpenSSL SHA-256 digest (`-` for non-regular) |

#### Example Record:
```text
#SENTINELFS-BASELINE v1
#CREATED 1731780000
/etc/passwd	2840	100644	0	0	1731000000	1731000000	131075	b7a8f...
```

---

### 2.3 Event Audit Log (`~/.sentinelfs/events.log`)

The event log is an append-only, mutex-synchronized audit log recording every classified filesystem event. Each line consists of 6 Tab-Separated Values (TSV).

#### TSV Event Schema (6 Fields):
| Column | Field Name | Format / Representation | Description |
| :--- | :--- | :--- | :--- |
| 1 | `timestamp` | Decimal integer (epoch) | Epoch seconds when the event was observed |
| 2 | `severity` | String (`INFO`, `WARNING`, `CRITICAL`) | Security risk classification |
| 3 | `type` | String (`CREATED`, `MODIFIED`, etc.) | Normalized filesystem event type |
| 4 | `path` | Escaped string | Target file or directory path |
| 5 | `old_path` | Escaped string (`-` if none) | Source path for rename/move operations |
| 6 | `detail` | Escaped string | Human-readable explanation of change/anomaly |

#### Example Event Line:
```text
1731780100	CRITICAL	MODIFIED	/etc/passwd	-	Cryptographic hash mismatch (potential unauthorized edit)
```

---

### 2.4 TSV Field Escaping Rules

To ensure reliable parsing across filenames and details containing special characters:
- `\` (backslash) is escaped as `\\`
- `\t` (tab) is escaped as `\t`
- `\n` (newline) is escaped as `\n`

Literal tab characters `\t` serve strictly as field delimiters. Unescaping replaces escape sequences with their respective byte representations in reverse.

---

## 3. Module Interfaces & Contracts

### 3.1 Common (`include/common.h`, `src/common.cpp`)
Provides central data structures, enum definitions, and serialization routines.
- `struct Config`: Global runtime settings container.
- `Config default_config()`: Returns built-in configuration defaults.
- `std::string event_type_to_string(EventType)` / `bool string_to_event_type(...)`
- `std::string severity_to_string(Severity)` / `bool string_to_severity(...)`
- `std::string escape_field(const std::string&)` / `std::string unescape_field(const std::string&)`
- `std::string baseline_record_to_line(const BaselineRecord&)` / `bool line_to_baseline_record(...)`
- `std::string classified_event_to_line(const ClassifiedEvent&)` / `bool line_to_classified_event(...)`
- `std::string format_time(time_t)`: Formats epoch into local `"YYYY-MM-DD HH:MM:SS"`.

---

### 3.2 Baseline Engine (`include/baseline.h`, `src/baseline.cpp`)
Maintains the snapshot of known files.
- `bool baseline_build(const Config& config)`: Scans protected directories and establishes baseline records.
- `bool baseline_load(const std::string& path)`: Loads records from TSV baseline database file.
- `bool baseline_save(const std::string& path)`: Flushes in-memory baseline to disk.
- `bool baseline_lookup(const std::string& path, BaselineRecord& out)`: Finds record by canonical path.
- `void baseline_update(const BaselineRecord& record)`: Inserts or updates an in-memory file record.
- `void baseline_remove(const std::string& path)`: Deletes an entry from baseline records.
- `bool baseline_compute_record(const std::string& path, BaselineRecord& out)`: Performs lstat and OpenSSL EVP SHA-256 calculation.
- **THREAD-SAFETY**: In-memory map is guarded by a single POSIX `pthread_mutex_t` internal to `baseline.cpp`.

---

### 3.3 Filesystem Monitor (`include/monitor.h`, `src/monitor.cpp`)
Manages recursive inotify subscriptions and event generation.
- `bool monitor_start(const Config& config)`: Configures inotify descriptors and watches for all configured protected paths.
- `void monitor_run(EventQueue& queue)`: Main event-producing loop. Reads inotify events and pushes to `queue`; terminates when `g_shutdown` is set.
- `void monitor_stop()`: Awakens monitor loop using self-pipe and tears down watch descriptors.

---

### 3.4 Event Queue & Worker Pool (`include/event_queue.h`, `src/event_queue.cpp`)
Bounded thread-safe producer-consumer queue and worker threads.
- `class EventQueue`:
  - `void push(const Event& ev)`: Enqueues event; blocks while queue is at capacity.
  - `bool pop(Event& out_ev)`: Dequeues event; blocks while empty; returns `false` when shutdown and fully drained.
  - `void shutdown()`: Broadcasts shutdown to unblock all waiting worker threads.
- `bool worker_pool_start(int n, EventQueue& queue, const Config& config)`: Spawns `n` worker pthreads.
- `void worker_pool_stop()`: Shuts down queue and joins all active worker threads.
- **THREAD-SAFETY**: Synchronized using raw POSIX `pthread_mutex_t` and two condition variables (`pthread_cond_t` for `not_empty` and `not_full`).

---

### 3.5 Classifier Engine (`include/classifier.h`, `src/classifier.cpp`)
Evaluates filesystem changes against baseline records and critical paths.
- `ClassifiedEvent classify(const Event& ev, const Config& config)`: Compares event with baseline state and determines `INFO`, `WARNING`, or `CRITICAL` severity.

---

### 3.6 Logger & Alert Dispatcher (`include/logger.h`, `src/logger.cpp`)
Thread-safe audit logging and operator alerting.
- `void log_event(const ClassifiedEvent& event)`: Writes TSV formatted event to `events.log` and renders color-coded alert on stdout/stderr.
- **THREAD-SAFETY**: Synchronized using an internal POSIX `pthread_mutex_t` to prevent garbled concurrent log writes.

---

### 3.7 Anomaly Analyzer (`include/analyzer.h`, `src/analyzer.cpp`)
Detects burst activity patterns (e.g. mass encryption, bulk deletion).
- `void analyzer_record(const ClassifiedEvent& event, const Config& config)`: Tracks event timestamps in sliding-window deque; triggers high-priority alert via logger when threshold within window is exceeded.
- **THREAD-SAFETY**: Synchronized using an internal POSIX `pthread_mutex_t`.

---

### 3.8 Audit Reporting & Export (`include/report.h`, `src/report.cpp`)
Offline log query and export utility.
- `bool report_load_events(const std::string& log_path, std::vector<ClassifiedEvent>& out_events)`: Parses `events.log`.
- `std::vector<ClassifiedEvent> report_filter(const std::vector<ClassifiedEvent>& events, EventType type, Severity min_sev, time_t since, const std::string& path_sub)`: Applies multi-criteria filters.
- `void report_print_table(const std::vector<ClassifiedEvent>& events)`: Prints tabular output.
- `void report_print_summary(const std::vector<ClassifiedEvent>& events)`: Prints statistical summary.
- `bool report_export_csv(const std::string& csv_path, const std::vector<ClassifiedEvent>& events)`: Exports events to CSV format.

---

## 4. Concurrency & Synchronization Model

1. **POSIX Pthreads Exclusively**: No usage of `<thread>` or `<mutex>`.
2. **Global State Restriction**: Only `volatile sig_atomic_t g_shutdown` is globally accessible; all module state is encapsulated behind mutex-guarded C interfaces.
3. **Producer-Consumer Decoupling**: The inotify monitor thread acts as the sole producer pushing into the bounded `EventQueue`. Multiple worker pthreads consume from `EventQueue`, invoke `classify()`, update `baseline`, query `analyzer`, and write to `logger`.
4. **Checked Return Values**: Every POSIX system call (`open`, `read`, `write`, `close`, `lstat`, `inotify_*`, `pthread_*`, `pipe`) must have its return value validated.
