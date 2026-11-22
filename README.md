# Warden

Warden is a real-time file integrity monitoring and tamper detection daemon for Linux. It combines POSIX filesystem metadata observation, recursive directory inotify event streaming, OpenSSL cryptographic baseline verification, multithreaded worker pools, and sliding-window anomaly analysis.

---

## Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        Linux Kernel Filesystem                         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ inotify events
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Filesystem Monitor Loop                         │
│   (inotify_init1 non-blocking, recursive watch map, self-pipe poll)    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Normalized Event structs
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Thread-Safe Bounded Event Queue                    │
│   (POSIX pthread_mutex_t + 2 pthread_cond_t: not_empty, not_full)      │
└───────────────┬───────────────────┬───────────────────┬────────────────┘
                │ pop               │ pop               │ pop
                ▼                   ▼                   ▼
        ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
        │ Worker Thread │   │ Worker Thread │   │ Worker Thread │
        └───────┬───────┘   └───────┬───────┘   └───────┬───────┘
                │                   │                   │
                └───────────────────┼───────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                           Classifier Engine                            │
│  (Recomputes SHA-256 via OpenSSL EVP streaming, filters false alarms,  │
│   detects permission & ownership changes, flags SUID/SGID escalations) │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ ClassifiedEvent (INFO, WARN, CRITICAL)
                                    ▼
        ┌───────────────────────────┴───────────────────────────┐
        ▼                                                       ▼
┌────────────────────────────────┐              ┌────────────────────────────────┐
│   Logger & Alert Dispatcher    │              │       Anomaly Analyzer         │
│  - Append-only TSV events.log  │              │  - Sliding time-window deque   │
│  - ANSI color-coded alerts     │              │  - Rapid tamper burst alerts   │
│  - syslog(LOG_ALERT) dispatch  │              │  - Window repeat suppression   │
└────────────────────────────────┘              └────────────────────────────────┘
```

---

## Build Instructions

### Prerequisites
Install the required C++17 build chain and OpenSSL development headers on Ubuntu / Debian:

```bash
sudo apt update && sudo apt install -y build-essential libssl-dev
```

### Compilation Targets
```bash
make            # Build standard release executable (./warden)
make debug      # Build with debug symbols and no optimizations (-g -O0)
make tsan       # Build with ThreadSanitizer (-fsanitize=thread -g)
make test       # Build all targets and run the test suite
make test-formats # Run data format and serialization tests
make test-queue # Run multithreaded concurrent queue stress test
make clean      # Remove all build artifacts and binaries
```

---

## CLI Usage and Subcommands

| Subcommand | Syntax | Description |
| :--- | :--- | :--- |
| `add` | `./warden add <dir>` | Add directory to protected monitoring list |
| `remove` | `./warden remove <dir>` | Remove directory from protected monitoring list |
| `list` | `./warden list` | List all protected directories and active patterns |
| `baseline` | `./warden baseline` | Establish cryptographic baseline snapshot with sidecar hash |
| `verify` | `./warden verify` | Scan live directories and compare against baseline in parallel |
| `watch` | `./warden watch` | Start real-time monitoring engine with live TUI dashboard |
| `web` | `./warden web [--port P] [--web-dir D]` | Start decoupled Forensic Web Ledger server (default port 8787) |
| `events` | `./warden events [flags]` | Display audit event log with filtering |
| `report` | `./warden report [flags]` | Generate comprehensive audit report with bar charts & export |
| `status` | `./warden status` | View running daemon status, memory, CPU, and diagnostics |

### Filtering Events
```bash
./warden events --severity CRITICAL
./warden events --type MODIFIED --since 30m
./warden events --path /etc --limit 20 --tail
```

### Decoupled Forensic Web Ledger
Warden includes a standalone, zero-framework HTTP server and "Forensic Ledger" browser UI:
```bash
# Run web server on default port 8787 (runs as its own decoupled process)
./warden web

# Or specify custom port and static files directory
./warden web --port 8787 --web-dir ./web
```
- **Access on WSL2 / Windows**: Open `http://localhost:8787` in any browser on your Windows host.
- **Decoupled Architecture**: Reads real files written by the daemon (`~/.warden/events.log`, `stats.json`, `baseline.db`, `/proc/<pid>`). Functions whether or not `watch` is currently active.
- **Zero Mock Data**: When no events exist or the daemon is idle, displays verified empty states ("The ledger is quiet").
- **Live Ingest Streaming**: Real-time updates delivered via Server-Sent Events (SSE) `GET /api/stream` with automatic fallback to polling.

### Comprehensive Reporting & Export
```bash
# Display terminal summary with block charts
./warden report

# Export to CSV and standalone dark-themed HTML
./warden report --csv audit.csv --html audit_report.html
```

---

## Module Ownership

| Module | Owner | Description |
| :--- | :--- | :--- |
| `config` | Aviral | Protected directory management, path validation, nesting rejection, key=value parser |
| `baseline` | Krishna | Recursive scanning, lstat metadata extraction, OpenSSL streaming SHA-256 |
| `monitor` | Eishit | inotify recursive engine, cookie-based move pairing, self-pipe shutdown |
| `event_queue` | Krishna + Ashutosh| Bounded multithreaded queue, POSIX mutex, condition variables, worker pool |
| `classifier` | Ashutosh | Security assessment, false-alarm pruning, permission/ownership differences, critical paths |
| `logger` | Aviral | Mutex-synchronized TSV logger, ANSI console alerts, syslog |
| `analyzer` | Eishit | Sliding-window burst detection, ransomware/mass modification detection |
| `report` | Krishna + Aviral| Log querying, CLI formatting, block charts, CSV and dark-mode HTML export |
| `ui` | Eishit + Ashutosh | TUI box drawing, colored badges, progress bars, live monitoring dashboard |

---

## Integration Test Suite

The test suite covers full system functionality using isolated temporary environments:

| Test ID | Script | Target Functionality Tested |
| :--- | :--- | :--- |
| **T01** | `tests/t01_add_valid_dir.sh` | Add valid existing directory to protection list |
| **T02** | `tests/t02_add_nonexistent_dir.sh` | Rejection and clear error message for nonexistent path |
| **T03** | `tests/t03_baseline_created.sh` | Generation of `baseline.db` and sidecar `baseline.db.sha256` |
| **T04** | `tests/t04_modify_detected.sh` | Inotify capture of file modification and TSV log record |
| **T05** | `tests/t05_create_detected.sh` | File creation event detection and logging |
| **T06** | `tests/t06_delete_detected.sh` | File deletion event detection and logging |
| **T07** | `tests/t07_rename_moved.sh` | Correlation of `IN_MOVED_FROM` and `IN_MOVED_TO` by cookie |
| **T08** | `tests/t08_unchanged_no_violation.sh` | Verification reporting 0 discrepancies on clean state |
| **T09** | `tests/t09_rapid_modifications.sh` | Capture of rapid sequential file modifications |
| **T10** | `tests/t10_queue_stress_drain.sh` | High event volume processing without dropped queues or crashes |
| **T11** | `tests/t11_queue_concurrency.sh` | Concurrent pthread stress test verifying 0 lost / 0 duplicated items |
| **T12** | `tests/t12_unreadable_file.sh` | Graceful handling of unreadable (`chmod 000`) files without crash |
| **T13** | `tests/t13_baseline_restart.sh` | Baseline persistence across restarts and cryptographic verification |
| **T14** | `tests/t14_burst_alert.sh` | Sliding-window anomaly detection for mass-tamper activity |
| **T15** | `tests/t15_sigint_clean_stop.sh` | Graceful SIGINT shutdown, PID file cleanup, no lingering threads |
| **T16** | `tests/t16_events_report.sh` | Query filtering and CSV / HTML export validation |
| **T17** | `tests/t17_web_api.sh` | Decoupled web server API, SSE streaming, tamper detection, traversal rejection |

To run all integration tests:
```bash
make test
```

To run a live demonstration of attack detection:
```bash
# In Terminal 1:
./warden watch

# In Terminal 2:
bash tests/simulate_attack.sh /tmp/demo_protected
```

---

## Known Limitations

1. **Linux Platform Requirement**: Relies directly on Linux kernel inotify (`sys/inotify.h`) and POSIX system calls. Not portable to macOS or native Windows (works under WSL2).
2. **Terminal Dashboard Backup**: The terminal TUI dashboard (`./warden watch`) remains fully operational and untouched as an independent in-terminal monitoring backup.
3. **Log Protection Boundary**: The audit log `events.log` is maintained on the local host with standard filesystem permissions; high-assurance deployments should replicate logs remotely or use an append-only hardware module.
4. **Directory Watch Limits**: The total number of monitored directories is bounded by the Linux kernel `fs.inotify.max_user_watches` system setting. Protect only authorized directories rather than the entire root filesystem.
