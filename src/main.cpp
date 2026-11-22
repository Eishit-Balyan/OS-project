/**
 * ============================================================================
 * Warden - Main Command Dispatcher & Service Orchestrator
 * Module Purpose: CLI argument parsing, POSIX signal handling (SIGINT/SIGTERM,
 *                 SIGHUP, SIGUSR1), PID file locking, real-time watch loop,
 *                 live TUI dashboard thread, and system diagnostics.
 * ============================================================================
 */

#include "common.h"
#include "config.h"
#include "baseline.h"
#include "monitor.h"
#include "event_queue.h"
#include "classifier.h"
#include "logger.h"
#include "analyzer.h"
#include "report.h"
#include "ui.h"
#include "web_server.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>

#include <unistd.h>
#include <csignal>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>

// Global POSIX signal flags
volatile sig_atomic_t g_shutdown = 0;
volatile sig_atomic_t g_reload_config = 0;
volatile sig_atomic_t g_dump_stats = 0;

#if defined(__GNUC__) || defined(__clang__)
#define NO_TSAN __attribute__((no_sanitize("thread")))
#else
#define NO_TSAN
#endif

NO_TSAN static void handle_posix_signals(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_shutdown = 1;
    } else if (sig == SIGHUP) {
        g_reload_config = 1;
    } else if (sig == SIGUSR1) {
        g_dump_stats = 1;
    }
}

static void setup_signals() {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_posix_signals;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
    sigaction(SIGUSR1, &sa, nullptr);
}

static std::string get_pid_file_path() {
    return config_get_default_dir() + "/warden.pid";
}

static bool check_and_create_pidfile(pid_t& existing_pid) {
    config_ensure_dir_exists();
    std::string pid_path = get_pid_file_path();

    std::ifstream in(pid_path);
    if (in.is_open()) {
        in >> existing_pid;
        in.close();
        // Check if process is actively running
        if (existing_pid > 0 && kill(existing_pid, 0) == 0) {
            return false; // Active instance already running
        }
        // Stale pid file
        unlink(pid_path.c_str());
    }

    std::ofstream out(pid_path);
    if (out.is_open()) {
        out << getpid() << "\n";
        out.close();
        return true;
    }
    return false;
}

static void remove_pidfile() {
    unlink(get_pid_file_path().c_str());
}

static void print_detailed_help(const char* prog) {
    ui_print_banner();
    std::cout << "\nUsage: " << prog << " <command> [options]\n\n"
              << "\033[1;37mPROTECTION CONFIGURATION:\033[0m\n"
              << "  add <dir>                Add directory to protected monitoring list\n"
              << "  remove <dir>             Remove directory from protected list\n"
              << "  list                     List all protected directories and patterns\n\n"
              << "\033[1;37mINTEGRITY & MONITORING:\033[0m\n"
              << "  baseline                 Scan protected directories and establish baseline\n"
              << "  verify                   Verify live filesystem state against baseline\n"
              << "  watch                    Start real-time monitoring daemon & dashboard\n"
              << "  web [--port P] [--web-dir D] Launch Forensic Ledger HTTP server (default port 8787)\n\n"
              << "\033[1;37mAUDIT & REPORTING:\033[0m\n"
              << "  events [flags]           View recent security events log\n"
              << "    --type <TYPE>          Filter by type (CREATED, MODIFIED, DELETED, etc.)\n"
              << "    --severity <SEV>       Filter by severity (INFO, WARNING, CRITICAL)\n"
              << "    --since <duration>     Filter events within window (e.g. 10m, 2h, 1d)\n"
              << "    --path <substr>        Filter by file path substring\n"
              << "    --limit <N>            Show at most N events\n"
              << "    --tail                 Show most recent N events (used with --limit)\n"
              << "  report [flags]           Generate security audit summary report\n"
              << "    --csv <file>           Export audit events to CSV format\n"
              << "    --html <file>          Export self-contained dark-mode HTML report\n"
              << "  status                   Show running daemon status and system health\n"
              << "  help, --help             Display this help message\n\n"
              << "\033[1;37mEXAMPLES:\033[0m\n"
              << "  " << prog << " add /etc\n"
              << "  " << prog << " baseline\n"
              << "  " << prog << " watch\n"
              << "  " << prog << " events --severity CRITICAL --since 1h\n"
              << "  " << prog << " report --html report.html\n"
              << std::endl;
}

static void* stats_writer_thread_routine(void* arg) {
    (void)arg;
    config_ensure_dir_exists();
    std::string stats_path = config_get_default_dir() + "/stats.json";
    std::string tmp_path = stats_path + ".tmp." + std::to_string(getpid());
    size_t last_events = 0;
    time_t last_calc_time = time(nullptr);
    double events_per_sec = 0.0;

    while (!g_shutdown) {
        time_t now = time(nullptr);
        DashboardStats copy;
        pthread_mutex_lock(&g_stats.mutex);
        copy = g_stats;
        pthread_mutex_unlock(&g_stats.mutex);

        time_t uptime = (copy.start_time > 0 && now >= copy.start_time) ? (now - copy.start_time) : 0;
        time_t dt = now - last_calc_time;
        if (dt >= 1) {
            size_t diff = (copy.total_events >= last_events) ? (copy.total_events - last_events) : 0;
            events_per_sec = static_cast<double>(diff) / dt;
            last_events = copy.total_events;
            last_calc_time = now;
        }

        std::ostringstream ss;
        ss << "{\n"
           << "  \"timestamp\": " << now << ",\n"
           << "  \"uptime\": " << uptime << ",\n"
           << "  \"workers\": " << copy.worker_count << ",\n"
           << "  \"queue_depth\": " << copy.queue_depth << ",\n"
           << "  \"queue_capacity\": " << copy.queue_capacity << ",\n"
           << "  \"events_total\": " << copy.total_events << ",\n"
           << "  \"events_per_sec\": " << events_per_sec << ",\n"
           << "  \"counts_by_type\": {\n"
           << "    \"CREATED\": " << copy.counts_by_type[CREATED] << ",\n"
           << "    \"MODIFIED\": " << copy.counts_by_type[MODIFIED] << ",\n"
           << "    \"DELETED\": " << copy.counts_by_type[DELETED] << ",\n"
           << "    \"MOVED\": " << copy.counts_by_type[MOVED] << ",\n"
           << "    \"PERM_CHANGED\": " << copy.counts_by_type[PERM_CHANGED] << ",\n"
           << "    \"OWNER_CHANGED\": " << copy.counts_by_type[OWNER_CHANGED] << "\n"
           << "  },\n"
           << "  \"counts_by_severity\": {\n"
           << "    \"INFO\": " << copy.counts_by_severity[INFO] << ",\n"
           << "    \"WARNING\": " << copy.counts_by_severity[WARNING] << ",\n"
           << "    \"CRITICAL\": " << copy.counts_by_severity[CRITICAL] << "\n"
           << "  }\n"
           << "}\n";

        std::string json = ss.str();
        int fd = open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            ssize_t written = write(fd, json.data(), json.size());
            (void)written;
            close(fd);
            rename(tmp_path.c_str(), stats_path.c_str());
        }

        for (int i = 0; i < 10 && !g_shutdown; ++i) {
            usleep(100000); // 100ms
        }
    }

    unlink(stats_path.c_str());
    unlink(tmp_path.c_str());
    return nullptr;
}

static void* dashboard_thread_routine(void* arg) {
    (void)arg;
    ui_hide_cursor();
    ui_clear_screen();
    while (!g_shutdown) {
        ui_render_dashboard();
        usleep(500000); // Redraw every 500ms
    }
    ui_show_cursor();
    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_detailed_help(argv[0]);
        return 1;
    }

    setup_signals();

    std::string cmd = argv[1];

    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        print_detailed_help(argv[0]);
        return 0;
    }

    if (cmd == "add") {
        if (argc < 3) {
            std::cerr << ui_error_mark() << " Error: 'add' requires a directory path argument.\n"
                      << "Usage: " << argv[0] << " add <dir>\n";
            return 1;
        }
        std::string dir = argv[2];
        Config config;
        config_load(config_get_default_path(), config);
        if (config_add_protected_dir(config, dir)) {
            if (config_save(config_get_default_path(), config)) {
                std::cout << ui_success_mark() << " Successfully added '" << dir
                          << "' to protected directories.\n";
                return 0;
            }
        }
        return 1;
    }

    if (cmd == "remove") {
        if (argc < 3) {
            std::cerr << ui_error_mark() << " Error: 'remove' requires a directory path argument.\n"
                      << "Usage: " << argv[0] << " remove <dir>\n";
            return 1;
        }
        std::string dir = argv[2];
        Config config;
        config_load(config_get_default_path(), config);
        if (config_remove_protected_dir(config, dir)) {
            if (config_save(config_get_default_path(), config)) {
                std::cout << ui_success_mark() << " Successfully removed '" << dir
                          << "' from protected directories.\n";
                return 0;
            }
        }
        return 1;
    }

    if (cmd == "list") {
        Config config;
        config_load(config_get_default_path(), config);
        config_list_protected_dirs(config);
        return 0;
    }

    if (cmd == "baseline") {
        ui_print_banner();
        std::cout << "Initializing baseline generation...\n";
        Config config;
        config_load(config_get_default_path(), config);

        if (config.protected_dirs.empty()) {
            std::cerr << ui_error_mark() << " No protected directories configured! Use '"
                      << argv[0] << " add <dir>' first.\n";
            return 1;
        }

        if (baseline_build(config)) {
            if (baseline_save(baseline_get_default_path())) {
                std::cout << ui_success_mark() << " Baseline saved to "
                          << baseline_get_default_path() << "\n";
                return 0;
            }
        }
        return 1;
    }

    if (cmd == "verify") {
        ui_print_banner();
        Config config;
        config_load(config_get_default_path(), config);

        if (config.protected_dirs.empty()) {
            std::cerr << ui_error_mark() << " No protected directories configured.\n";
            return 1;
        }

        bool clean = baseline_verify_against_disk(config, baseline_get_default_path());
        return clean ? 0 : 2;
    }

    if (cmd == "web") {
        WebServerConfig web_cfg;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--port" && i + 1 < argc) {
                web_cfg.port = std::stoi(argv[++i]);
            } else if (arg == "--web-dir" && i + 1 < argc) {
                web_cfg.web_dir = argv[++i];
            }
        }
        ui_print_banner();
        return web_server_run(web_cfg);
    }

    if (cmd == "watch") {
        pid_t existing_pid = 0;
        if (!check_and_create_pidfile(existing_pid)) {
            std::cerr << ui_error_mark() << " Error: Warden is already running (PID: "
                      << existing_pid << "). Refusing to start second instance.\n";
            return 1;
        }

        Config config;
        config_load(config_get_default_path(), config);

        if (config.protected_dirs.empty()) {
            std::cerr << ui_error_mark() << " Error: No protected directories configured.\n"
                      << "Please run '" << argv[0] << " add <dir>' before starting watch.\n";
            remove_pidfile();
            return 1;
        }

        // Check if baseline exists; if missing, build one
        struct stat st;
        if (stat(baseline_get_default_path().c_str(), &st) != 0) {
            std::cout << ui_badge(WARNING) << " No existing baseline found. Building initial baseline now...\n";
            baseline_build(config);
            baseline_save(baseline_get_default_path());
        } else {
            baseline_load(baseline_get_default_path());
        }

        ui_stats_init();
        g_stats.worker_count = config.worker_count;
        g_stats.queue_capacity = config.queue_capacity;
        g_stats.baseline_files = baseline_get_record_count();

        EventQueue queue(static_cast<size_t>(config.queue_capacity));

        if (!monitor_start(config)) {
            std::cerr << ui_error_mark() << " Failed to start inotify monitor engine.\n";
            remove_pidfile();
            return 1;
        }

        g_stats.dirs_watched = monitor_get_watch_count();

        if (!worker_pool_start(config.worker_count, queue, config)) {
            std::cerr << ui_error_mark() << " Failed to launch worker pool.\n";
            monitor_stop();
            remove_pidfile();
            return 1;
        }

        pthread_t dash_tid = 0;
        bool tty_active = ui_is_tty();
        if (tty_active) {
            ui_set_dashboard_active(true);
            pthread_create(&dash_tid, nullptr, dashboard_thread_routine, nullptr);
        } else {
            ui_set_dashboard_active(false);
            std::cout << "[INFO] Starting Warden in background stream mode (non-TTY)...\n";
        }

        pthread_t stats_tid = 0;
        pthread_create(&stats_tid, nullptr, stats_writer_thread_routine, nullptr);

        // Main event producing loop
        while (!g_shutdown) {
            monitor_run(queue);

            if (g_reload_config) {
                g_reload_config = 0;
                config_load(config_get_default_path(), config);
                std::cout << "[CONFIG] Reloaded configuration from disk.\n";
            }

            if (g_dump_stats) {
                g_dump_stats = 0;
                ui_stats_dump_summary();
            }
        }

        // Clean termination sequence
        ui_set_dashboard_active(false);
        monitor_stop();
        worker_pool_stop();
        queue.shutdown();

        if (tty_active && dash_tid != 0) {
            pthread_join(dash_tid, nullptr);
            ui_clear_screen();
        }

        if (stats_tid != 0) {
            pthread_join(stats_tid, nullptr);
        }

        // Save updated baseline state and remove PID file
        baseline_save(baseline_get_default_path());
        remove_pidfile();

        ui_stats_dump_summary();
        std::cout << ui_success_mark() << " Warden terminated cleanly.\n";
        return 0;
    }

    if (cmd == "events") {
        ReportFilterOptions opts;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--type" && i + 1 < argc) opts.type_str = argv[++i];
            else if (arg == "--severity" && i + 1 < argc) opts.severity_str = argv[++i];
            else if (arg == "--since" && i + 1 < argc) opts.since_str = argv[++i];
            else if (arg == "--path" && i + 1 < argc) opts.path_substring = argv[++i];
            else if (arg == "--limit" && i + 1 < argc) opts.limit = std::stoi(argv[++i]);
            else if (arg == "--tail") opts.tail = true;
        }

        std::vector<ClassifiedEvent> all_events;
        report_load_events(logger_get_default_path(), all_events);
        auto filtered = report_filter(all_events, opts);
        report_print_events_table(filtered, opts.limit, opts.tail);
        return 0;
    }

    if (cmd == "report") {
        std::string csv_file;
        std::string html_file;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--csv" && i + 1 < argc) csv_file = argv[++i];
            else if (arg == "--html" && i + 1 < argc) html_file = argv[++i];
        }

        std::vector<ClassifiedEvent> all_events;
        report_load_events(logger_get_default_path(), all_events);
        report_print_comprehensive_summary(all_events);

        if (!csv_file.empty()) {
            if (report_export_csv(csv_file, all_events)) {
                std::cout << ui_success_mark() << " CSV export saved to: " << csv_file << "\n";
            }
        }
        if (!html_file.empty()) {
            if (report_export_html(html_file, all_events)) {
                std::cout << ui_success_mark() << " HTML report saved to: " << html_file << "\n";
            }
        }
        return 0;
    }

    if (cmd == "status") {
        ui_print_banner();
        pid_t daemon_pid = 0;
        bool is_running = false;
        std::string pid_path = get_pid_file_path();

        std::ifstream in(pid_path);
        if (in.is_open()) {
            in >> daemon_pid;
            in.close();
            if (daemon_pid > 0 && kill(daemon_pid, 0) == 0) {
                is_running = true;
            }
        }

        std::vector<std::string> lines;
        lines.push_back("Status:        " + std::string(is_running ? "\033[1;32mRUNNING (active)\033[0m" : "\033[1;31mSTOPPED (inactive)\033[0m"));
        if (is_running) {
            lines.push_back("Daemon PID:    " + std::to_string(daemon_pid));

            // Query /proc/<pid>/status for memory and threads
            std::string proc_status = "/proc/" + std::to_string(daemon_pid) + "/status";
            std::ifstream proc_in(proc_status);
            if (proc_in.is_open()) {
                std::string pline;
                while (std::getline(proc_in, pline)) {
                    if (pline.rfind("VmRSS:", 0) == 0) lines.push_back("Memory (RSS):  " + pline.substr(6));
                    if (pline.rfind("Threads:", 0) == 0) lines.push_back("Active Threads: " + pline.substr(8));
                }
            }
        }

        Config config;
        config_load(config_get_default_path(), config);
        lines.push_back("Worker Pool:   " + std::to_string(config.worker_count) + " consumer threads");
        lines.push_back("Queue Cap:     " + std::to_string(config.queue_capacity) + " items");
        lines.push_back("Burst Config:  " + std::to_string(config.burst_threshold) + " events in " +
                        std::to_string(config.burst_window_sec) + "s");

        struct stat bst;
        if (stat(baseline_get_default_path().c_str(), &bst) == 0) {
            lines.push_back("Baseline DB:   " + ui_human_size(bst.st_size) + " (updated " +
                            ui_human_time_ago(bst.st_mtime) + ")");
        } else {
            lines.push_back("Baseline DB:   (Not generated)");
        }

        struct stat lst;
        if (stat(logger_get_default_path().c_str(), &lst) == 0) {
            lines.push_back("Audit Log:     " + ui_human_size(lst.st_size) + " (last activity " +
                            ui_human_time_ago(lst.st_mtime) + ")");
        }

        ui_draw_box("Warden Service Diagnostics", lines);
        config_list_protected_dirs(config);
        return 0;
    }

    std::cerr << ui_error_mark() << " Error: Unknown command '" << cmd << "'\n\n";
    print_detailed_help(argv[0]);
    return 1;
}
