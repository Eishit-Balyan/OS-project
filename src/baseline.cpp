/**
 * ============================================================================
 * SentinelFS - Baseline Management Implementation
 * Module Purpose: Real directory scanning, OpenSSL EVP streaming hashing,
 *                 atomic database file persistence with sidecar tamper detection,
 *                 and parallel multithreaded integrity verification.
 * Owner: Gaurav
 * ============================================================================
 */

#include "baseline.h"
#include "config.h"
#include "ui.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <vector>
#include <cstring>
#include <cstdlib>

#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <openssl/evp.h>

// THREAD-SAFETY: Mutex protecting the active in-memory baseline database
static pthread_mutex_t g_baseline_mutex = PTHREAD_MUTEX_INITIALIZER;
static std::unordered_map<std::string, BaselineRecord> g_baseline_records;

// Immutable snapshot of the baseline as loaded from disk for drift detection
static pthread_mutex_t g_trusted_mutex = PTHREAD_MUTEX_INITIALIZER;
static std::unordered_map<std::string, BaselineRecord> g_trusted_records;

std::string baseline_get_default_path() {
    return config_get_default_dir() + "/baseline.db";
}

size_t baseline_get_record_count() {
    pthread_mutex_lock(&g_baseline_mutex);
    size_t count = g_baseline_records.size();
    pthread_mutex_unlock(&g_baseline_mutex);
    return count;
}

static bool compute_sha256_streaming(const std::string& path, std::string& out_hex) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }

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

    const size_t CHUNK_SIZE = 64 * 1024;
    std::vector<unsigned char> buffer(CHUNK_SIZE);
    ssize_t bytes_read = 0;

    while ((bytes_read = read(fd, buffer.data(), CHUNK_SIZE)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer.data(), static_cast<size_t>(bytes_read)) != 1) {
            EVP_MD_CTX_free(ctx);
            close(fd);
            return false;
        }
    }

    close(fd);

    if (bytes_read < 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(ctx, md_value, &md_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < md_len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md_value[i]);
    }
    out_hex = oss.str();
    return true;
}

bool baseline_compute_record(const std::string& path, BaselineRecord& out) {
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        return false;
    }

    out.path = path;
    out.size = st.st_size;
    out.mode = st.st_mode;
    out.uid = st.st_uid;
    out.gid = st.st_gid;
    out.mtime = st.st_mtime;
    out.ctime = st.st_ctime;
    out.inode = st.st_ino;

    if (S_ISREG(st.st_mode)) {
        if (!compute_sha256_streaming(path, out.sha256)) {
            out.sha256 = "-"; // Unreadable or read error
        }
    } else {
        out.sha256 = "-";
    }

    return true;
}

static void scan_directory_recursive(const std::string& dir_path,
                                    const Config& config,
                                    std::unordered_map<std::string, BaselineRecord>& out_map) {
    if (config_is_ignored(config, dir_path)) {
        return;
    }

    DIR* dir = opendir(dir_path.c_str());
    if (!dir) {
        std::cerr << ui_error_mark() << " Warning: Cannot open directory "
                  << dir_path << ": " << std::strerror(errno) << std::endl;
        return;
    }

    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        const char* name = entry->d_name;
        if (std::strcmp(name, ".") == 0 || std::strcmp(name, "..") == 0) {
            continue;
        }

        std::string full_path = dir_path + "/" + name;
        if (config_is_ignored(config, full_path)) {
            continue;
        }

        struct stat st;
        if (lstat(full_path.c_str(), &st) != 0) {
            std::cerr << ui_error_mark() << " Warning: Cannot stat "
                      << full_path << ": " << std::strerror(errno) << std::endl;
            continue;
        }

        // Do not follow symlinks
        if (S_ISLNK(st.st_mode)) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            scan_directory_recursive(full_path, config, out_map);
        } else if (S_ISREG(st.st_mode)) {
            BaselineRecord rec;
            if (baseline_compute_record(full_path, rec)) {
                out_map[full_path] = rec;
            }
        }
    }

    closedir(dir);
}

bool baseline_build(const Config& config) {
    std::unordered_map<std::string, BaselineRecord> new_records;
    for (const auto& dir : config.protected_dirs) {
        std::cout << "  Scanning protected root: " << dir << "..." << std::endl;
        scan_directory_recursive(dir, config, new_records);
    }

    pthread_mutex_lock(&g_baseline_mutex);
    g_baseline_records = new_records;
    pthread_mutex_unlock(&g_baseline_mutex);

    pthread_mutex_lock(&g_trusted_mutex);
    g_trusted_records = new_records;
    pthread_mutex_unlock(&g_trusted_mutex);

    std::cout << ui_success_mark() << " Baseline built successfully ("
              << new_records.size() << " files recorded)." << std::endl;
    return true;
}

bool baseline_load(const std::string& path) {
    std::string sidecar_path = path + ".sha256";
    std::ifstream sidecar_in(sidecar_path);
    if (sidecar_in.is_open()) {
        std::string expected_hash;
        sidecar_in >> expected_hash;
        sidecar_in.close();

        std::string actual_hash;
        if (compute_sha256_streaming(path, actual_hash)) {
            if (expected_hash != actual_hash) {
                std::cerr << "\n\033[1;37;41m ****************************************************** \033[0m\n"
                          << "\033[1;31m   CRITICAL ALERT: BASELINE FILE TAMPERED!            \033[0m\n"
                          << "   Expected: " << expected_hash << "\n"
                          << "   Actual:   " << actual_hash << "\n"
                          << "\033[1;37;41m ****************************************************** \033[0m\n\n";
            }
        }
    }

    std::ifstream infile(path);
    if (!infile.is_open()) {
        return false;
    }

    std::unordered_map<std::string, BaselineRecord> loaded;
    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty() || line[0] == '#') continue;
        BaselineRecord rec;
        if (line_to_baseline_record(line, rec)) {
            loaded[rec.path] = rec;
        }
    }

    pthread_mutex_lock(&g_baseline_mutex);
    g_baseline_records = loaded;
    pthread_mutex_unlock(&g_baseline_mutex);

    pthread_mutex_lock(&g_trusted_mutex);
    g_trusted_records = loaded;
    pthread_mutex_unlock(&g_trusted_mutex);

    return true;
}

bool baseline_save(const std::string& path) {
    config_ensure_dir_exists();
    std::string temp_path = path + ".tmp." + std::to_string(getpid());

    int fd = open(temp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        std::cerr << ui_error_mark() << " Failed to open temporary baseline file "
                  << temp_path << ": " << std::strerror(errno) << std::endl;
        return false;
    }

    // Ensure permissions are strictly 0600
    fchmod(fd, 0600);

    FILE* fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return false;
    }

    // Line 1: Header, Line 2: Created epoch
    time_t now = time(nullptr);
    std::fprintf(fp, "#SENTINELFS-BASELINE v1\n#CREATED %ld\n", static_cast<long>(now));

    pthread_mutex_lock(&g_baseline_mutex);
    for (const auto& kv : g_baseline_records) {
        std::string line = baseline_record_to_line(kv.second);
        std::fprintf(fp, "%s\n", line.c_str());
    }
    pthread_mutex_unlock(&g_baseline_mutex);

    std::fflush(fp);
    fsync(fileno(fp));
    std::fclose(fp);

    // Atomic rename
    if (rename(temp_path.c_str(), path.c_str()) != 0) {
        std::cerr << ui_error_mark() << " Atomic rename failed: "
                  << std::strerror(errno) << std::endl;
        unlink(temp_path.c_str());
        return false;
    }

    // Compute and write sidecar SHA-256
    std::string db_hash;
    if (compute_sha256_streaming(path, db_hash)) {
        std::string sidecar_path = path + ".sha256";
        std::ofstream sidecar_out(sidecar_path);
        if (sidecar_out.is_open()) {
            sidecar_out << db_hash << "\n";
            sidecar_out.close();
            chmod(sidecar_path.c_str(), 0600);
        }
    }

    return true;
}

bool baseline_lookup(const std::string& path, BaselineRecord& out) {
    pthread_mutex_lock(&g_baseline_mutex);
    auto it = g_baseline_records.find(path);
    bool found = (it != g_baseline_records.end());
    if (found) {
        out = it->second;
    }
    pthread_mutex_unlock(&g_baseline_mutex);
    return found;
}

void baseline_update(const BaselineRecord& record) {
    pthread_mutex_lock(&g_baseline_mutex);
    g_baseline_records[record.path] = record;
    pthread_mutex_unlock(&g_baseline_mutex);
}

void baseline_remove(const std::string& path) {
    pthread_mutex_lock(&g_baseline_mutex);
    g_baseline_records.erase(path);
    pthread_mutex_unlock(&g_baseline_mutex);
}

// Parallel verification worker context
struct VerifyJob {
    std::vector<std::string> paths;
    size_t next_idx;
    pthread_mutex_t mutex;
    const Config* config;
    std::unordered_map<std::string, BaselineRecord> disk_records;
    pthread_mutex_t out_mutex;
    size_t done_count;
};

static void* verify_worker_routine(void* arg) {
    VerifyJob* job = static_cast<VerifyJob*>(arg);

    while (true) {
        std::string current_path;
        pthread_mutex_lock(&job->mutex);
        if (job->next_idx >= job->paths.size()) {
            pthread_mutex_unlock(&job->mutex);
            break;
        }
        current_path = job->paths[job->next_idx++];
        pthread_mutex_unlock(&job->mutex);

        BaselineRecord rec;
        if (baseline_compute_record(current_path, rec)) {
            pthread_mutex_lock(&job->out_mutex);
            job->disk_records[current_path] = rec;
            job->done_count++;
            ui_draw_progress_bar(job->done_count, job->paths.size(), "Hashing files:");
            pthread_mutex_unlock(&job->out_mutex);
        }
    }
    return nullptr;
}

bool baseline_verify_against_disk(const Config& config, const std::string& baseline_path) {
    if (!baseline_load(baseline_path)) {
        std::cerr << ui_error_mark() << " Error: Could not load baseline database from "
                  << baseline_path << std::endl;
        return false;
    }

    pthread_mutex_lock(&g_trusted_mutex);
    std::unordered_map<std::string, BaselineRecord> baseline = g_trusted_records;
    pthread_mutex_unlock(&g_trusted_mutex);

    std::cout << "Scanning filesystem across protected roots...\n";
    std::unordered_map<std::string, BaselineRecord> dummy_map;
    // Discover all candidate paths on disk
    std::vector<std::string> disk_paths;
    for (const auto& dir : config.protected_dirs) {
        std::unordered_map<std::string, BaselineRecord> temp_scan;
        scan_directory_recursive(dir, config, temp_scan);
        for (const auto& kv : temp_scan) {
            disk_paths.push_back(kv.first);
        }
    }

    // Parallel worker pool for computing file hashes
    VerifyJob job;
    job.paths = disk_paths;
    job.next_idx = 0;
    job.config = &config;
    job.done_count = 0;
    pthread_mutex_init(&job.mutex, nullptr);
    pthread_mutex_init(&job.out_mutex, nullptr);

    int num_workers = config.worker_count > 0 ? config.worker_count : 4;
    std::vector<pthread_t> workers(num_workers);
    for (int i = 0; i < num_workers; ++i) {
        pthread_create(&workers[i], nullptr, verify_worker_routine, &job);
    }

    for (int i = 0; i < num_workers; ++i) {
        pthread_join(workers[i], nullptr);
    }
    pthread_mutex_destroy(&job.mutex);
    pthread_mutex_destroy(&job.out_mutex);

    size_t unchanged_count = 0;
    size_t modified_count = 0;
    size_t new_count = 0;
    size_t missing_count = 0;

    std::vector<std::vector<std::string>> diff_rows;

    // Check disk records against baseline
    for (const auto& kv : job.disk_records) {
        const std::string& p = kv.first;
        const BaselineRecord& disk_rec = kv.second;

        auto it = baseline.find(p);
        if (it == baseline.end()) {
            new_count++;
            diff_rows.push_back({ui_badge(INFO), "NEW", ui_truncate_path(p, 45), "Not in baseline"});
        } else {
            const BaselineRecord& base_rec = it->second;
            bool hash_diff = (base_rec.sha256 != disk_rec.sha256);
            bool mode_diff = (base_rec.mode != disk_rec.mode);
            bool owner_diff = (base_rec.uid != disk_rec.uid || base_rec.gid != disk_rec.gid);

            if (hash_diff || mode_diff || owner_diff) {
                modified_count++;
                std::string reason;
                if (hash_diff) reason += "Hash mismatch ";
                if (mode_diff) reason += "Perms changed ";
                if (owner_diff) reason += "Owner changed";
                diff_rows.push_back({ui_badge(WARNING), "MODIFIED", ui_truncate_path(p, 45), reason});
            } else {
                unchanged_count++;
            }
        }
    }

    // Check for missing baseline files
    for (const auto& kv : baseline) {
        if (job.disk_records.find(kv.first) == job.disk_records.end()) {
            missing_count++;
            diff_rows.push_back({ui_badge(CRITICAL), "MISSING", ui_truncate_path(kv.first, 45), "File removed from disk"});
        }
    }

    std::cout << "\n";
    if (!diff_rows.empty()) {
        std::vector<std::string> headers = {"Severity", "Status", "File Path", "Discrepancy Detail"};
        std::vector<size_t> widths = {12, 10, 47, 25};
        ui_draw_table(headers, diff_rows, widths);
    }

    std::vector<std::string> summary_lines;
    summary_lines.push_back("Total Baselined Files: " + std::to_string(baseline.size()));
    summary_lines.push_back("Unchanged:            " + std::to_string(unchanged_count) + " (Clean)");
    summary_lines.push_back("Modified:             " + std::to_string(modified_count) + " (Altered)");
    summary_lines.push_back("Missing / Deleted:    " + std::to_string(missing_count) + " (Deleted)");
    summary_lines.push_back("New / Unbaselined:    " + std::to_string(new_count) + " (Added)");

    ui_draw_box("Integrity Verification Summary", summary_lines);
    return (modified_count == 0 && missing_count == 0);
}
