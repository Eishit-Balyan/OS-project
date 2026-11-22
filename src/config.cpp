/**
 * ============================================================================
 * SentinelFS - Configuration Management Implementation
 * Module Purpose: Configuration file parser/serializer, directory validation,
 *                 duplicate/nesting rejection, and glob pattern filtering.
 * Owner: Arjun
 * ============================================================================
 */

#include "config.h"
#include "ui.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <limits.h>
#include <fnmatch.h>

static std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

std::string config_get_default_dir() {
    std::string home;
    const char* env_home = std::getenv("HOME");
    if (env_home && *env_home != '\0') {
        home = env_home;
    } else {
        struct passwd* pw = getpwuid(getuid());
        if (pw && pw->pw_dir) {
            home = pw->pw_dir;
        }
    }
    if (home.empty()) {
        home = ".";
    }
    return home + "/.sentinelfs";
}

std::string config_get_default_path() {
    return config_get_default_dir() + "/config";
}

bool config_ensure_dir_exists() {
    std::string dir = config_get_default_dir();
    struct stat st;
    if (stat(dir.c_str(), &st) != 0) {
        if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
            std::cerr << ui_error_mark() << " Failed to create directory "
                      << dir << ": " << std::strerror(errno) << std::endl;
            return false;
        }
    }
    return true;
}

bool config_load(const std::string& config_file, Config& config) {
    config_ensure_dir_exists();
    std::ifstream infile(config_file);
    if (!infile.is_open()) {
        // If config file doesn't exist, create it with default configuration
        config = default_config();
        config_save(config_file, config);
        return true;
    }

    config = default_config();
    config.protected_dirs.clear();
    config.ignore_patterns.clear();
    config.critical_paths.clear();

    std::string line;
    while (std::getline(infile, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;

        std::string key = trim(line.substr(0, eq_pos));
        std::string val = trim(line.substr(eq_pos + 1));

        try {
            if (key == "protected") {
                if (!val.empty()) config.protected_dirs.push_back(val);
            } else if (key == "ignore") {
                if (!val.empty()) config.ignore_patterns.push_back(val);
            } else if (key == "critical") {
                if (!val.empty()) config.critical_paths.push_back(val);
            } else if (key == "worker_count") {
                config.worker_count = std::stoi(val);
            } else if (key == "queue_capacity") {
                config.queue_capacity = std::stoi(val);
            } else if (key == "burst_threshold") {
                config.burst_threshold = std::stoi(val);
            } else if (key == "burst_window_sec") {
                config.burst_window_sec = std::stoi(val);
            }
        } catch (...) {
            std::cerr << ui_error_mark() << " Warning: Invalid configuration value for key: "
                      << key << " (value: " << val << ")" << std::endl;
        }
    }

    // Apply defaults if repeatable vectors were completely empty
    if (config.ignore_patterns.empty()) {
        config.ignore_patterns = { "*.swp", "*.tmp", "*~" };
    }
    if (config.critical_paths.empty()) {
        config.critical_paths = { "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config" };
    }

    return true;
}

bool config_save(const std::string& config_file, const Config& config) {
    config_ensure_dir_exists();
    std::ofstream outfile(config_file);
    if (!outfile.is_open()) {
        std::cerr << ui_error_mark() << " Failed to write configuration to "
                  << config_file << ": " << std::strerror(errno) << std::endl;
        return false;
    }

    outfile << "# =============================================================================\n"
            << "# SentinelFS Configuration File\n"
            << "# =============================================================================\n\n"
            << "worker_count=" << config.worker_count << "\n"
            << "queue_capacity=" << config.queue_capacity << "\n"
            << "burst_threshold=" << config.burst_threshold << "\n"
            << "burst_window_sec=" << config.burst_window_sec << "\n\n"
            << "# Protected Directories\n";

    for (const auto& dir : config.protected_dirs) {
        outfile << "protected=" << dir << "\n";
    }

    outfile << "\n# Ignore Patterns (wildcard globs)\n";
    for (const auto& pat : config.ignore_patterns) {
        outfile << "ignore=" << pat << "\n";
    }

    outfile << "\n# Critical Paths (trigger CRITICAL severity)\n";
    for (const auto& cp : config.critical_paths) {
        outfile << "critical=" << cp << "\n";
    }

    return true;
}

bool config_add_protected_dir(Config& config, const std::string& dir_path) {
    char resolved[PATH_MAX];
    if (realpath(dir_path.c_str(), resolved) == nullptr) {
        std::cerr << ui_error_mark() << " Error: Cannot resolve directory path '"
                  << dir_path << "': " << std::strerror(errno) << std::endl;
        return false;
    }

    std::string canonical(resolved);
    struct stat st;
    if (lstat(canonical.c_str(), &st) != 0) {
        std::cerr << ui_error_mark() << " Error: Path '" << canonical
                  << "' cannot be accessed: " << std::strerror(errno) << std::endl;
        return false;
    }

    if (!S_ISDIR(st.st_mode)) {
        std::cerr << ui_error_mark() << " Error: Path '" << canonical
                  << "' is not a directory." << std::endl;
        return false;
    }

    // Check for duplicates
    for (const auto& existing : config.protected_dirs) {
        if (existing == canonical) {
            std::cerr << ui_error_mark() << " Error: Directory '" << canonical
                      << "' is already in the protected list." << std::endl;
            return false;
        }
    }

    // Check for nested / overlapping directories
    for (const auto& existing : config.protected_dirs) {
        // Is new directory inside an existing protected directory?
        if (canonical.rfind(existing + "/", 0) == 0) {
            std::cerr << ui_error_mark() << " Error: Directory '" << canonical
                      << "' is nested inside already protected directory '"
                      << existing << "'." << std::endl;
            return false;
        }
        // Is an existing protected directory inside the new directory?
        if (existing.rfind(canonical + "/", 0) == 0) {
            std::cerr << ui_error_mark() << " Error: Existing protected directory '"
                      << existing << "' is inside '" << canonical
                      << "' (overlapping directories are rejected)." << std::endl;
            return false;
        }
    }

    config.protected_dirs.push_back(canonical);
    return true;
}

bool config_remove_protected_dir(Config& config, const std::string& dir_path) {
    char resolved[PATH_MAX];
    std::string target = dir_path;
    if (realpath(dir_path.c_str(), resolved) != nullptr) {
        target = resolved;
    }

    auto it = std::find(config.protected_dirs.begin(), config.protected_dirs.end(), target);
    if (it == config.protected_dirs.end()) {
        // Also check if raw dir_path matches directly
        it = std::find(config.protected_dirs.begin(), config.protected_dirs.end(), dir_path);
    }

    if (it != config.protected_dirs.end()) {
        config.protected_dirs.erase(it);
        return true;
    }

    std::cerr << ui_error_mark() << " Error: Directory '" << dir_path
              << "' not found in protected directories list." << std::endl;
    return false;
}

void config_list_protected_dirs(const Config& config) {
    std::cout << "\n=== SentinelFS Monitored Directories ===\n";
    if (config.protected_dirs.empty()) {
        std::cout << "  (No protected directories configured. Use 'add <dir>' to add one.)\n";
    } else {
        for (size_t i = 0; i < config.protected_dirs.size(); ++i) {
            std::cout << "  [" << (i + 1) << "] " << config.protected_dirs[i] << "\n";
        }
    }

    std::cout << "\n=== Ignore Patterns ===\n";
    for (const auto& pat : config.ignore_patterns) {
        std::cout << "  - " << pat << "\n";
    }

    std::cout << "\n=== Critical Security Paths ===\n";
    for (const auto& cp : config.critical_paths) {
        std::cout << "  * " << cp << "\n";
    }
    std::cout << std::endl;
}

bool config_validate_path(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        std::cerr << ui_error_mark() << " Path validation failed for '" << path
                  << "': " << std::strerror(errno) << std::endl;
        return false;
    }
    return S_ISDIR(st.st_mode);
}

bool config_is_ignored(const Config& config, const std::string& path) {
    size_t slash = path.find_last_of('/');
    std::string fname = (slash == std::string::npos) ? path : path.substr(slash + 1);

    for (const auto& pat : config.ignore_patterns) {
        if (fnmatch(pat.c_str(), fname.c_str(), 0) == 0) {
            return true;
        }
        if (fnmatch(pat.c_str(), path.c_str(), 0) == 0) {
            return true;
        }
    }
    return false;
}
