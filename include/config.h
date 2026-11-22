#ifndef WARDEN_CONFIG_H
#define WARDEN_CONFIG_H

/**
 * ============================================================================
 * Warden - Configuration Management Module
 * Module Purpose: Real configuration management for protected directories,
 *                 ignore patterns, critical security paths, and thresholds.
 *                 Handles ~/.warden/ directory creation and key=value config.
 * Owner: Aviral
 * ============================================================================
 */

#include "common.h"
#include <string>

// Returns the default directory path (~/.warden)
std::string config_get_default_dir();

// Returns the default configuration file path (~/.warden/config)
std::string config_get_default_path();

// Ensures ~/.warden directory exists with proper permissions (0700)
bool config_ensure_dir_exists();

// Loads key=value configuration from disk into config; creates default if missing
bool config_load(const std::string& config_file, Config& config);

// Saves configuration to disk in key=value format
bool config_save(const std::string& config_file, const Config& config);

// Adds a directory path to the protected list; validates realpath, directory status,
// and rejects duplicate or overlapping/nested directory hierarchies
bool config_add_protected_dir(Config& config, const std::string& dir_path);

// Removes a directory path from the protected list
bool config_remove_protected_dir(Config& config, const std::string& dir_path);

// Displays all currently protected directories and settings
void config_list_protected_dirs(const Config& config);

// Validates whether a given path exists, is accessible, and is a directory
bool config_validate_path(const std::string& path);

// Checks if a given path or filename matches any configured ignore patterns via fnmatch()
bool config_is_ignored(const Config& config, const std::string& path);

#endif // WARDEN_CONFIG_H
