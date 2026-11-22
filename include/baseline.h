#ifndef WARDEN_BASELINE_H
#define WARDEN_BASELINE_H

/**
 * ============================================================================
 * Warden - Baseline Management Module
 * Module Purpose: Recursive directory scanning, POSIX metadata extraction (lstat),
 *                 streaming OpenSSL SHA-256 calculation, atomic DB persistence,
 *                 sidecar hash verification, and parallel multi-threaded verify.
 * Owner: Krishna
 * ============================================================================
 */

#include "common.h"
#include <string>
#include <vector>

// THREAD-SAFETY: In-memory baseline records are guarded by a single internal
//                POSIX pthread_mutex_t in baseline.cpp.

// Recursively scans configured protected directories and builds in-memory baseline
bool baseline_build(const Config& config);

// Loads baseline records from the specified path, verifying sidecar SHA-256
bool baseline_load(const std::string& path);

// Atomically writes in-memory baseline database and updates sidecar hash (chmod 0600)
bool baseline_save(const std::string& path);

// Queries in-memory baseline for a record matching canonical path
bool baseline_lookup(const std::string& path, BaselineRecord& out);

// Inserts or updates a file record in the in-memory baseline database
void baseline_update(const BaselineRecord& record);

// Removes a file record from the in-memory baseline database
void baseline_remove(const std::string& path);

// Calculates POSIX metadata and streaming OpenSSL EVP SHA-256 for a given path
bool baseline_compute_record(const std::string& path, BaselineRecord& out);

// Rescans protected directories and compares against baseline using parallel workers
bool baseline_verify_against_disk(const Config& config, const std::string& baseline_path);

// Returns default baseline database path (~/.warden/baseline.db)
std::string baseline_get_default_path();

// Returns number of records currently loaded in memory
size_t baseline_get_record_count();

#endif // WARDEN_BASELINE_H
