/**
 * ============================================================================
 * SentinelFS - Event Classifier Implementation
 * Module Purpose: Real security classification comparing incoming events with
 *                 baseline records, detecting false alarms, identifying permission
 *                 and ownership transitions, setuid/setgid escalations, and
 *                 critical path alerts.
 * Owner: Ayaansh
 * ============================================================================
 */

#include "classifier.h"
#include "baseline.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>

static std::string format_mode_octal(mode_t mode) {
    std::ostringstream oss;
    oss << "0" << std::oct << (mode & 07777);
    return oss.str();
}

ClassifiedEvent classify(const Event& ev, const Config& config) {
    ClassifiedEvent ce;
    ce.ev = ev;
    ce.severity = INFO;
    ce.detail = "";

    // Check if target path matches configured critical paths
    bool is_critical_path = false;
    for (const auto& cp : config.critical_paths) {
        if (cp == ev.path) {
            is_critical_path = true;
            break;
        }
    }

    BaselineRecord base_rec;
    bool in_baseline = baseline_lookup(ev.path, base_rec);

    BaselineRecord cur_rec;
    bool stat_ok = baseline_compute_record(ev.path, cur_rec);

    bool suid_sgid_newly_set = false;
    if (stat_ok && ((cur_rec.mode & (S_ISUID | S_ISGID)) != 0)) {
        if (!in_baseline || ((base_rec.mode & (S_ISUID | S_ISGID)) == 0)) {
            suid_sgid_newly_set = true;
        }
    }

    if (ev.type == MODIFIED) {
        if (stat_ok && in_baseline) {
            // Check for false alarms: if hash, size, and metadata are unchanged, return NO_CHANGE
            if (cur_rec.sha256 == base_rec.sha256 &&
                cur_rec.size == base_rec.size &&
                cur_rec.mode == base_rec.mode &&
                cur_rec.uid == base_rec.uid &&
                cur_rec.gid == base_rec.gid) {
                ce.detail = "NO_CHANGE";
                return ce;
            }

            std::string diffs;
            if (cur_rec.sha256 != base_rec.sha256) {
                std::string old_h = (base_rec.sha256.size() >= 8) ? base_rec.sha256.substr(0, 8) : base_rec.sha256;
                std::string new_h = (cur_rec.sha256.size() >= 8) ? cur_rec.sha256.substr(0, 8) : cur_rec.sha256;
                diffs += "hash " + old_h + ".. -> " + new_h + ".. ";
            }
            if (cur_rec.size != base_rec.size) {
                diffs += "size " + std::to_string(base_rec.size) + " -> " + std::to_string(cur_rec.size) + " ";
            }
            if (cur_rec.mode != base_rec.mode) {
                diffs += "mode " + format_mode_octal(base_rec.mode) + " -> " + format_mode_octal(cur_rec.mode) + " ";
            }
            if (cur_rec.uid != base_rec.uid || cur_rec.gid != base_rec.gid) {
                diffs += "owner " + std::to_string(base_rec.uid) + ":" + std::to_string(base_rec.gid) +
                         " -> " + std::to_string(cur_rec.uid) + ":" + std::to_string(cur_rec.gid) + " ";
            }
            ce.detail = diffs;
            baseline_update(cur_rec);
        } else if (stat_ok && !in_baseline) {
            ce.detail = "unbaselined file modified (size: " + std::to_string(cur_rec.size) + ")";
            baseline_update(cur_rec);
        } else {
            ce.detail = "file modified (unable to read content)";
        }
    } else if (ev.type == PERM_CHANGED) {
        if (stat_ok && in_baseline) {
            if (cur_rec.uid != base_rec.uid || cur_rec.gid != base_rec.gid) {
                ce.ev.type = OWNER_CHANGED;
                ce.detail = "owner " + std::to_string(base_rec.uid) + ":" + std::to_string(base_rec.gid) +
                            " -> " + std::to_string(cur_rec.uid) + ":" + std::to_string(cur_rec.gid);
            } else if (cur_rec.mode != base_rec.mode) {
                ce.detail = "mode " + format_mode_octal(base_rec.mode) + " -> " + format_mode_octal(cur_rec.mode);
            } else {
                // False alarm
                ce.detail = "NO_CHANGE";
                return ce;
            }
            baseline_update(cur_rec);
        } else if (stat_ok) {
            ce.detail = "mode " + format_mode_octal(cur_rec.mode);
            baseline_update(cur_rec);
        } else {
            ce.detail = "attribute change";
        }
    } else if (ev.type == CREATED) {
        ce.detail = "new file created";
        if (stat_ok) {
            baseline_update(cur_rec);
        }
    } else if (ev.type == DELETED) {
        ce.detail = "file deleted from disk";
        if (in_baseline) {
            baseline_remove(ev.path);
        }
    } else if (ev.type == MOVED) {
        ce.detail = "moved from " + (ev.old_path.empty() ? "(external)" : ev.old_path);
        if (!ev.old_path.empty()) {
            baseline_remove(ev.old_path);
        }
        if (stat_ok) {
            baseline_update(cur_rec);
        }
    } else {
        ce.detail = "filesystem event observed";
    }

    if (suid_sgid_newly_set) {
        ce.detail += " [PRIVILEGE ESCALATION: SUID/SGID bit set!]";
    }
    if (is_critical_path) {
        ce.detail += " [CRITICAL SECURITY PATH]";
    }

    // Determine Severity Level
    if (is_critical_path || suid_sgid_newly_set || (in_baseline && (ce.ev.type == DELETED || ce.ev.type == MOVED))) {
        ce.severity = CRITICAL;
    } else if (in_baseline && (ce.ev.type == MODIFIED || ce.ev.type == PERM_CHANGED || ce.ev.type == OWNER_CHANGED)) {
        ce.severity = WARNING;
    } else if (!in_baseline && (ce.ev.type == DELETED || ce.ev.type == MOVED)) {
        ce.severity = WARNING;
    } else if (ce.ev.type == CREATED) {
        ce.severity = INFO;
    } else {
        ce.severity = INFO;
    }

    return ce;
}
