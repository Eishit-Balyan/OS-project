/**
 * ============================================================================
 * Warden - Data Format and Serialization Test Suite
 * Module Purpose: Unit tests validating round-trip serialization, special
 *                 character escaping, malformed input rejection, and enum
 *                 conversions in common.cpp.
 * ============================================================================
 */

#include "common.h"
#include <iostream>
#include <vector>
#include <string>

static int g_failures = 0;

static void report_result(const std::string& check_name, bool passed) {
    if (passed) {
        std::cout << "[PASS] " << check_name << std::endl;
    } else {
        std::cout << "[FAIL] " << check_name << std::endl;
        g_failures++;
    }
}

// Test (a): BaselineRecord with tabs, newlines, and backslashes round-trips unchanged
static void test_baseline_record_escaping() {
    BaselineRecord orig;
    orig.path = "/test/dir\twith\ttabs/\nnewline_file\\with\\backslash.txt";
    orig.size = 123456789;
    orig.mode = 0100644;
    orig.uid = 1001;
    orig.gid = 1002;
    orig.mtime = 1731780000;
    orig.ctime = 1731780005;
    orig.inode = 9876543210ULL;
    orig.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    std::string line = baseline_record_to_line(orig);
    BaselineRecord parsed;
    bool parse_ok = line_to_baseline_record(line, parsed);

    bool match = parse_ok &&
                 (parsed.path == orig.path) &&
                 (parsed.size == orig.size) &&
                 (parsed.mode == orig.mode) &&
                 (parsed.uid == orig.uid) &&
                 (parsed.gid == orig.gid) &&
                 (parsed.mtime == orig.mtime) &&
                 (parsed.ctime == orig.ctime) &&
                 (parsed.inode == orig.inode) &&
                 (parsed.sha256 == orig.sha256);

    report_result("test_baseline_record_escaping (tab, newline, backslash in path)", match);
}

// Test (b): ClassifiedEvent survives to_line -> from_line round-trip
static void test_classified_event_roundtrip() {
    bool all_ok = true;

    // Case 1: Event with old_path and special characters
    ClassifiedEvent orig1;
    orig1.ev.timestamp = 1731781234;
    orig1.severity = CRITICAL;
    orig1.ev.type = MOVED;
    orig1.ev.path = "/var/log/secret\tfile\nnew.log";
    orig1.ev.old_path = "/tmp/old\\name\t1.log";
    orig1.ev.raw_mask = 0;
    orig1.detail = "Suspicious move\tdetected\nwith backslash \\ alert";

    std::string line1 = classified_event_to_line(orig1);
    ClassifiedEvent parsed1;
    bool ok1 = line_to_classified_event(line1, parsed1);

    if (!ok1 ||
        parsed1.ev.timestamp != orig1.ev.timestamp ||
        parsed1.severity != orig1.severity ||
        parsed1.ev.type != orig1.ev.type ||
        parsed1.ev.path != orig1.ev.path ||
        parsed1.ev.old_path != orig1.ev.old_path ||
        parsed1.detail != orig1.detail) {
        all_ok = false;
    }

    // Case 2: Event with empty old_path (represented as "-")
    ClassifiedEvent orig2;
    orig2.ev.timestamp = 1731785555;
    orig2.severity = WARNING;
    orig2.ev.type = PERM_CHANGED;
    orig2.ev.path = "/etc/shadow";
    orig2.ev.old_path = "";
    orig2.ev.raw_mask = 0;
    orig2.detail = "Permissions altered from 0640 to 0666";

    std::string line2 = classified_event_to_line(orig2);
    ClassifiedEvent parsed2;
    bool ok2 = line_to_classified_event(line2, parsed2);

    if (!ok2 ||
        parsed2.ev.timestamp != orig2.ev.timestamp ||
        parsed2.severity != orig2.severity ||
        parsed2.ev.type != orig2.ev.type ||
        parsed2.ev.path != orig2.ev.path ||
        !parsed2.ev.old_path.empty() ||
        parsed2.detail != orig2.detail) {
        all_ok = false;
    }

    report_result("test_classified_event_roundtrip (with and without old_path)", all_ok);
}

// Test (c): Malformed lines return false instead of crashing
static void test_malformed_lines() {
    bool all_handled = true;
    BaselineRecord rec;
    ClassifiedEvent ev;

    // Test baseline malformed cases
    std::vector<std::string> bad_baseline_lines = {
        "",
        "# this is a comment line",
        "only\tthree\tfields",
        "/path\tnot_a_number\t0644\t1000\t1000\t1700\t1700\t1\thash",
        "/path\t1024\t99invalid_octal\t1000\t1000\t1700\t1700\t1\thash",
        "/path\t1024\t0644\t1000\t1000\t1700\t1700\t1\thash\textra_tenth_field"
    };

    for (const auto& bad_line : bad_baseline_lines) {
        if (line_to_baseline_record(bad_line, rec)) {
            all_handled = false;
        }
    }

    // Test classified event malformed cases
    std::vector<std::string> bad_event_lines = {
        "",
        "# comment",
        "only\ttwo\tfields",
        "not_a_timestamp\tCRITICAL\tMODIFIED\t/path\t-\tdetail",
        "1731780000\tINVALID_SEVERITY\tMODIFIED\t/path\t-\tdetail",
        "1731780000\tCRITICAL\tINVALID_EVENT_TYPE\t/path\t-\tdetail",
        "1731780000\tCRITICAL\tMODIFIED\t/path\t-\tdetail\textra_field"
    };

    for (const auto& bad_line : bad_event_lines) {
        if (line_to_classified_event(bad_line, ev)) {
            all_handled = false;
        }
    }

    report_result("test_malformed_lines (safely returns false without crashing)", all_handled);
}

// Test (d): Every EventType and Severity round-trips through string conversions
static void test_enum_roundtrips() {
    bool types_ok = true;
    std::vector<EventType> all_types = {
        CREATED, MODIFIED, DELETED, MOVED, PERM_CHANGED, OWNER_CHANGED, UNKNOWN
    };

    for (EventType t : all_types) {
        std::string s = event_type_to_string(t);
        EventType parsed;
        if (!string_to_event_type(s, parsed) || parsed != t) {
            types_ok = false;
        }
    }

    bool sevs_ok = true;
    std::vector<Severity> all_sevs = {
        INFO, WARNING, CRITICAL
    };

    for (Severity sev : all_sevs) {
        std::string s = severity_to_string(sev);
        Severity parsed;
        if (!string_to_severity(s, parsed) || parsed != sev) {
            sevs_ok = false;
        }
    }

    report_result("test_enum_roundtrips (all EventType and Severity variants)", types_ok && sevs_ok);
}

int main() {
    std::cout << "Running Warden Data Format & Serialization Tests..." << std::endl;

    test_baseline_record_escaping();
    test_classified_event_roundtrip();
    test_malformed_lines();
    test_enum_roundtrips();

    if (g_failures == 0) {
        std::cout << "ALL TESTS PASSED" << std::endl;
        return 0;
    } else {
        std::cerr << g_failures << " TEST(S) FAILED" << std::endl;
        return 1;
    }
}
