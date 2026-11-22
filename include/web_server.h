#ifndef WARDEN_WEB_SERVER_H
#define WARDEN_WEB_SERVER_H

/**
 * ============================================================================
 * Warden - Decoupled HTTP API & Forensic Web Ledger Server
 * Module Purpose: Standalone C++17 POSIX socket HTTP server serving JSON APIs,
 *                 Server-Sent Events (SSE) tailing events.log, CSV exports,
 *                 and offline static forensic ledger frontend files.
 * ============================================================================
 */

#include "common.h"
#include <string>

// Default port and connection limits
constexpr int DEFAULT_WEB_PORT = 8787;
constexpr int MAX_WEB_CONNECTIONS = 32;

struct WebServerConfig {
    int port = DEFAULT_WEB_PORT;
    std::string web_dir;
};

// Starts the HTTP web server loop (blocks until g_shutdown is signaled)
int web_server_run(const WebServerConfig& config);

// Helper to escape strings for valid JSON encoding (escapes quotes, backslashes, control characters)
std::string json_escape(const std::string& input);

#endif // WARDEN_WEB_SERVER_H
