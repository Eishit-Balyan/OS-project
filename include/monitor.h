#ifndef SENTINELFS_MONITOR_H
#define SENTINELFS_MONITOR_H

/**
 * ============================================================================
 * SentinelFS - Real-Time Filesystem Monitor Module
 * Module Purpose: Real Linux inotify file monitoring with recursive subdirectory
 *                 watching, self-pipe shutdown signaling, cookie-based move pairing,
 *                 and queue overflow recovery.
 * Owner: Vaibhav
 * ============================================================================
 */

#include "common.h"
#include "event_queue.h"
#include <string>

// Initializes inotify descriptor and attaches recursive watches for configured protected dirs
bool monitor_start(const Config& config);

// Continuous event loop: reads raw inotify events, converts them, and pushes to EventQueue; exits when g_shutdown is set
void monitor_run(EventQueue& queue);

// Signals the monitor loop to break via self-pipe trick and cleans up inotify watches
void monitor_stop();

// Returns the total number of active directory watches
size_t monitor_get_watch_count();

#endif // SENTINELFS_MONITOR_H
