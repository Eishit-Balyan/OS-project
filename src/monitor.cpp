/**
 * ============================================================================
 * Warden - Real-Time Filesystem Monitor Implementation
 * Module Purpose: Real Linux inotify event monitoring with recursive watch
 *                 descriptor registration, self-pipe shutdown unblocking,
 *                 cookie-based rename/move pairing, and queue overflow recovery.
 * Owner: Eishit
 * ============================================================================
 */

#include "monitor.h"
#include "config.h"
#include "ui.h"

#include <iostream>
#include <unordered_map>
#include <vector>
#include <cstring>
#include <cstdlib>

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <pthread.h>

static int g_inotify_fd = -1;
static int g_self_pipe[2] = {-1, -1};
static const Config* g_config_ptr = nullptr;

static pthread_mutex_t g_watch_mutex = PTHREAD_MUTEX_INITIALIZER;
static std::unordered_map<int, std::string> g_wd_to_path;
static std::unordered_map<std::string, int> g_path_to_wd;

static const uint32_t INOTIFY_WATCH_MASK =
    IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_FROM |
    IN_MOVED_TO | IN_ATTRIB | IN_DELETE_SELF;

size_t monitor_get_watch_count() {
    pthread_mutex_lock(&g_watch_mutex);
    size_t count = g_wd_to_path.size();
    pthread_mutex_unlock(&g_watch_mutex);
    return count;
}

static void add_watch_recursive(int inotify_fd, const std::string& dir_path, const Config& config) {
    if (config_is_ignored(config, dir_path)) {
        return;
    }

    pthread_mutex_lock(&g_watch_mutex);
    if (g_path_to_wd.find(dir_path) != g_path_to_wd.end()) {
        pthread_mutex_unlock(&g_watch_mutex);
        return;
    }

    int wd = inotify_add_watch(inotify_fd, dir_path.c_str(), INOTIFY_WATCH_MASK);
    if (wd >= 0) {
        g_wd_to_path[wd] = dir_path;
        g_path_to_wd[dir_path] = wd;
    } else {
        std::cerr << ui_error_mark() << " Warning: Could not watch "
                  << dir_path << ": " << std::strerror(errno) << std::endl;
    }
    pthread_mutex_unlock(&g_watch_mutex);

    DIR* dir = opendir(dir_path.c_str());
    if (!dir) return;

    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        const char* name = entry->d_name;
        if (std::strcmp(name, ".") == 0 || std::strcmp(name, "..") == 0) continue;

        std::string sub = dir_path + "/" + name;
        if (config_is_ignored(config, sub)) continue;

        struct stat st;
        if (lstat(sub.c_str(), &st) == 0 && S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            add_watch_recursive(inotify_fd, sub, config);
        }
    }
    closedir(dir);
}

bool monitor_start(const Config& config) {
    g_config_ptr = &config;

    g_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (g_inotify_fd < 0) {
        std::cerr << ui_error_mark() << " Failed to initialize inotify: "
                  << std::strerror(errno) << std::endl;
        return false;
    }

    if (pipe(g_self_pipe) != 0) {
        std::cerr << ui_error_mark() << " Failed to create self-pipe: "
                  << std::strerror(errno) << std::endl;
        close(g_inotify_fd);
        g_inotify_fd = -1;
        return false;
    }

    // Set self-pipe to non-blocking
    fcntl(g_self_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(g_self_pipe[1], F_SETFL, O_NONBLOCK);

    for (const auto& dir : config.protected_dirs) {
        add_watch_recursive(g_inotify_fd, dir, config);
    }

    return true;
}

void monitor_run(EventQueue& queue) {
    if (g_inotify_fd < 0) return;

    struct pollfd fds[2];
    fds[0].fd = g_inotify_fd;
    fds[0].events = POLLIN;
    fds[1].fd = g_self_pipe[0];
    fds[1].events = POLLIN;

    // Structure to correlate IN_MOVED_FROM and IN_MOVED_TO via cookie
    struct PendingMove {
        time_t timestamp;
        std::string source_path;
    };
    std::unordered_map<uint32_t, PendingMove> pending_moves;

    const size_t BUF_LEN = 16384;
    char buffer[BUF_LEN] __attribute__((aligned(__alignof__(struct inotify_event))));

    while (!g_shutdown) {
        int poll_ret = poll(fds, 2, 250);
        if (poll_ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Check self-pipe for stop signal
        if (fds[1].revents & POLLIN) {
            char dummy[16];
            while (read(g_self_pipe[0], dummy, sizeof(dummy)) > 0) {}
            break;
        }

        if (g_shutdown) break;

        // Process inotify events
        if (fds[0].revents & POLLIN) {
            ssize_t len = read(g_inotify_fd, buffer, BUF_LEN);
            if (len <= 0) {
                if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    // No more events available currently
                }
                continue;
            }

            ssize_t i = 0;
            while (i < len) {
                struct inotify_event* raw_ev = reinterpret_cast<struct inotify_event*>(&buffer[i]);

                // Handle queue overflow
                if (raw_ev->mask & IN_Q_OVERFLOW) {
                    std::cerr << ui_error_mark()
                              << " Warning: inotify event queue overflowed (IN_Q_OVERFLOW)! Rescanning...\n";
                    if (g_config_ptr) {
                        for (const auto& dir : g_config_ptr->protected_dirs) {
                            add_watch_recursive(g_inotify_fd, dir, *g_config_ptr);
                        }
                    }
                    i += sizeof(struct inotify_event) + raw_ev->len;
                    continue;
                }

                std::string parent_dir;
                pthread_mutex_lock(&g_watch_mutex);
                auto it = g_wd_to_path.find(raw_ev->wd);
                if (it != g_wd_to_path.end()) {
                    parent_dir = it->second;
                }
                pthread_mutex_unlock(&g_watch_mutex);

                std::string full_path = parent_dir;
                if (raw_ev->len > 0 && raw_ev->name[0] != '\0') {
                    full_path = parent_dir + "/" + raw_ev->name;
                }

                // If watch was deleted or ignored, update internal table
                if (raw_ev->mask & (IN_DELETE_SELF | IN_IGNORED)) {
                    pthread_mutex_lock(&g_watch_mutex);
                    g_wd_to_path.erase(raw_ev->wd);
                    g_path_to_wd.erase(parent_dir);
                    pthread_mutex_unlock(&g_watch_mutex);
                }

                // Skip ignored filenames
                if (g_config_ptr && config_is_ignored(*g_config_ptr, full_path)) {
                    i += sizeof(struct inotify_event) + raw_ev->len;
                    continue;
                }

                // Dynamically add watches for newly created subdirectories
                if ((raw_ev->mask & IN_CREATE) && (raw_ev->mask & IN_ISDIR)) {
                    if (g_config_ptr) {
                        add_watch_recursive(g_inotify_fd, full_path, *g_config_ptr);
                    }
                }

                // Handle move pairing with cookie
                if (raw_ev->mask & IN_MOVED_FROM) {
                    if (raw_ev->cookie != 0) {
                        PendingMove pm;
                        pm.timestamp = time(nullptr);
                        pm.source_path = full_path;
                        pending_moves[raw_ev->cookie] = pm;
                    } else {
                        Event ev;
                        ev.timestamp = time(nullptr);
                        ev.path = full_path;
                        ev.old_path = "";
                        ev.type = DELETED;
                        ev.raw_mask = raw_ev->mask;
                        queue.push(ev);
                    }
                } else if (raw_ev->mask & IN_MOVED_TO) {
                    if (raw_ev->cookie != 0 && pending_moves.find(raw_ev->cookie) != pending_moves.end()) {
                        Event ev;
                        ev.timestamp = time(nullptr);
                        ev.path = full_path;
                        ev.old_path = pending_moves[raw_ev->cookie].source_path;
                        ev.type = MOVED;
                        ev.raw_mask = raw_ev->mask;
                        queue.push(ev);
                        pending_moves.erase(raw_ev->cookie);
                    } else {
                        Event ev;
                        ev.timestamp = time(nullptr);
                        ev.path = full_path;
                        ev.old_path = "";
                        ev.type = CREATED;
                        ev.raw_mask = raw_ev->mask;
                        queue.push(ev);
                    }
                } else {
                    EventType ev_type = UNKNOWN;
                    if (raw_ev->mask & IN_CLOSE_WRITE) {
                        ev_type = MODIFIED;
                    } else if (raw_ev->mask & IN_CREATE) {
                        ev_type = CREATED;
                    } else if (raw_ev->mask & IN_DELETE) {
                        ev_type = DELETED;
                    } else if (raw_ev->mask & IN_ATTRIB) {
                        ev_type = PERM_CHANGED;
                    }

                    if (ev_type != UNKNOWN) {
                        Event ev;
                        ev.timestamp = time(nullptr);
                        ev.path = full_path;
                        ev.old_path = "";
                        ev.type = ev_type;
                        ev.raw_mask = raw_ev->mask;
                        queue.push(ev);
                    }
                }

                i += sizeof(struct inotify_event) + raw_ev->len;
            }
        }

        // Evict expired pending moves (> 2 seconds old)
        time_t cur_time = time(nullptr);
        for (auto it = pending_moves.begin(); it != pending_moves.end(); ) {
            if (cur_time - it->second.timestamp >= 2) {
                Event ev;
                ev.timestamp = it->second.timestamp;
                ev.path = it->second.source_path;
                ev.old_path = "";
                ev.type = DELETED;
                ev.raw_mask = 0;
                queue.push(ev);
                it = pending_moves.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void monitor_stop() {
    if (g_self_pipe[1] >= 0) {
        char wake = 'x';
        write(g_self_pipe[1], &wake, 1);
    }

    if (g_inotify_fd >= 0) {
        pthread_mutex_lock(&g_watch_mutex);
        for (const auto& kv : g_wd_to_path) {
            inotify_rm_watch(g_inotify_fd, kv.first);
        }
        g_wd_to_path.clear();
        g_path_to_wd.clear();
        pthread_mutex_unlock(&g_watch_mutex);

        close(g_inotify_fd);
        g_inotify_fd = -1;
    }

    if (g_self_pipe[0] >= 0) {
        close(g_self_pipe[0]);
        close(g_self_pipe[1]);
        g_self_pipe[0] = -1;
        g_self_pipe[1] = -1;
    }
}
