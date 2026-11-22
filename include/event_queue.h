#ifndef SENTINELFS_EVENT_QUEUE_H
#define SENTINELFS_EVENT_QUEUE_H

/**
 * ============================================================================
 * SentinelFS - Thread-Safe Bounded Event Queue & Worker Pool Module
 * Module Purpose: Provides a bounded producer-consumer queue synchronized
 *                 using raw POSIX pthreads and controls the worker thread pool.
 * Owner: Vaibhav
 * ============================================================================
 */

#include "common.h"
#include <pthread.h>
#include <queue>
#include <cstddef>

/**
 * EventQueue: Bounded synchronized queue structure.
 * THREAD-SAFETY: All operations are synchronized using an internal pthread_mutex_t
 *                and two condition variables (not_empty, not_full). Safe for
 *                concurrent access across multiple producers and consumers.
 */
class EventQueue {
public:
    // Initializes queue synchronization primitives and capacity limit
    explicit EventQueue(size_t max_capacity = 1024);

    // Destroys mutex and condition variables
    ~EventQueue();

    // Enqueues an event; blocks while queue is at max capacity; returns false if shutdown
    void push(const Event& ev);

    // Dequeues an event; blocks if empty; returns false once shutdown and drained
    bool pop(Event& out_ev);

    // Signals shutdown to unblock all threads waiting on queue conditions
    void shutdown();

    // Returns current number of items in the queue
    size_t size();

    // Returns maximum capacity of the queue
    size_t capacity() const;

private:
    std::queue<Event> queue_;
    size_t max_capacity_;
    bool shutdown_;
    mutable pthread_mutex_t mutex_;
    pthread_cond_t not_empty_;
    pthread_cond_t not_full_;
};

// Spawns n worker pthreads that process events from the shared queue
bool worker_pool_start(int n, EventQueue& queue, const Config& config);

// Signals shutdown and joins all active worker pthreads
void worker_pool_stop();

#endif // SENTINELFS_EVENT_QUEUE_H
