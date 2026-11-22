/**
 * ============================================================================
 * Warden - Thread-Safe Bounded Event Queue Implementation
 * Module Purpose: Real POSIX pthread bounded queue synchronization with
 *                 mutex and condition variables, plus worker thread lifecycle.
 * Owner: Krishna + Ashutosh
 * ============================================================================
 */

#include "event_queue.h"
#include "classifier.h"
#include "logger.h"
#include "analyzer.h"
#include "ui.h"

#include <iostream>
#include <vector>

EventQueue::EventQueue(size_t max_capacity)
    : max_capacity_(max_capacity > 0 ? max_capacity : 1024), shutdown_(false) {
    pthread_mutex_init(&mutex_, nullptr);
    pthread_cond_init(&not_empty_, nullptr);
    pthread_cond_init(&not_full_, nullptr);
}

EventQueue::~EventQueue() {
    shutdown();
    pthread_mutex_destroy(&mutex_);
    pthread_cond_destroy(&not_empty_);
    pthread_cond_destroy(&not_full_);
}

void EventQueue::push(const Event& ev) {
    pthread_mutex_lock(&mutex_);
    while (queue_.size() >= max_capacity_ && !shutdown_) {
        pthread_cond_wait(&not_full_, &mutex_);
    }

    if (shutdown_) {
        pthread_mutex_unlock(&mutex_);
        return;
    }

    queue_.push(ev);
    pthread_cond_signal(&not_empty_);
    pthread_mutex_unlock(&mutex_);
}

bool EventQueue::pop(Event& out_ev) {
    pthread_mutex_lock(&mutex_);
    while (queue_.empty() && !shutdown_) {
        pthread_cond_wait(&not_empty_, &mutex_);
    }

    if (queue_.empty() && shutdown_) {
        pthread_mutex_unlock(&mutex_);
        return false;
    }

    out_ev = queue_.front();
    queue_.pop();
    pthread_cond_signal(&not_full_);
    pthread_mutex_unlock(&mutex_);
    return true;
}

void EventQueue::shutdown() {
    pthread_mutex_lock(&mutex_);
    if (!shutdown_) {
        shutdown_ = true;
        pthread_cond_broadcast(&not_empty_);
        pthread_cond_broadcast(&not_full_);
    }
    pthread_mutex_unlock(&mutex_);
}

size_t EventQueue::size() {
    pthread_mutex_lock(&mutex_);
    size_t s = queue_.size();
    pthread_mutex_unlock(&mutex_);
    return s;
}

size_t EventQueue::capacity() const {
    return max_capacity_;
}

// Worker thread context
struct WorkerContext {
    EventQueue* queue;
    const Config* config;
};

static std::vector<pthread_t> g_worker_threads;
static bool g_workers_running = false;

static void* worker_thread_func(void* arg) {
    WorkerContext* ctx = static_cast<WorkerContext*>(arg);
    EventQueue& queue = *(ctx->queue);
    const Config& config = *(ctx->config);

    Event ev;
    while (queue.pop(ev)) {
        try {
            ClassifiedEvent ce = classify(ev, config);
            // Skip logging if classifier determines no actual change occurred (false alarm filter)
            if (ce.detail != "NO_CHANGE") {
                log_event(ce);
                analyzer_record(ce, config);
                ui_stats_record_event(ce, queue.size());
            }
        } catch (const std::exception& ex) {
            std::cerr << ui_error_mark() << " Worker exception processing event on '"
                      << ev.path << "': " << ex.what() << std::endl;
        } catch (...) {
            std::cerr << ui_error_mark() << " Worker unknown exception processing event on '"
                      << ev.path << "'" << std::endl;
        }
    }

    return nullptr;
}

static WorkerContext g_worker_ctx;

bool worker_pool_start(int n, EventQueue& queue, const Config& config) {
    if (g_workers_running) {
        return true;
    }

    int count = (n > 0) ? n : 4;
    g_worker_ctx.queue = &queue;
    g_worker_ctx.config = &config;
    g_worker_threads.resize(count);

    for (int i = 0; i < count; ++i) {
        if (pthread_create(&g_worker_threads[i], nullptr, worker_thread_func, &g_worker_ctx) != 0) {
            std::cerr << ui_error_mark() << " Failed to spawn worker thread #" << i << std::endl;
            return false;
        }
    }

    g_workers_running = true;
    return true;
}

void worker_pool_stop() {
    if (!g_workers_running) {
        return;
    }

    if (g_worker_ctx.queue) {
        g_worker_ctx.queue->shutdown();
    }

    for (pthread_t tid : g_worker_threads) {
        pthread_join(tid, nullptr);
    }

    g_worker_threads.clear();
    g_workers_running = false;
}
