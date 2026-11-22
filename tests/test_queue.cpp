/**
 * ============================================================================
 * SentinelFS - Concurrent EventQueue Stress Test
 * Module Purpose: Validates multithreaded EventQueue push/pop under heavy
 *                 concurrency with raw POSIX pthreads. Verifies that zero
 *                 items are lost or duplicated.
 * ============================================================================
 */

#include "event_queue.h"
#include <iostream>
#include <vector>
#include <atomic>
#include <pthread.h>
#include <cassert>
#include <csignal>

// Definition of global shutdown flag declared extern in common.h.
// monitor.o (included in MODULE_OBJS) references g_shutdown in monitor_run().
// In the main executable, g_shutdown is defined in src/main.cpp.
// Because standalone test programs link MODULE_OBJS without main.o,
// this definition satisfies the symbol reference at link time.
volatile sig_atomic_t g_shutdown = 0;

static const int NUM_PRODUCERS = 4;
static const int NUM_CONSUMERS = 4;
static const int ITEMS_PER_PRODUCER = 1000;
static const int TOTAL_ITEMS = NUM_PRODUCERS * ITEMS_PER_PRODUCER;

struct ProdArg {
    EventQueue* q;
    int prod_id;
};

static void* producer_thread(void* arg) {
    ProdArg* pa = static_cast<ProdArg*>(arg);
    for (int i = 0; i < ITEMS_PER_PRODUCER; ++i) {
        Event ev;
        ev.timestamp = time(nullptr);
        // Encode producer ID and sequence into raw_mask for verification
        ev.raw_mask = static_cast<uint32_t>(pa->prod_id * ITEMS_PER_PRODUCER + i);
        ev.path = "item_" + std::to_string(ev.raw_mask);
        ev.old_path = "";
        ev.type = MODIFIED;
        pa->q->push(ev);
    }
    return nullptr;
}

struct ConsArg {
    EventQueue* q;
    std::vector<int>* received;
    pthread_mutex_t* rec_mutex;
    std::atomic<int>* total_consumed;
};

static void* consumer_thread(void* arg) {
    ConsArg* ca = static_cast<ConsArg*>(arg);
    Event ev;
    while (ca->q->pop(ev)) {
        pthread_mutex_lock(ca->rec_mutex);
        ca->received->push_back(static_cast<int>(ev.raw_mask));
        pthread_mutex_unlock(ca->rec_mutex);

        int count = ++(*(ca->total_consumed));
        if (count >= TOTAL_ITEMS) {
            ca->q->shutdown();
        }
    }
    return nullptr;
}

int main() {
    std::cout << "Starting EventQueue Concurrent Stress Test (" << TOTAL_ITEMS << " items)...\n";

    EventQueue q(128); // Bounded small queue to force frequent blocking on condition variables

    std::vector<int> received_items;
    received_items.reserve(TOTAL_ITEMS);
    pthread_mutex_t rec_mutex = PTHREAD_MUTEX_INITIALIZER;
    std::atomic<int> total_consumed(0);

    pthread_t consumers[NUM_CONSUMERS];
    ConsArg ca{&q, &received_items, &rec_mutex, &total_consumed};
    for (int i = 0; i < NUM_CONSUMERS; ++i) {
        pthread_create(&consumers[i], nullptr, consumer_thread, &ca);
    }

    pthread_t producers[NUM_PRODUCERS];
    ProdArg pa[NUM_PRODUCERS];
    for (int i = 0; i < NUM_PRODUCERS; ++i) {
        pa[i] = ProdArg{&q, i};
        pthread_create(&producers[i], nullptr, producer_thread, &pa[i]);
    }

    // Join producers
    for (int i = 0; i < NUM_PRODUCERS; ++i) {
        pthread_join(producers[i], nullptr);
    }

    // Join consumers
    for (int i = 0; i < NUM_CONSUMERS; ++i) {
        pthread_join(consumers[i], nullptr);
    }

    // Verification
    if (static_cast<int>(received_items.size()) != TOTAL_ITEMS) {
        std::cerr << "[FAIL] Total items mismatch: expected " << TOTAL_ITEMS
                  << ", received " << received_items.size() << std::endl;
        return 1;
    }

    std::vector<bool> seen(TOTAL_ITEMS, false);
    for (int id : received_items) {
        if (id < 0 || id >= TOTAL_ITEMS) {
            std::cerr << "[FAIL] Received out-of-bounds item ID: " << id << std::endl;
            return 1;
        }
        if (seen[id]) {
            std::cerr << "[FAIL] Duplicate item ID observed: " << id << std::endl;
            return 1;
        }
        seen[id] = true;
    }

    for (int i = 0; i < TOTAL_ITEMS; ++i) {
        if (!seen[i]) {
            std::cerr << "[FAIL] Lost item ID: " << i << std::endl;
            return 1;
        }
    }

    std::cout << "[PASS] EventQueue Concurrent Stress Test: All " << TOTAL_ITEMS
              << " items safely delivered with 0 loss and 0 duplicates.\n";
    return 0;
}
