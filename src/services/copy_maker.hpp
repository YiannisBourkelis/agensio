// The copies of cached files made once (docs/design-compression.md 5): a site with
// response_compression on gets brotli 11 and gzip 9 copies of each compressible file it
// caches, made here on one low-priority thread, never on a worker (brotli 11 takes about 60 ms
// per 100 KB), and attached to the file's CacheEntry as its `br` and `gzip` twins are, in memory
// only, charged to the cache's byte budget with the file, served by the twin code unchanged. A
// file with a twin on disk keeps it and gets no copy; a file whose entry was evicted while its
// copies were made gets nothing. The queue is bounded: a fill past it serves the file as today
// and the next fill asks again.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <thread>

#include "cache.hpp"

namespace agensio {

class CopyMaker {
public:
    // `max_size`: files above it get no copy (8 MB in the design).
    explicit CopyMaker(FileCache& cache, std::size_t max_size = 8u << 20, std::size_t queue_limit = 1024);
    ~CopyMaker();
    CopyMaker(const CopyMaker&) = delete;
    CopyMaker& operator=(const CopyMaker&) = delete;

    // Asks for the entry's copies. False, nothing queued, when the queue is full or the entry does
    // not qualify (its bytes beyond max_size, a twin already there); the caller serves the file
    // as it is. Cheap: one lock, one push.
    bool ask(EntryPtr entry);

    // For status: copies made, bytes they hold, entries refused by the queue or the budget.
    struct Counts {
        std::uint64_t made = 0, bytes = 0, queue_full = 0, budget_refused = 0, failed = 0;
    };
    Counts counts() const noexcept;

private:
    void run();
    void make(const EntryPtr& entry);
    FileCache& cache_;
    const std::size_t max_size_;
    const std::size_t limit_;
    std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<EntryPtr> queue_;
    bool stopping_ = false;
    std::atomic<std::uint64_t> made_{0}, bytes_{0}, queue_full_{0}, budget_refused_{0}, failed_{0};
    std::thread thread_;
};

}  // namespace agensio
