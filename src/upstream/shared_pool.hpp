// Idle connections to origins that belong to no worker (docs/design-upstream-pool.md 4.1): the
// second level of the upstream pool. A worker hands a connection here once it has taken it out of
// its own event loop, and any worker takes one from here and puts it into its own. What is held is
// a bare descriptor (and, for a TLS origin, the TLS session), so nothing of one worker is ever
// touched by another: the pattern of the file cache, a shared store under a lock beside a
// lock-free part per worker.
//
// One entry per pool key, with its own mutex: two workers contend only when they take or give a
// connection of the same origin at the same instant. An entry's count is readable without the
// lock, so a worker that finds it empty pays one load. Entries are never moved or freed while the
// store lives.
#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace agensio {

class SharedPool {
public:
    using Clock = std::chrono::steady_clock;

    // A connection out of every event loop.
    struct Idle {
        int fd = -1;
        int family = 0;        // of the socket (AF_INET, AF_INET6, AF_UNIX): what assigning it to a loop needs
        void* tls = nullptr;   // the TLS session (an SSL*) of an https origin's connection
        Clock::time_point released_at{};
    };

    struct Stats {
        std::uint64_t idle = 0;     // held now
        std::uint64_t given = 0;    // handed to the store since the start
        std::uint64_t taken = 0;    // taken from it
        std::uint64_t expired = 0;  // closed there: past idle_timeout, or beyond max_idle
        std::uint64_t dead = 0;     // found closed by the origin when taken
    };

    class Entry {
    public:
        std::uint32_t idle() const noexcept { return count_.load(std::memory_order_relaxed); }
        // A worker that took a connection and found the origin had closed it says so (the status count).
        void note_dead() noexcept { dead_.fetch_add(1, std::memory_order_relaxed); }

    private:
        friend class SharedPool;
        std::atomic<std::uint32_t> count_{0};
        std::mutex mutex_;
        std::vector<Idle> idle_;  // oldest first: the newest is taken, the oldest expires
        std::chrono::milliseconds idle_timeout_{0};  // of the last connection given; 0 keeps them
        std::atomic<std::uint64_t> given_{0}, taken_{0}, expired_{0}, dead_{0};
    };

    SharedPool() = default;
    ~SharedPool();  // closes what it holds
    SharedPool(const SharedPool&) = delete;
    SharedPool& operator=(const SharedPool&) = delete;

    // The entry of a pool key, made on first use. The reference stays valid while the store lives:
    // a worker asks once per origin and keeps it.
    Entry& entry(const std::string& key);

    // Hands `c` to the store, which owns it from here. An entry holds at most `max_idle`: beyond
    // it the oldest is closed (max_idle 0 closes `c`).
    void give(Entry& e, Idle c, std::size_t max_idle, std::chrono::milliseconds idle_timeout);

    // The newest connection of `e`, the caller's from here; false when the entry holds none that
    // has not expired (the expired ones are closed on the way).
    bool take(Entry& e, Idle& out, Clock::time_point now);

    // Closes every expired connection of every entry. The workers' ticks share the job: sweep_due
    // is true for one caller a second.
    void sweep(Clock::time_point now);
    bool sweep_due(Clock::time_point now) noexcept;

    std::size_t idle_total() const noexcept { return total_.load(std::memory_order_relaxed); }
    std::vector<std::pair<std::string, Stats>> stats() const;  // per pool key, for status

    // Frees the session and closes the descriptor of a connection the caller owns.
    static void close(Idle& c) noexcept;

private:
    static bool expired(const Entry& e, const Idle& c, Clock::time_point now) noexcept {
        return e.idle_timeout_.count() > 0 && now - c.released_at > e.idle_timeout_;
    }
    void drop_front(Entry& e, std::size_t n) noexcept;  // closes the n oldest; the entry's lock held

    mutable std::mutex mutex_;  // the map alone
    std::unordered_map<std::string, std::unique_ptr<Entry>> entries_;
    std::atomic<std::size_t> total_{0};
    std::atomic<std::int64_t> swept_at_{0};  // steady-clock milliseconds of the last sweep
};

}  // namespace agensio
