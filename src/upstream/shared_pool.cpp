#include "upstream/shared_pool.hpp"

#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef AGENSIO_HAS_TLS
#include <openssl/ssl.h>
#endif

namespace agensio {

void SharedPool::close(Idle& c) noexcept {
#ifdef AGENSIO_HAS_TLS
    if (c.tls) SSL_free(static_cast<SSL*>(c.tls));  // its socket BIO does not own the descriptor
#endif
    c.tls = nullptr;
#ifndef _WIN32
    if (c.fd >= 0) ::close(c.fd);
#endif
    c.fd = -1;
}

SharedPool::~SharedPool() {
    for (auto& [key, e] : entries_)
        for (Idle& c : e->idle_) close(c);
}

SharedPool::Entry& SharedPool::entry(const std::string& key) {
    const std::lock_guard<std::mutex> lock(mutex_);
    auto& slot = entries_[key];
    if (!slot) slot = std::make_unique<Entry>();
    return *slot;
}

void SharedPool::drop_front(Entry& e, std::size_t n) noexcept {
    if (n == 0) return;
    for (std::size_t i = 0; i < n; ++i) close(e.idle_[i]);
    e.idle_.erase(e.idle_.begin(), e.idle_.begin() + static_cast<std::ptrdiff_t>(n));
    e.count_.fetch_sub(static_cast<std::uint32_t>(n), std::memory_order_relaxed);
    e.expired_.fetch_add(n, std::memory_order_relaxed);
    total_.fetch_sub(n, std::memory_order_relaxed);
}

void SharedPool::give(Entry& e, Idle c, std::size_t max_idle, std::chrono::milliseconds idle_timeout) {
    e.given_.fetch_add(1, std::memory_order_relaxed);
    if (max_idle == 0) {
        e.expired_.fetch_add(1, std::memory_order_relaxed);
        close(c);
        return;
    }
    const std::lock_guard<std::mutex> lock(e.mutex_);
    e.idle_timeout_ = idle_timeout;
    if (e.idle_.size() >= max_idle) drop_front(e, e.idle_.size() - max_idle + 1);
    e.idle_.push_back(c);
    e.count_.fetch_add(1, std::memory_order_relaxed);
    total_.fetch_add(1, std::memory_order_relaxed);
}

bool SharedPool::take(Entry& e, Idle& out, Clock::time_point now) {
    const std::lock_guard<std::mutex> lock(e.mutex_);
    if (e.idle_.empty()) return false;
    // Given in time order, so when the newest has expired they all have.
    if (expired(e, e.idle_.back(), now)) {
        drop_front(e, e.idle_.size());
        return false;
    }
    out = e.idle_.back();
    e.idle_.pop_back();
    e.count_.fetch_sub(1, std::memory_order_relaxed);
    e.taken_.fetch_add(1, std::memory_order_relaxed);
    total_.fetch_sub(1, std::memory_order_relaxed);
    return true;
}

bool SharedPool::sweep_due(Clock::time_point now) noexcept {
    const std::int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::int64_t last = swept_at_.load(std::memory_order_relaxed);
    return ms - last >= 1000 && swept_at_.compare_exchange_strong(last, ms, std::memory_order_relaxed);
}

void SharedPool::sweep(Clock::time_point now) {
    std::vector<Entry*> all;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        all.reserve(entries_.size());
        for (auto& [key, e] : entries_) all.push_back(e.get());
    }
    for (Entry* e : all) {
        if (e->idle() == 0) continue;
        const std::lock_guard<std::mutex> lock(e->mutex_);
        std::size_t n = 0;
        while (n < e->idle_.size() && expired(*e, e->idle_[n], now)) ++n;
        drop_front(*e, n);
    }
}

std::vector<std::pair<std::string, SharedPool::Stats>> SharedPool::stats() const {
    std::vector<std::pair<std::string, Stats>> out;
    const std::lock_guard<std::mutex> lock(mutex_);
    out.reserve(entries_.size());
    for (const auto& [key, e] : entries_) {
        Stats s;
        s.idle = e->count_.load(std::memory_order_relaxed);
        s.given = e->given_.load(std::memory_order_relaxed);
        s.taken = e->taken_.load(std::memory_order_relaxed);
        s.expired = e->expired_.load(std::memory_order_relaxed);
        s.dead = e->dead_.load(std::memory_order_relaxed);
        out.emplace_back(key, s);
    }
    return out;
}

}  // namespace agensio
