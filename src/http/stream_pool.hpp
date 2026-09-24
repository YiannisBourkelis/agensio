// The per-connection table of active streams and the pool of released ones, shared by
// HTTP/2 and HTTP/3 (design-http2 6.6 and 7.3, measured 2026-09-24): a stream is found by
// its slot in O(1), released by moving the last active stream into its slot, and kept
// with its buffers for the next request up to the concurrency limit, because at its
// peak the connection held that many anyway and a client that keeps a hundred streams
// busy would otherwise construct and free a stream per request (a fifth of the CPU of
// a small answer). An idle connection sheds the pool. The stream type provides `slot`
// and `reset()`.
#pragma once

#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

namespace agensio::http {

template <class S>
class StreamPool {
public:
    std::size_t active() const noexcept { return active_.size(); }
    std::size_t pooled() const noexcept { return pool_.size(); }
    std::vector<std::unique_ptr<S>>& all() noexcept { return active_; }
    const std::vector<std::unique_ptr<S>>& all() const noexcept { return active_; }

    // A stream from the pool, or a new one that `init` sets up once (the owner links
    // its body source there); its slot is set and it is active from here.
    template <class Init>
    S& take(Init&& init) {
        std::unique_ptr<S> s;
        if (!pool_.empty()) {
            s = std::move(pool_.back());
            pool_.pop_back();
        } else {
            s = std::make_unique<S>();
            init(*s);
        }
        s->slot = active_.size();
        S& ref = *s;
        active_.push_back(std::move(s));
        return ref;
    }

    // Out of the table by its slot; reset and kept for the next request while the pool
    // is below `keep` streams. False when the stream was not in the table.
    bool release(S& s, std::size_t keep) {
        const std::size_t i = s.slot;
        if (i >= active_.size() || active_[i].get() != &s) return false;
        std::unique_ptr<S> p = std::move(active_[i]);
        active_[i] = std::move(active_.back());
        active_.pop_back();
        if (i < active_.size()) active_[i]->slot = i;
        p->reset();
        if (pool_.size() < keep) pool_.push_back(std::move(p));
        return true;
    }

    void shed() { pool_.clear(); }

private:
    std::vector<std::unique_ptr<S>> active_;
    std::vector<std::unique_ptr<S>> pool_;
};

}  // namespace agensio::http
