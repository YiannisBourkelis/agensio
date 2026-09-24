// The worker's deadline heap (design-http3 6.8): a connection has one deadline, the
// earliest of its PTO, ACK delay, pacing, idle and closing timers, and stores its index
// here; the worker's one steady_timer is re-armed only when the earliest deadline of
// all changes. No connection owns a timer, so nothing reprograms the reactor's timerfd
// per packet (the D1 finding).
#pragma once

#include <chrono>
#include <cstddef>
#include <utility>
#include <vector>

namespace agensio::quic {

struct Timed {
    std::chrono::steady_clock::time_point deadline{};  // time_point::max() = none
    std::size_t heap_index = static_cast<std::size_t>(-1);
};

class TimerHeap {
public:
    static constexpr std::size_t npos = static_cast<std::size_t>(-1);
    bool empty() const noexcept { return v_.empty(); }
    Timed* top() const noexcept { return v_.empty() ? nullptr : v_.front(); }
    std::chrono::steady_clock::time_point earliest() const noexcept {
        return v_.empty() ? std::chrono::steady_clock::time_point::max() : v_.front()->deadline;
    }
    // The deadline of t changed (or t is new): keeps the heap ordered.
    void update(Timed* t) {
        if (t->heap_index == npos) {
            t->heap_index = v_.size();
            v_.push_back(t);
            up(t->heap_index);
            return;
        }
        const std::size_t i = t->heap_index;
        if (!up(i)) down(i);
    }
    void remove(Timed* t) {
        const std::size_t i = t->heap_index;
        if (i == npos) return;
        t->heap_index = npos;
        Timed* last = v_.back();
        v_.pop_back();
        if (i == v_.size()) return;
        v_[i] = last;
        last->heap_index = i;
        if (!up(i)) down(i);
    }

private:
    bool up(std::size_t i) {
        bool moved = false;
        while (i > 0) {
            const std::size_t parent = (i - 1) / 2;
            if (!(v_[i]->deadline < v_[parent]->deadline)) break;
            swap(i, parent);
            i = parent;
            moved = true;
        }
        return moved;
    }
    void down(std::size_t i) {
        for (;;) {
            const std::size_t l = 2 * i + 1, r = l + 1;
            std::size_t m = i;
            if (l < v_.size() && v_[l]->deadline < v_[m]->deadline) m = l;
            if (r < v_.size() && v_[r]->deadline < v_[m]->deadline) m = r;
            if (m == i) return;
            swap(i, m);
            i = m;
        }
    }
    void swap(std::size_t a, std::size_t b) noexcept {
        std::swap(v_[a], v_[b]);
        v_[a]->heap_index = a;
        v_[b]->heap_index = b;
    }
    std::vector<Timed*> v_;
};

}  // namespace agensio::quic
