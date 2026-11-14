// Buffers an answer needs only while it is on its way belong to the worker, not to the connection:
// a connection takes one when it has bytes to put there and gives it back when they are with the
// kernel, so what a worker holds follows the answers in flight, not the connections open
// (docs/design-proxy-streaming.md 11). Until 0.1.0-alpha.147 each connection kept its own from its
// first large answer to its idle shed: 16 KB of write coalescing over TLS and a 64 KB piece for
// files and streamed bodies, 80 KB times the busy connections.
//
// One set per thread (a worker is a thread, and one worker's state is never another's): no lock.
// The spares kept are few; beyond them a buffer is allocated and freed with its answer.
#pragma once

#include <cstddef>
#include <utility>
#include <vector>

namespace agensio {

class SpareBuffers {
public:
    explicit SpareBuffers(std::size_t keep) : keep_(keep) { spares_.reserve(keep); }

    // `to` (empty, no capacity) gets a buffer of at least `capacity` bytes, its size 0.
    void lend_empty(std::vector<char>& to, std::size_t capacity) {
        if (!spares_.empty() && spares_.back().capacity() >= capacity) {
            to.swap(spares_.back());
            spares_.pop_back();
            return;
        }
        to.reserve(capacity);
    }
    // `to` (empty) gets a buffer of exactly `size` bytes, their content whatever was there.
    void lend_sized(std::vector<char>& to, std::size_t size) {
        if (!spares_.empty() && spares_.back().size() == size) {
            to.swap(spares_.back());
            spares_.pop_back();
            return;
        }
        to.resize(size);
    }
    // The buffer back; `from` is left without capacity. `sized`: kept at its size (lend_sized's).
    void take(std::vector<char>& from, bool sized) {
        if (from.capacity() == 0) return;
        if (spares_.size() < keep_) {
            if (!sized) from.clear();
            spares_.push_back(std::move(from));
        }
        std::vector<char>().swap(from);
    }
    std::size_t spares() const noexcept { return spares_.size(); }

private:
    std::size_t keep_;
    std::vector<std::vector<char>> spares_;
};

// The write-coalescing buffers of TLS connections (one record and a head) and the pieces files and
// streamed bodies are read into (server.stream_chunk_size), per worker thread.
inline SpareBuffers& record_spares() {
    thread_local SpareBuffers s(16);
    return s;
}
inline SpareBuffers& piece_spares() {
    thread_local SpareBuffers s(8);
    return s;
}

}  // namespace agensio
