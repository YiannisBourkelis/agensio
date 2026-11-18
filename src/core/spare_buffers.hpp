// Buffers an answer needs only while it is on its way belong to the worker, not to the connection:
// a connection takes one when it has bytes to put there and gives it back when they are with the
// kernel, so what a worker holds follows the answers in flight, not the connections open
// (docs/design-proxy-streaming.md 11). Until 0.1.0-alpha.147 each connection kept its own from its
// first large answer to its idle shed: 16 KB of write coalescing over TLS and a 64 KB piece for
// files and streamed bodies, 80 KB times the busy connections.
//
// One set per thread (a worker is a thread, and one worker's state is never another's): no lock.
// The spares kept are few; beyond them a buffer is allocated and freed with its answer.
//
// A lend and a take run with every answer over TLS, so they only swap three pointers with a slot
// of a fixed array: the slots from `n_` on are always empty, with no capacity. Until 0.1.0-alpha.148
// the spares were a vector of vectors, a push_back and a pop_back each time with a moved-from
// vector destroyed: the lending cost 178 instructions an answer on HTTPS 1 KB (callgrind), about 115 now.
#pragma once

#include <array>
#include <cstddef>
#include <vector>

namespace agensio {

template <std::size_t Keep>
class SpareBuffers {
public:
    // `to` (empty, no capacity) gets a buffer of at least `capacity` bytes, its size 0.
    void lend_empty(std::vector<char>& to, std::size_t capacity) {
        if (n_ != 0 && slots_[n_ - 1].capacity() >= capacity) {
            to.swap(slots_[--n_]);
            leave_empty(slots_[n_]);
            return;
        }
        to.reserve(capacity);
    }
    // `to` (empty) gets a buffer of exactly `size` bytes, their content whatever was there.
    void lend_sized(std::vector<char>& to, std::size_t size) {
        if (n_ != 0 && slots_[n_ - 1].size() == size) {
            to.swap(slots_[--n_]);
            leave_empty(slots_[n_]);
            return;
        }
        to.resize(size);
    }
    // The buffer back; `from` is left without capacity. `sized`: kept at its size (lend_sized's).
    void take(std::vector<char>& from, bool sized) {
        if (from.capacity() == 0) return;
        if (n_ < Keep) {
            if (!sized) from.clear();
            from.swap(slots_[n_++]);  // the slot was empty: `from` is left without capacity
            return;
        }
        std::vector<char>().swap(from);
    }
    std::size_t spares() const noexcept { return n_; }

private:
    // A slot past `n_` holds nothing. `to` holds nothing when lent to (the callers' rule); if it did,
    // its block is freed here as the vector of vectors' pop_back freed it.
    static void leave_empty(std::vector<char>& slot) {
        if (slot.capacity() != 0) [[unlikely]]
            std::vector<char>().swap(slot);
    }

    std::array<std::vector<char>, Keep> slots_{};
    std::size_t n_ = 0;
};

// The write-coalescing buffers of TLS connections (one record and a head) and the pieces files and
// streamed bodies are read into (server.stream_chunk_size), per worker thread.
inline SpareBuffers<16>& record_spares() {
    thread_local SpareBuffers<16> s;
    return s;
}
inline SpareBuffers<8>& piece_spares() {
    thread_local SpareBuffers<8> s;
    return s;
}

}  // namespace agensio
