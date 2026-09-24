// A QUIC stream's transport state (RFC 9000 sections 2 to 4): what arrived, in order or
// not, and how much of it the application took (the credit it returns); what we send,
// which is the application's head bytes followed by a memory body or a file, addressed
// by offset so a lost range is re-framed from the same source, and what of it is
// acknowledged. The application embeds one in its own stream object (H3Stream) and the
// connection finds it by id through the application.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "file.hpp"
#include "quic/range_set.hpp"

namespace agensio::quic {

inline constexpr std::uint64_t kNoSize = ~std::uint64_t{0};

inline bool stream_is_bidi(std::uint64_t id) noexcept { return (id & 0x2) == 0; }
inline bool stream_is_client(std::uint64_t id) noexcept { return (id & 0x1) == 0; }

struct QuicStream {
    void* owner = nullptr;  // the application's stream object holding this one (set once)
    std::uint64_t id = 0;
    bool open = false;  // known to the connection

    // ---- receive ----
    std::string rbuf;         // bytes from absolute offset roff; [rpos, size) not yet consumed
    std::uint64_t roff = 0;
    std::size_t rpos = 0;
    RangeSet rranges;         // what arrived, absolute
    std::uint64_t highest = 0;    // the highest offset received + 1 (connection-level accounting)
    std::uint64_t final_size = kNoSize;
    bool fin_seen = false;        // the final size is known
    bool fin_delivered = false;   // the application saw the end
    std::uint64_t max_recv = 0;   // the offset the peer may send up to (our MAX_STREAM_DATA)
    std::uint64_t window = 0;     // the window we keep open beyond what was consumed
    bool credit_due = false;      // a MAX_STREAM_DATA should go out
    bool reset_received = false;
    std::uint64_t reset_code = 0;
    bool stop_sending_received = false;
    std::uint64_t stop_code = 0;

    std::uint64_t consumed() const noexcept { return roff + rpos; }
    std::size_t available() const noexcept {
        const std::uint64_t c = consumed();
        return static_cast<std::size_t>(rranges.contiguous_from(c) - c);
    }
    const char* data() const noexcept { return rbuf.data() + rpos; }
    bool at_end() const noexcept { return fin_seen && consumed() == final_size; }
    void consume(std::size_t n) noexcept {
        rpos += n;
        if (rpos == rbuf.size()) {
            roff += rpos;
            rbuf.clear();
            rpos = 0;
        }
    }

    // ---- send ----
    std::string head;             // the first bytes of the stream (a frame header, a field section)
    std::uint64_t head_base = 0;  // bytes dropped from the front of head once acknowledged (trim_head streams)
    bool trim_head = false;       // a long-lived stream whose head grows: acknowledged bytes are dropped
    std::string_view mem;         // a memory body after the head
    const File* file = nullptr;   // or a file region after the head
    std::uint64_t file_offset = 0;
    std::uint64_t file_len = 0;
    std::vector<char> chunk;      // a window of the file read ahead
    std::uint64_t chunk_off = 0;
    std::size_t chunk_len = 0;
    bool fin = false;             // FIN after the last byte
    std::uint64_t total = 0;      // head + body
    std::uint64_t next = 0;       // the next new byte to send
    RangeSet lost;                // ranges to send again, first
    RangeSet acked;
    bool fin_sent = false;
    bool fin_acked = false;
    std::uint64_t max_send = 0;   // the peer's MAX_STREAM_DATA
    bool blocked_reported = false;
    bool ready = false;           // in the connection's ready list
    QuicStream* next_ready = nullptr;
    bool reset_sent = false;
    std::uint64_t reset_send_code = 0;
    bool reset_due = false;       // a RESET_STREAM should go out
    bool stop_due = false;        // a STOP_SENDING should go out
    std::uint64_t stop_send_code = 0;
    bool send_done = false;       // every byte and the FIN acknowledged, or reset acknowledged

    bool has_unsent() const noexcept { return !lost.empty() || next < total || (fin && !fin_sent); }
    std::uint64_t body_len() const noexcept { return total - head_base - head.size(); }
    std::uint64_t head_end() const noexcept { return head_base + head.size(); }

    void reset_quic() {
        id = 0;
        open = false;
        rbuf.clear();
        roff = 0;
        rpos = 0;
        rranges.clear();
        highest = 0;
        final_size = kNoSize;
        fin_seen = fin_delivered = false;
        max_recv = window = 0;
        credit_due = reset_received = stop_sending_received = false;
        reset_code = stop_code = 0;
        head.clear();
        head_base = 0;
        trim_head = false;
        mem = {};
        file = nullptr;
        file_offset = file_len = 0;
        chunk_off = chunk_len = 0;
        fin = false;
        total = next = 0;
        lost.clear();
        acked.clear();
        fin_sent = fin_acked = false;
        max_send = 0;
        blocked_reported = ready = false;
        next_ready = nullptr;
        reset_sent = reset_due = stop_due = send_done = false;
        reset_send_code = stop_send_code = 0;
    }
};

}  // namespace agensio::quic
