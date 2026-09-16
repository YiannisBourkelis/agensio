// HTTP/1.1 chunked transfer coding (RFC 9112 section 7.1): the encoder helpers used by the
// response writer for bodies of unknown length, and the incremental decoder the
// connection runs over request bodies. Pure functions and a small state machine, no I/O:
// unit-tested byte by byte and fuzzed (tests/fuzz/fuzz_chunked.cpp).
#pragma once

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace agensio {

// "0\r\n\r\n": the last-chunk line plus the empty trailer section.
inline constexpr std::string_view kLastChunk = "0\r\n\r\n";

using ChunkSizeBuffer = std::array<char, 20>;  // 16 hex digits + CRLF

// Formats the chunk-size line "<hex>\r\n" for a chunk of n bytes into buf.
inline std::string_view chunk_size_line(std::uint64_t n, ChunkSizeBuffer& buf) noexcept {
    auto r = std::to_chars(buf.data(), buf.data() + 16, n, 16);
    *r.ptr++ = '\r';
    *r.ptr++ = '\n';
    return std::string_view(buf.data(), static_cast<std::size_t>(r.ptr - buf.data()));
}

// Incremental decoder. Feed it any split of the wire bytes; it copies decoded body bytes
// out and reports exactly how much input it used, so bytes of a pipelined next request
// that follow the final CRLF are never touched. Chunk extensions and trailer fields are
// accepted and discarded (bounded in length); obs-fold in trailers, bare LF, non-hex
// sizes and sizes over 16 hex digits are errors.
class ChunkedDecoder {
public:
    enum class Status {
        ok,     // consumed/produced updated; produced == 0 means more input is needed
        done,   // the final CRLF was consumed; the body is complete
        error,  // malformed framing: the connection must be closed
    };

    static constexpr std::size_t kMaxLine = 4096;      // chunk-ext or one trailer line
    static constexpr std::size_t kMaxTrailers = 8192;  // all trailer bytes together

    void reset() noexcept { *this = ChunkedDecoder{}; }
    bool done() const noexcept { return state_ == State::complete; }

    // Decodes from `in` into out[0, out_cap). Returns when `in` is exhausted, `out` is full,
    // the body is complete, or on error. `consumed` and `produced` are set (not added to).
    Status decode(std::string_view in, std::size_t& consumed, char* out, std::size_t out_cap,
                  std::size_t& produced) noexcept {
        consumed = 0;
        produced = 0;
        while (consumed < in.size()) {
            const unsigned char c = static_cast<unsigned char>(in[consumed]);
            switch (state_) {
                case State::size: {
                    const int d = hex_value(c);
                    if (d >= 0) {
                        if (++digits_ > 16) return fail();
                        remaining_ = (remaining_ << 4) | static_cast<std::uint64_t>(d);
                        ++consumed;
                        break;
                    }
                    if (digits_ == 0) return fail();
                    if (c == ';') {
                        state_ = State::ext;
                        line_ = 0;
                    } else if (c == '\r') {
                        state_ = State::size_lf;
                    } else {
                        return fail();
                    }
                    ++consumed;
                    break;
                }
                case State::ext:
                    if (c == '\r') state_ = State::size_lf;
                    else if (c == '\n' || ++line_ > kMaxLine) return fail();
                    ++consumed;
                    break;
                case State::size_lf:
                    if (c != '\n') return fail();
                    ++consumed;
                    if (remaining_ == 0) {
                        state_ = State::trailer_start;
                        line_ = 0;
                    } else {
                        state_ = State::data;
                    }
                    break;
                case State::data: {
                    if (produced == out_cap) return Status::ok;  // output full; caller comes back
                    const std::size_t take = static_cast<std::size_t>(
                        std::min<std::uint64_t>(remaining_, std::min(in.size() - consumed, out_cap - produced)));
                    std::memcpy(out + produced, in.data() + consumed, take);
                    produced += take;
                    consumed += take;
                    remaining_ -= take;
                    if (remaining_ == 0) state_ = State::data_cr;
                    break;
                }
                case State::data_cr:
                    if (c != '\r') return fail();
                    state_ = State::data_lf;
                    ++consumed;
                    break;
                case State::data_lf:
                    if (c != '\n') return fail();
                    state_ = State::size;
                    digits_ = 0;
                    ++consumed;
                    break;
                case State::trailer_start:  // beginning of a trailer line, or the final CRLF
                    if (c == '\r') state_ = State::end_lf;
                    else if (c == ' ' || c == '\t' || c == '\n') return fail();  // obs-fold / bare LF
                    else state_ = State::trailer_line;
                    ++consumed;
                    ++line_;
                    break;
                case State::trailer_line:
                    if (c == '\r') state_ = State::trailer_lf;
                    else if (c == '\n') return fail();
                    ++consumed;
                    if (++line_ > kMaxTrailers) return fail();
                    break;
                case State::trailer_lf:
                    if (c != '\n') return fail();
                    state_ = State::trailer_start;
                    ++consumed;
                    break;
                case State::end_lf:
                    if (c != '\n') return fail();
                    state_ = State::complete;
                    ++consumed;
                    return Status::done;
                case State::complete:
                    return Status::done;  // never consumes past the end of the body
                case State::failed:
                    return Status::error;
            }
        }
        return state_ == State::complete ? Status::done : Status::ok;
    }

private:
    enum class State {
        size,
        ext,
        size_lf,
        data,
        data_cr,
        data_lf,
        trailer_start,
        trailer_line,
        trailer_lf,
        end_lf,
        complete,
        failed
    };

    static int hex_value(unsigned char c) noexcept {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
    Status fail() noexcept {
        state_ = State::failed;
        return Status::error;
    }

    State state_ = State::size;
    std::uint64_t remaining_ = 0;  // bytes left in the current chunk
    unsigned digits_ = 0;          // hex digits seen in the current size line
    std::size_t line_ = 0;         // bytes of the current extension line / all trailers
};

}  // namespace agensio
