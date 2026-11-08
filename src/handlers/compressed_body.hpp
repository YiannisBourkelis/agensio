// An application's answer compressed as the writer pulls it (docs/design-compression.md 6, step 6):
// a buffered answer above the whole-answer limit, one spilled to a temp file, or one streamed from
// the upstream, wrapped as a StreamBody, so HTTP/1.1 frames it chunked and HTTP/2 in DATA frames
// with their backpressure: a slow client holds one piece and one encoder, never a whole body.
//
// The encoder writes straight into the writer's buffer; a source not already in memory is read into
// the encoder's pooled input buffer. Each read takes at most about one piece (kPieceAnswer or
// kPieceEvents) of input, so one answer holds the worker for well under a millisecond per read.
// One flush rule (design 12, decision 12): while the application keeps sending, pieces are
// compressed without flushing; when the upstream has nothing more ready (StreamBody::ready), what
// was compressed is flushed, so an application's flush() and each server-sent event reach the client
// as they were sent. Once 256 KB of input was compressed since the last time, a read answers through
// the worker's loop (`ctx`), not inside the call: the writers chain a body's reads inline while the
// socket takes them, and a socket buffer holds a whole compressed answer, so without it one 1 MB gzip
// answer would hold the worker for its whole encode (about 10 ms).
#pragma once

#include <asio/io_context.hpp>
#include <cstdint>
#include <memory>
#include <string>

#include "compress.hpp"
#include "core/body.hpp"
#include "file.hpp"

namespace agensio {

class CompressedBody final : public StreamBody {
public:
    // A buffered answer, given whole. `ctx`: the worker's loop, where a read that compressed a piece
    // answers (none: every read answers inside the call, as the tests drive it).
    CompressedBody(StreamEncoder enc, std::string memory, asio::io_context* ctx = nullptr);
    // A spilled answer: the temp file and its size.
    CompressedBody(StreamEncoder enc, File file, std::uint64_t size, asio::io_context* ctx = nullptr);
    // A streamed answer: the upstream's source, held to the length it declared, if any.
    CompressedBody(StreamEncoder enc, std::unique_ptr<StreamBody> source, asio::io_context* ctx = nullptr);

    // A pull in flight is abandoned: HTTP/1 lets go of the exchange once the head is out, so a close
    // mid-answer (the client gone, a timeout) frees this body while the exchange, kept alive by its own
    // socket read, would still copy the application's next bytes into the encoder's input buffer and
    // call back here.
    ~CompressedBody() override;
    CompressedBody(const CompressedBody&) = delete;
    CompressedBody& operator=(const CompressedBody&) = delete;

    bool length(std::uint64_t&) const noexcept override { return false; }  // the coded length is not known ahead
    void async_read(char* buf, std::size_t len, ReadHandler handler) override;
    std::string failure() const override { return source_ ? source_->failure() : std::string(); }  // the upstream's

private:
    enum class From : std::uint8_t { memory, file, stream };
    void drive();
    void complete(std::error_code ec);
    void pull_source();

    StreamEncoder enc_;
    asio::io_context* ctx_ = nullptr;
    From from_;
    std::string memory_;
    File file_;
    std::uint64_t file_size_ = 0, file_pos_ = 0;
    std::unique_ptr<StreamBody> source_;
    bool sized_ = false;
    std::uint64_t remaining_ = 0;  // a sized source's bytes still to come
    // The input not yet given to the encoder.
    const char* in_ = nullptr;
    std::size_t in_len_ = 0;
    bool source_done_ = false;
    bool unflushed_ = false;  // input given since the last flush
    bool finished_ = false;   // the coding's end written
    bool op_open_ = false;    // a flush or finish in progress (op_)
    StreamEncoder::Op op_ = StreamEncoder::Op::process;
    // The writer's read in progress.
    char* out_ = nullptr;
    std::size_t len_ = 0, room_ = 0, taken_ = 0;
    std::size_t since_yield_ = 0;  // input compressed since a read last answered through the loop
    ReadHandler handler_;
    // The source's answer: pending, arrived inline, or arrived later (then drive resumes).
    bool pulling_ = false, inline_ = false, have_pull_ = false;
    std::error_code pulled_ec_;
    std::size_t pulled_ = 0;
};

}  // namespace agensio
