#include "handlers/compressed_body.hpp"

#include <algorithm>
#include <asio/error.hpp>
#include <asio/post.hpp>

namespace agensio {

namespace {
// The room a zlib flush needs to complete in one call (zlib.h: more than six bytes, or a sync marker
// repeats); with less and something to give, the read returns and the flush runs on the next.
constexpr std::size_t kFlushRoom = 16;
// The input compressed since the last yield past which a read answers through the worker's loop:
// the whole-answer limit's bound (compress_answer::kWholeMax), so one answer holds the worker at most
// as long as one compressed whole may (0.35 to 0.7 ms with zstd 3, about 2 ms with gzip 5). Yielding
// after every 64 KB piece cost 14 % more CPU per 512 KB answer: interleaved encoders push each
// other's tables out of the cache (2026-11-07, 1.58 against 1.39 ms at 8 connections).
constexpr std::size_t kYieldInput = 256 * 1024;
std::error_code encoder_failed() { return std::make_error_code(std::errc::io_error); }
}  // namespace

CompressedBody::CompressedBody(StreamEncoder enc, std::string memory, asio::io_context* ctx)
    : enc_(std::move(enc)), ctx_(ctx), from_(From::memory), memory_(std::move(memory)) {
    in_ = memory_.data();
    in_len_ = memory_.size();
}

CompressedBody::CompressedBody(StreamEncoder enc, File file, std::uint64_t size, asio::io_context* ctx)
    : enc_(std::move(enc)), ctx_(ctx), from_(From::file), file_(std::move(file)), file_size_(size) {}

CompressedBody::CompressedBody(StreamEncoder enc, std::unique_ptr<StreamBody> source, asio::io_context* ctx)
    : enc_(std::move(enc)), ctx_(ctx), from_(From::stream), source_(std::move(source)) {
    sized_ = source_->length(remaining_);
}

CompressedBody::~CompressedBody() {
    if (pulling_ && source_) source_->abandon_read();
}

void CompressedBody::async_read(char* buf, std::size_t len, ReadHandler handler) {
    out_ = buf;
    len_ = room_ = len;
    taken_ = 0;
    handler_ = std::move(handler);
    drive();
}

// The writer's read answered: the bytes written into its buffer, or 0 once the coding has ended. The
// handler is the last thing touched: it may start the next read, or end the answer and destroy this.
// After a piece's worth of compression it is answered from the worker's loop (the posted handler
// holds the writer's own reference, never this body).
void CompressedBody::complete(std::error_code ec) {
    ReadHandler h = std::move(handler_);
    handler_ = nullptr;
    const std::size_t n = ec ? 0 : len_ - room_;
    since_yield_ += taken_;
    if (ctx_ && since_yield_ >= kYieldInput) {
        since_yield_ = 0;
        asio::post(*ctx_, [h = std::move(h), ec, n]() mutable { h(ec, n); });
        return;
    }
    h(ec, n);
}

void CompressedBody::pull_source() {
    std::size_t want = enc_.input_capacity();
    if (sized_) want = static_cast<std::size_t>(std::min<std::uint64_t>(want, remaining_));
    pulling_ = true;
    inline_ = true;
    source_->async_read(enc_.input(), want, [this](std::error_code ec, std::size_t n) {
        pulling_ = false;
        have_pull_ = true;
        pulled_ec_ = ec;
        if (sized_) {  // never more than declared: the surplus is not this answer's
            n = static_cast<std::size_t>(std::min<std::uint64_t>(n, remaining_));
            remaining_ -= n;
        }
        pulled_ = n;
        if (!inline_) drive();  // the source answered later: the writer's read is still waiting
    });
    inline_ = false;
}

void CompressedBody::drive() {
    using Op = StreamEncoder::Op;
    for (;;) {
        const std::size_t made = len_ - room_;
        // A flush or the finish in progress runs to its end before anything else.
        if (op_open_) {
            if (room_ < kFlushRoom && made > 0) return complete({});
            const char* none = nullptr;
            std::size_t zero = 0;
            bool done = false;
            if (!enc_.run(op_, none, zero, out_, room_, done)) return complete(encoder_failed());
            if (!done) {
                if (len_ - room_ > 0) return complete({});  // the rest on the next read
                return complete(encoder_failed());          // no room and no progress: never a false end
            }
            op_open_ = false;
            if (op_ == Op::finish) {
                finished_ = true;
                return complete({});  // 0 bytes only when the end came with nothing before it in this read
            }
            unflushed_ = false;
            if (len_ - room_ > 0) return complete({});  // what the application sent so far, to the client now
            continue;
        }
        if (finished_) return complete({});  // 0 bytes: the end of the body
        if (in_len_ > 0) {
            // One piece at a time, and back to the writer once a piece's worth of input is taken and
            // something is ready: the time one read holds the worker stays bounded whatever the ratio.
            if (taken_ >= enc_.input_capacity() && made > 0) return complete({});
            std::size_t give = std::min(in_len_, enc_.input_capacity());
            const std::size_t before_out = room_;
            const char* in = in_;
            bool done = false;
            if (!enc_.run(Op::process, in, give, out_, room_, done)) return complete(encoder_failed());
            const std::size_t used = static_cast<std::size_t>(in - in_);
            in_ = in;
            in_len_ -= used;
            taken_ += used;
            if (used > 0) unflushed_ = true;
            if (room_ == 0) return complete({});
            if (used == 0 && room_ == before_out) return complete(encoder_failed());  // the library made no progress
            continue;
        }
        if (source_done_) {
            op_ = Op::finish;
            op_open_ = true;
            continue;
        }
        // The next input.
        if (from_ == From::memory) {
            source_done_ = true;
            continue;
        }
        if (from_ == From::file) {
            if (file_pos_ >= file_size_) {
                source_done_ = true;
                continue;
            }
            const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(enc_.input_capacity(), file_size_ - file_pos_));
            const std::int64_t got = file_.read_at(enc_.input(), want, file_pos_);
            if (got <= 0) return complete(std::make_error_code(std::errc::io_error));  // the file shrank: a short body, cut
            file_pos_ += static_cast<std::uint64_t>(got);
            in_ = enc_.input();
            in_len_ = static_cast<std::size_t>(got);
            continue;
        }
        if (have_pull_) {
            have_pull_ = false;
            if (pulled_ec_) return complete(pulled_ec_);
            if (pulled_ == 0) {
                if (sized_ && remaining_ > 0) return complete(std::error_code(asio::error::connection_reset));  // declared more than it sent
                source_done_ = true;
                continue;
            }
            in_ = enc_.input();
            in_len_ = pulled_;
            continue;
        }
        if (sized_ && remaining_ == 0) {
            source_done_ = true;
            continue;
        }
        // The upstream: with nothing ready, the application paused, and what was compressed goes out.
        if (!source_->ready()) {
            if (unflushed_) {
                op_ = Op::flush;
                op_open_ = true;
                continue;
            }
            if (made > 0) return complete({});
        }
        pull_source();
        if (pulling_) return;  // drive resumes from the source's answer, the writer's read still waiting
    }
}

}  // namespace agensio
