// HTTP/2 response writer: turns the Responses of ready streams into HEADERS and DATA
// frames and writes them, together with the pending control frames, in write cycles.
// One cycle gathers up to kMaxPieces scatter entries across streams: control frames
// first, then each ready stream gets up to a quantum of body bytes within its send
// window, the connection window and the peer's frame size, and a stream with more to
// send goes back to the end of the list (round robin). On plain sockets the payloads are
// views into cache entries and chunk buffers, nothing copied (one writev); on TLS the
// cycle is concatenated into one buffer and encrypted as a run of records. The head is
// HPACK: the status index, the worker's server+date pair refreshed once per second, the
// response's prebuilt block (a cache entry's, built at insert) or its text block encoded
// now, and the extra fields. StreamBody sources (FastCGI, proxy, CGI) are pulled one
// chunk at a time per stream, at most kPullBudget streams at once per connection, so an
// origin is never read faster than the client takes.
//
// The connection (Owner) provides the socket, its lifetime (shared_from_this), close(),
// touch(), on_stream_written(H2Stream&) when a stream's END_STREAM has been handed to the
// kernel, on_stream_failed(H2Stream&) when a source fails mid-body, and release_deferred(H2Stream&)
// for a stream closed while its bytes were in flight.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <asio.hpp>

#include "config.hpp"
#include "core/fields.hpp"
#include "core/strings.hpp"
#include "core/worker_state.hpp"
#include "http1/writer.hpp"  // IsTlsStream
#include "http2/frame.hpp"
#include "http2/hpack.hpp"
#include "http2/stream.hpp"

namespace agensio::h2 {

template <class Socket, class Owner>
class Http2Writer {
public:
    static constexpr std::size_t kTlsRecord = 16384;       // TLS plaintext bytes per record
    // DATA payload per frame: on TLS a frame with its 9-byte header is exactly one record,
    // so a run of frames never leaves a short record behind (measured on the 10 MB TLS
    // stream: 16,393-byte writes made one full record plus a 9-byte one each, twice the
    // sends nginx makes; that was the one row it won).
    static constexpr std::size_t kPayload = IsTlsStream<Socket>::value ? kTlsRecord - kFrameHeaderSize : 16384;
    static constexpr std::size_t kFramesPerChunk = 4;      // file frames read with one preadv
    static constexpr std::size_t kSlot = kFrameHeaderSize + kPayload;
    static constexpr std::size_t kQuantum = kFramesPerChunk * kPayload;  // body bytes per stream per cycle
    static constexpr std::size_t kMaxPieces = 256;         // scatter entries per cycle
    // Body bytes per cycle. TLS cycles with separate header pieces are copied into one
    // buffer before SSL_write; 64 KB keeps that copy and the encrypt in cache (measured
    // 2026-09-24 on the arena's static-h2: 256 KB cycles cost 9 % after the write batching
    // made every cycle full).
    static constexpr std::size_t kMaxCycleBytes = IsTlsStream<Socket>::value ? 64 * 1024 : 256 * 1024;
    // A cycle of many small pieces (the answers of many streams to one read) is copied into
    // one buffer and written once: asio hands the kernel at most 64 entries per call, so a
    // scatter list of tiny answers costs a syscall per 21 of them, and the copy is cheaper
    // (2026-09-24, the arena's baseline-h2: one sendmsg per 2.4 answers before batching).
    static constexpr std::size_t kCoalescePieces = 16;
    static constexpr std::size_t kCoalesceBytes = 64 * 1024;
    static constexpr unsigned kPullBudget = 8;             // StreamBody reads in flight per connection
    static constexpr unsigned kInlineBudget = 8;           // cycles completed inline before yielding to the loop

    Http2Writer(Socket& socket, Owner& owner, asio::io_context& ctx, const Config& cfg)
        : socket_(socket), owner_(owner), ctx_(ctx), cfg_(cfg) {
        ctl_.reserve(256);
        hdrs_.reserve(kMaxPieces * kFrameHeaderSize);
        pieces_.reserve(kMaxPieces);
    }
    Http2Writer(const Http2Writer&) = delete;
    Http2Writer& operator=(const Http2Writer&) = delete;

    // ---- what the connection feeds ----

    // A control frame (SETTINGS, PING ACK, WINDOW_UPDATE, RST_STREAM, GOAWAY) goes out with
    // the next cycle, ahead of stream data.
    void control(std::string_view frame) {
        ctl_.append(frame);
        schedule();
    }
    // The stream's response is filled (or its window or source data became available).
    void enqueue(H2Stream& s) {
        if (!s.in_ready) {
            s.in_ready = true;
            s.next_ready = nullptr;
            if (ready_tail_) ready_tail_->next_ready = &s;
            else ready_head_ = &s;
            ready_tail_ = &s;
        }
        schedule();
    }
    // The stream was reset or closed: forget it (bytes already in flight finish on their own).
    void dequeue(H2Stream& s) noexcept {
        if (!s.in_ready) return;
        H2Stream* prev = nullptr;
        for (H2Stream* p = ready_head_; p; prev = p, p = p->next_ready) {
            if (p != &s) continue;
            if (prev) prev->next_ready = p->next_ready;
            else ready_head_ = p->next_ready;
            if (ready_tail_ == p) ready_tail_ = prev;
            break;
        }
        s.in_ready = false;
        s.next_ready = nullptr;
        for (auto& w : waiting_)
            if (w == &s) w = nullptr;
    }
    // True while bytes of this stream are in the write in flight (its buffers must live on).
    bool in_flight(const H2Stream& s) const noexcept {
        if (!writing_) return false;
        for (const auto& [p, gen] : inflight_)
            if (p == &s) return true;
        return false;
    }
    // Runs a cycle now, unless one is being built, one is in flight, or a completion is
    // running its callbacks: then the tail of that work runs the next cycle, so a callback
    // that enqueues a frame can never start a cycle inside the cycle that is calling it
    // (the recursion the sanitizer found under h2load as a stack overflow).
    void schedule() {
        if (holding_ || writing_ || building_ || in_completion_) {
            again_ = true;
            return;
        }
        cycle();
    }
    // While held, enqueued streams and control frames wait; release starts the one cycle
    // that carries them all. The connection holds the writer across the frames of one
    // read, so a hundred answers to a hundred HEADERS frames leave in one write instead
    // of one every few streams (the write completes inline on a fast socket, and the
    // next cycle used to start with whatever was ready by then).
    void hold() noexcept { holding_ = true; }
    void release() {
        holding_ = false;
        if (again_) schedule();
    }
    struct Hold {
        Http2Writer& w;
        explicit Hold(Http2Writer& writer) noexcept : w(writer) { w.hold(); }
        ~Hold() { w.release(); }
        Hold(const Hold&) = delete;
        Hold& operator=(const Hold&) = delete;
    };
    // The peer's SETTINGS_HEADER_TABLE_SIZE: the most our encoder's table may be.
    void set_peer_table_size(std::uint32_t v) { encoder_.set_peer_max(v); }
    const hpack::Encoder& encoder() const noexcept { return encoder_; }
    // The peer's connection-level window and frame size (SETTINGS, WINDOW_UPDATE).
    std::int32_t conn_window() const noexcept { return conn_window_; }
    void set_conn_window(std::int32_t w) noexcept { conn_window_ = w; }
    void set_max_frame(std::uint32_t n) noexcept { max_frame_ = n; }
    bool idle() const noexcept { return !writing_ && ctl_.empty() && ready_head_ == nullptr; }
    unsigned pulls() const noexcept { return pulls_; }

    // Idle: the coalescing buffer (up to a cycle's worth) and the scatter list go.
    void shed() noexcept {
        if (writing_) return;
        std::vector<char>().swap(out_);
        std::vector<unsigned char>().swap(hdrs_);
        std::vector<asio::const_buffer>().swap(pieces_);
    }

    // The connection is closing: nothing more is written, in-flight completions are ignored.
    void reset() noexcept {
        closed_ = true;
        ready_head_ = ready_tail_ = nullptr;
        ctl_.clear();
        waiting_.clear();
    }

private:
    enum class Emit { more, blocked, pulling, finished };

    std::shared_ptr<Owner> self() { return owner_.shared_from_this(); }
    template <class F>
    auto immediate(F&& f) {
        return asio::bind_immediate_executor(ctx_.get_executor(), std::forward<F>(f));
    }

    H2Stream* pop_ready() noexcept {
        H2Stream* s = ready_head_;
        if (!s) return nullptr;
        ready_head_ = s->next_ready;
        if (!ready_head_) ready_tail_ = nullptr;
        s->in_ready = false;
        s->next_ready = nullptr;
        return s;
    }

    // ---- the write cycle ----

    void cycle() {
        if (closed_ || writing_ || building_) return;
        building_ = true;
        again_ = false;
        pieces_.clear();
        hdrs_.clear();
        finished_.clear();
        inflight_.clear();
        std::size_t bytes = 0;
        if (!ctl_.empty()) {
            ctl_out_.swap(ctl_);
            ctl_.clear();
            pieces_.push_back(asio::buffer(ctl_out_));
            bytes += ctl_out_.size();
        }
        // Each ready stream once per cycle: the head of the list at cycle start marks the round.
        std::size_t rounds = 0;
        for (H2Stream* p = ready_head_; p; p = p->next_ready) ++rounds;
        while (rounds-- > 0 && pieces_.size() + 2 <= kMaxPieces && bytes < kMaxCycleBytes) {
            H2Stream* s = pop_ready();
            if (!s) break;
            const std::size_t before = bytes;
            switch (emit(*s, bytes)) {
                case Emit::more:
                    enqueue_silent(*s);  // back to the end: round robin
                    break;
                case Emit::blocked:   // window: WINDOW_UPDATE re-enqueues it
                case Emit::pulling:   // source: the pull completion re-enqueues it
                case Emit::finished:
                    break;
            }
            if (bytes > before || !inflight_.empty()) note_inflight(*s);
        }
        building_ = false;
        if (pieces_.empty()) return;
        writing_ = true;
        auto done = immediate([self = self(), this](const asio::error_code& ec, std::size_t) { on_written(ec); });
        if constexpr (IsTlsStream<Socket>::value) {
            // Every piece a whole frame or a pre-framed block (no separate frame headers):
            // written one after another, each an integral number of records but its last.
            // Otherwise the pieces are coalesced so a header never becomes a record of its own.
            if (hdrs_.empty()) {
                asio::async_write(socket_, pieces_, done);
            } else {
                out_.clear();
                for (const asio::const_buffer& b : pieces_)
                    out_.insert(out_.end(), static_cast<const char*>(b.data()), static_cast<const char*>(b.data()) + b.size());
                asio::async_write(socket_, asio::buffer(out_), done);
            }
        } else {
            if (pieces_.size() > kCoalescePieces) {
                std::size_t total = 0;
                for (const asio::const_buffer& b : pieces_) total += b.size();
                if (total <= kCoalesceBytes) {
                    out_.clear();
                    for (const asio::const_buffer& b : pieces_)
                        out_.insert(out_.end(), static_cast<const char*>(b.data()), static_cast<const char*>(b.data()) + b.size());
                    asio::async_write(socket_, asio::buffer(out_), done);
                    return;
                }
            }
            asio::async_write(socket_, pieces_, done);
        }
    }

    void enqueue_silent(H2Stream& s) noexcept {
        if (s.in_ready) return;
        s.in_ready = true;
        s.next_ready = nullptr;
        if (ready_tail_) ready_tail_->next_ready = &s;
        else ready_head_ = &s;
        ready_tail_ = &s;
    }

    void note_inflight(H2Stream& s) {
        for (const auto& [p, gen] : inflight_)
            if (p == &s) return;
        inflight_.emplace_back(&s, s.gen);
    }

    void on_written(const asio::error_code& ec) {
        writing_ = false;
        if (closed_) return;
        if (ec) {
            owner_.close();
            return;
        }
        owner_.touch();
        // The cycle's lists are taken over before any callback runs: a callback may enqueue
        // work (that sets again_) but never starts a cycle here (in_completion_).
        in_completion_ = true;
        done_.swap(finished_);
        finished_.clear();
        flown_.swap(inflight_);
        inflight_.clear();
        // Streams closed while their bytes were in flight can be released now.
        for (const auto& [p, gen] : flown_)
            if (p->gen == gen && p->defer_release) owner_.release_deferred(*p);
        for (const auto& [p, gen] : done_)
            if (p->gen == gen && !p->defer_release) owner_.on_stream_written(*p);
        in_completion_ = false;
        if (closed_) return;
        // Pulls that waited for the budget.
        if (pulls_ < kPullBudget && !waiting_.empty()) {
            for (H2Stream* w : waiting_)
                if (w) enqueue_silent(*w);
            waiting_.clear();
        }
        if (again_ || ready_head_ || !ctl_.empty()) {
            // A write that completes inline brings the next cycle here on the same stack:
            // after kInlineBudget of them the continuation is posted, which bounds the depth
            // and gives the other connections of the worker their turn.
            if (++inline_runs_ >= kInlineBudget) {
                inline_runs_ = 0;
                asio::post(ctx_, [self = self(), this] { schedule(); });
                return;
            }
            cycle();
            return;
        }
        inline_runs_ = 0;
        owner_.after_write();
    }

    // ---- frames of one stream ----

    void push_frame(std::uint32_t length, FrameType type, std::uint8_t flags, std::uint32_t stream_id,
                    std::string_view payload) {
        const std::size_t at = hdrs_.size();
        hdrs_.resize(at + kFrameHeaderSize);
        write_frame_header(hdrs_.data() + at, length, type, flags, stream_id);
        pieces_.push_back(asio::buffer(hdrs_.data() + at, kFrameHeaderSize));
        if (!payload.empty()) pieces_.push_back(asio::buffer(payload.data(), payload.size()));
    }

    static StreamBody* source_of(Response& r) noexcept {
        auto* p = std::get_if<std::unique_ptr<StreamBody>>(&r.body);
        return p ? p->get() : nullptr;
    }

    // Appends the stream's next frames to the cycle. `bytes` counts the cycle's payload.
    Emit emit(H2Stream& s, std::size_t& bytes) {
        Response& r = s.stream.response;
        if (!s.head_sent) {
            build_head(s);
            bool end = r.head || !has_body(r.body);
            if (!end) {
                if (const auto* m = std::get_if<MemoryBody>(&r.body)) end = m->data.empty();
                else if (const auto* f = std::get_if<FileBody>(&r.body)) end = f->size == 0;
            }
            write_frame_header(reinterpret_cast<unsigned char*>(s.head.data()),  // NOLINT: bytes
                               static_cast<std::uint32_t>(s.head.size() - kFrameHeaderSize), FrameType::headers,
                               static_cast<std::uint8_t>(flag::end_headers | (end ? flag::end_stream : 0)), s.id);
            pieces_.push_back(asio::buffer(s.head));
            bytes += s.head.size();
            s.head_sent = s.responded = true;
            s.since = std::chrono::steady_clock::now();
            if (end) {
                s.finished = true;
                finished_.emplace_back(&s, s.gen);
                return Emit::finished;
            }
        }
        std::size_t quantum = kQuantum;
        while (pieces_.size() + 2 <= kMaxPieces) {
            std::string_view data;
            bool last = false;
            if (const auto* m = std::get_if<MemoryBody>(&r.body)) {
                data = m->data.substr(static_cast<std::size_t>(s.body_offset));
                last = true;  // everything is at hand
            } else if (auto* f = std::get_if<FileBody>(&r.body)) {
                // A pre-framed block: up to kFramesPerChunk frames read with one preadv into
                // the payload slots of the chunk, the headers written in place, one
                // contiguous piece and no copy; every frame but the last fills its slot, so
                // on TLS each is one record.
                const std::uint64_t remaining = f->size - s.body_offset;
                if (remaining == 0) {
                    data = {};
                } else {
                    if (s.send_window <= 0 || conn_window_ <= 0) return Emit::blocked;
                    std::size_t allowed = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, quantum));
                    allowed = std::min<std::size_t>(allowed, static_cast<std::size_t>(s.send_window));
                    allowed = std::min<std::size_t>(allowed, static_cast<std::size_t>(conn_window_));
                    if (allowed == 0) return quantum == 0 ? Emit::more : Emit::blocked;
                    if (s.chunk.size() < kFramesPerChunk * kSlot) s.chunk.resize(kFramesPerChunk * kSlot);
                    File::MutSlice slices[kFramesPerChunk];
                    int frames = 0;
                    for (std::size_t left = allowed; left > 0 && frames < static_cast<int>(kFramesPerChunk); ++frames) {
                        const std::size_t n = std::min(left, kPayload);
                        slices[frames] = File::MutSlice{s.chunk.data() + static_cast<std::size_t>(frames) * kSlot + kFrameHeaderSize, n};
                        left -= n;
                    }
                    const std::int64_t got = f->file->read_at(slices, frames, f->offset + s.body_offset);
                    if (got <= 0) {  // the file shrank or failed: the client sees a truncated stream
                        owner_.on_stream_failed(s);
                        return Emit::finished;
                    }
                    const std::size_t total = static_cast<std::size_t>(got);
                    const bool ends = s.body_offset + total == f->size;
                    std::size_t left = total, block = 0;
                    for (int i = 0; i < frames && left > 0; ++i) {
                        const std::size_t n = std::min(left, slices[i].len);
                        left -= n;
                        write_frame_header(reinterpret_cast<unsigned char*>(s.chunk.data() + static_cast<std::size_t>(i) * kSlot),  // NOLINT
                                           static_cast<std::uint32_t>(n), FrameType::data,
                                           (ends && left == 0) ? flag::end_stream : 0, s.id);
                        block = static_cast<std::size_t>(i) * kSlot + kFrameHeaderSize + n;
                    }
                    pieces_.push_back(asio::buffer(s.chunk.data(), block));
                    s.body_offset += total;
                    s.body_sent += total;
                    s.send_window -= static_cast<std::int32_t>(total);
                    conn_window_ -= static_cast<std::int32_t>(total);
                    quantum -= std::min(quantum, total);
                    bytes += total;
                    s.since = std::chrono::steady_clock::now();
                    if (ends) {
                        s.finished = true;
                        finished_.emplace_back(&s, s.gen);
                        return Emit::finished;
                    }
                    if (quantum == 0 || pieces_.size() + 2 > kMaxPieces) return Emit::more;
                    continue;
                }
            } else if (StreamBody* source = source_of(r)) {
                if (s.chunk_pos == s.chunk_len) {
                    if (!s.source_done) {
                        if (pulls_ >= kPullBudget) {
                            waiting_.push_back(&s);
                            return Emit::pulling;
                        }
                        pull(s, *source);
                        return Emit::pulling;
                    }
                    data = {};
                } else {
                    data = std::string_view(s.chunk.data() + s.chunk_pos, s.chunk_len - s.chunk_pos);
                    last = s.source_done;  // the source already said so, this chunk is its last
                }
            }
            if (data.empty()) {  // the end: an empty DATA frame carries END_STREAM
                if (!s.finished) {
                    push_frame(0, FrameType::data, flag::end_stream, s.id, {});
                    s.finished = true;
                    finished_.emplace_back(&s, s.gen);
                }
                return Emit::finished;
            }
            std::size_t n = std::min(data.size(), quantum);
            n = std::min<std::size_t>(n, std::min<std::size_t>(max_frame_, kPayload));
            if (s.send_window <= 0 || conn_window_ <= 0) return Emit::blocked;
            n = std::min<std::size_t>(n, static_cast<std::size_t>(s.send_window));
            n = std::min<std::size_t>(n, static_cast<std::size_t>(conn_window_));
            if (n == 0) return quantum == 0 ? Emit::more : Emit::blocked;
            const bool end = last && n == data.size();
            push_frame(static_cast<std::uint32_t>(n), FrameType::data, end ? flag::end_stream : 0, s.id, data.substr(0, n));
            s.body_offset += n;
            s.body_sent += n;
            if (source_of(r)) s.chunk_pos += n;
            s.send_window -= static_cast<std::int32_t>(n);
            conn_window_ -= static_cast<std::int32_t>(n);
            quantum -= n;
            bytes += n;
            s.since = std::chrono::steady_clock::now();
            if (end) {
                s.finished = true;
                finished_.emplace_back(&s, s.gen);
                return Emit::finished;
            }
            if (quantum == 0) return Emit::more;
        }
        return Emit::more;
    }

    void pull(H2Stream& s, StreamBody& source) {
        if (s.chunk.empty()) s.chunk.resize(cfg_.stream_chunk_size);
        if (s.source_sized && s.source_remaining == 0) {
            s.source_done = true;
            enqueue_silent(s);
            return;
        }
        std::size_t want = s.chunk.size();
        if (s.source_sized) want = static_cast<std::size_t>(std::min<std::uint64_t>(s.source_remaining, want));
        s.pulling = true;
        ++pulls_;
        source.async_read(s.chunk.data(), want,
                          [self = self(), this, sp = &s, gen = s.gen](std::error_code ec, std::size_t n) {
                              --pulls_;
                              H2Stream& st = *sp;
                              st.pulling = false;
                              if (st.gen != gen) {  // reset meanwhile: the stream is only now free
                                  owner_.release_deferred(st);
                                  return;
                              }
                              if (closed_) return;
                              if (ec || (n == 0 && st.source_sized && st.source_remaining > 0)) {
                                  owner_.on_stream_failed(st);  // the source failed or ended short
                                  return;
                              }
                              if (n == 0) {
                                  st.source_done = true;
                              } else {
                                  if (st.source_sized) st.source_remaining -= n;
                                  st.chunk_len = n;
                                  st.chunk_pos = 0;
                              }
                              enqueue(st);
                          });
    }

    // ---- the head ----

    // "Name: value\r\n" lines (an upstream's or a handler's text block) to HPACK literals;
    // connection-specific fields are dropped (RFC 9113 8.2.2).
    void encode_text_block(std::string& out, std::string_view text, std::string& scratch) {
        while (!text.empty()) {
            const std::size_t eol = text.find("\r\n");
            const std::string_view line = text.substr(0, eol);
            text = eol == std::string_view::npos ? std::string_view() : text.substr(eol + 2);
            if (line.empty()) continue;
            const std::size_t colon = line.find(':');
            if (colon == std::string_view::npos || colon == 0) continue;
            std::string_view value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
            append_lower(out, line.substr(0, colon), value, scratch);
        }
    }
    void append_lower(std::string& out, std::string_view name, std::string_view value, std::string& scratch) {
        scratch.assign(name);
        for (char& c : scratch) c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
        if (fields::connection_specific(scratch)) return;
        encoder_.field(out, scratch, value);
    }

    // The head through the connection's dynamic table (design 6.2.1): status, server and
    // date by remembered index, the representation's type and coding through the table,
    // then the entry's prebuilt tail of literals, or a text block field by field.
    void build_head(H2Stream& s) {
        Response& r = s.stream.response;
        WorkerState& ws = owner_.worker_state();
        std::string& h = s.head;
        h.assign(kFrameHeaderSize, '\0');  // the HEADERS frame header, filled in by emit()
        encoder_.begin(h);
        hpack::append_status(h, r.status);
        if (!ws.server_line.empty()) {
            if (ws.h2_server_insert.empty()) hpack::append_insert(ws.h2_server_insert, "server", cfg_.server_header);
            encoder_.server(h, cfg_.server_header, ws.h2_server_insert);
        }
        if (ws.h2_date_time != ws.now) {  // the date's inserting literal, once per second per worker
            ws.h2_date_insert.clear();
            hpack::append_insert(ws.h2_date_insert, "date", ws.date.at(ws.now));
            ws.h2_date_time = ws.now;
        }
        encoder_.date(h, ws.now, ws.date.at(ws.now), ws.h2_date_insert);
        if (!r.prebuilt_h2.empty()) {
            if (!r.content_type.empty()) encoder_.field(h, "content-type", r.content_type);
            if (!r.content_encoding.empty()) encoder_.field(h, "content-encoding", r.content_encoding);
            if (r.vary) encoder_.field(h, "vary", "Accept-Encoding");
            h.append(r.prebuilt_h2);
        } else if (!r.prebuilt_headers.empty()) {
            encode_text_block(h, r.prebuilt_headers, s.scratch);
        }
        for (const HeaderField& f : r.headers) append_lower(h, f.name, f.value, s.scratch);
        if (const StreamBody* source = source_of(r)) {
            std::uint64_t len = 0;
            s.source_sized = source->length(len);
            s.source_remaining = len;
            if (s.source_sized) {
                s.scratch.clear();
                append_number(s.scratch, len);
                encoder_.field(h, "content-length", s.scratch);
            }
        }
    }

    Socket& socket_;
    Owner& owner_;
    asio::io_context& ctx_;
    const Config& cfg_;
    hpack::Encoder encoder_;  // the connection's dynamic table for response heads (design 6.2.1)
    std::string ctl_;      // control frames waiting for the next cycle
    std::string ctl_out_;  // the control frames of the cycle in flight
    std::vector<unsigned char> hdrs_;         // frame headers of the cycle in flight
    std::vector<asio::const_buffer> pieces_;  // the scatter list of the cycle in flight
    std::vector<char> out_;                   // TLS: the cycle concatenated
    std::vector<std::pair<H2Stream*, unsigned>> finished_;  // END_STREAM queued in this cycle
    std::vector<std::pair<H2Stream*, unsigned>> inflight_;  // streams with bytes in this cycle
    std::vector<std::pair<H2Stream*, unsigned>> done_, flown_;  // the same two, taken over by the completion
    std::vector<H2Stream*> waiting_;                        // pulls held back by the budget
    H2Stream* ready_head_ = nullptr;
    H2Stream* ready_tail_ = nullptr;
    std::int32_t conn_window_ = static_cast<std::int32_t>(65535);
    std::uint32_t max_frame_ = 16384;
    unsigned pulls_ = 0;
    unsigned inline_runs_ = 0;
    bool writing_ = false;
    bool holding_ = false;        // the connection is inside a read's frame loop: cycles wait for release()
    bool building_ = false;       // a cycle is being assembled
    bool in_completion_ = false;  // on_written is running the owner's callbacks
    bool again_ = false;
    bool closed_ = false;
};

}  // namespace agensio::h2
