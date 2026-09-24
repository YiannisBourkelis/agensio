// The HTTP/3 connection (RFC 9114) over a QuicConnection (design-http3 section 7): the
// control and QPACK streams both ways, request streams turned into Streams for the
// dispatcher exactly as HTTP/2 does (the same request assembler, the same pool, the same
// dispatch), answers as a HEADERS frame and DATA frames on the stream's send side, the
// request body as the pull source behind Request::body with the bytes waiting in the
// QUIC stream's receive buffer until the handler takes them (credit returns as it
// does), the access log. It fulfils the contract of design-http2 5.1 for HTTP/3.
#pragma once

#include <asio.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "config.hpp"
#include "core/fields.hpp"
#include "core/forwarded.hpp"
#include "handlers/dispatch.hpp"
#include "http/request_assembly.hpp"
#include "http/stream_pool.hpp"
#include "http3/frame.hpp"
#include "http3/qpack.hpp"
#include "http3/stream.hpp"
#include "net/cidr.hpp"
#include "quic/connection.hpp"
#include "quic/udp.hpp"
#include "server.hpp"
#include "services/log.hpp"
#include "upstream/client.hpp"

namespace agensio::h3 {

class Http3Connection final : public std::enable_shared_from_this<Http3Connection>, private BodyOwner {
public:
    using Quic = quic::QuicConnection<Http3Connection>;
    using Endpoint = quic::Endpoint<Http3Connection>;
    using TimePoint = quic::TimePoint;

    static constexpr std::uint64_t kExcessiveLoad = 0x107;       // H3_EXCESSIVE_LOAD: the transport's reset budget closes with it
    static constexpr std::uint64_t kStreamWindowMax = 1u << 20;  // a body's window, as HTTP/2's
    static constexpr std::uint64_t kDiscardMax = 64 * 1024;      // an unread body is drained this far, then STOP_SENDING

    Http3Connection(Endpoint& ep, Worker& worker, std::shared_ptr<const Generation> gen, const Listener* listener,
                    const Config& cfg, Dispatcher& dispatcher, SSL_CTX* ctx, const quic::PacketHeader& initial,
                    const quic::AcceptInfo& info, const sockaddr_storage& peer, socklen_t peer_len, const quic::Limits& limits,
                    TimePoint now)
        : ep_(ep),
          worker_(worker),
          gen_(std::move(gen)),
          listener_(listener),
          live_(&gen_->cfg),
          cfg_(cfg),
          dispatcher_(dispatcher),
          quic_(*this, ep, ctx, initial, info, peer, peer_len, limits, now),
          now_(now) {
        worker_.connections.fetch_add(1, std::memory_order_relaxed);
        remote_from(peer);
        for (H3Stream* c : {&ctl_, &qenc_, &qdec_}) {
            c->kind = H3Stream::Kind::our_uni;
            c->q.owner = c;
        }
    }
    Http3Connection(const Http3Connection&) = delete;
    Http3Connection& operator=(const Http3Connection&) = delete;
    ~Http3Connection() override {
        worker_.connections.fetch_sub(1, std::memory_order_relaxed);
        ++worker_.sheds;
    }

    Quic& quic() noexcept { return quic_; }

    // ---- the transport's callbacks ----

    quic::QuicStream* on_new_stream(std::uint64_t id) {
        if (closed_) return nullptr;
        refresh_generation();
        H3Stream& s = streams_.take([this](H3Stream& fresh) {
            fresh.body_source.owner = this;
            fresh.body_source.stream = &fresh;
            fresh.q.owner = &fresh;
        });
        s.kind = quic::stream_is_bidi(id) ? H3Stream::Kind::request : H3Stream::Kind::peer_uni;
        s.since = now_;
        ++streams_opened_;
        return &s.q;
    }

    quic::QuicStream* find_stream(std::uint64_t id) noexcept {
        for (auto& s : streams_.all())
            if (s->q.open && s->q.id == id) return &s->q;
        for (H3Stream* c : {&ctl_, &qenc_, &qdec_})
            if (c->q.open && c->q.id == id) return &c->q;
        return nullptr;
    }

    template <class F>
    void for_each_stream(F f) {
        for (auto& s : streams_.all()) f(s->q);
        for (H3Stream* c : {&ctl_, &qenc_, &qdec_}) f(c->q);
    }

    void on_stream_readable(quic::QuicStream& q) {
        H3Stream& s = of(q);
        worker_.state.now = std::time(nullptr);
        if (s.kind == H3Stream::Kind::request) pump(s);
        else if (s.kind == H3Stream::Kind::peer_uni) on_uni_data(s);
    }

    void on_stream_reset(quic::QuicStream& q, std::uint64_t code) {
        H3Stream& s = of(q);
        (void)code;
        if (s.kind == H3Stream::Kind::peer_uni) {
            if (s.type_known && (s.uni_type == stream_type::control || s.uni_type == stream_type::qpack_encoder || s.uni_type == stream_type::qpack_decoder))
                return connection_error(err::closed_critical_stream, "critical stream reset");
            return close_stream(s);
        }
        // A cancelled request (RFC 9114 4.1.1): whatever we were doing stops, our side is reset.
        if (s.upstream) {
            s.upstream->cancel();
            s.upstream.reset();
        }
        if (s.pending_handler) deliver_error(s, asio::error::operation_aborted);
        s.body_done = true;
        q.fin_delivered = true;
        if (!q.send_done && !q.reset_sent) quic_.stream_reset(q, err::request_cancelled);
        else s.finished = true;
        maybe_close(s);
    }

    void on_stop_sending(quic::QuicStream& q, std::uint64_t code) {
        H3Stream& s = of(q);
        if (s.kind == H3Stream::Kind::our_uni) return connection_error(err::closed_critical_stream, "STOP_SENDING on a critical stream");
        if (s.upstream && !s.responded) {
            s.upstream->cancel();
            s.upstream.reset();
        }
        if (!q.send_done && !q.reset_sent) quic_.stream_reset(q, code);  // RFC 9000 3.5: the code is copied
        maybe_close(s);
    }

    // Every byte acknowledged, or our RESET_STREAM gone out.
    void on_stream_sent(quic::QuicStream& q) {
        H3Stream& s = of(q);
        s.finished = true;
        if (s.kind != H3Stream::Kind::request) return;
        log_request(s);
        maybe_close(s);
    }

    void on_handshake_done() {
#ifdef AGENSIO_HAS_TLS
        if (SSL* ssl = quic_.tls().ssl()) cert_names_ = listener_->names_for(SSL_get_SSL_CTX(ssl));
#endif
        if (quic_.alpn() != "h3") return connection_error(err::no_error, "ALPN is not h3");
        // Our control stream (SETTINGS first, RFC 9114 6.2.1) and the two QPACK streams,
        // which carry nothing beyond their type while the table capacity is 0.
        std::string& c = ctl_.q.head;
        c.assign("\x00", 1);
        std::string settings;
        quic::append_varint(settings, setting::max_field_section_size);
        quic::append_varint(settings, live_->max_header_size);
        quic::append_varint(settings, setting::qpack_max_table_capacity);
        quic::append_varint(settings, qpack::Decoder::kMaxCapacity);
        quic::append_varint(settings, setting::qpack_blocked_streams);
        quic::append_varint(settings, qpack::Decoder::kMaxBlocked);
        append_frame_header(c, frame::settings, settings.size());
        c.append(settings);
        qenc_.q.head.assign("\x02", 1);
        qdec_.q.head.assign("\x03", 1);
        qdec_.q.trim_head = true;  // its acknowledgements accumulate for the connection's life
        for (H3Stream* u : {&ctl_, &qenc_, &qdec_}) {
            if (!quic_.open_uni_stream(u->q)) return connection_error(err::general_protocol, "the client allows no unidirectional streams");
            u->q.total = u->q.head.size();
            u->q.fin = false;
            quic_.stream_ready(u->q);
        }
    }

    void on_closed(bool by_peer, std::uint64_t code) {
        (void)by_peer;
        (void)code;
        if (closed_) return;
        closed_ = true;
        for (auto& sp : streams_.all()) {
            H3Stream& s = *sp;
            if (s.upstream) {
                s.upstream->cancel();
                s.upstream.reset();
            }
            if (s.pending_handler) deliver_error(s, asio::error::operation_aborted);
            if (s.kind == H3Stream::Kind::request && s.headers_done) log_request(s);
        }
    }

private:
    static H3Stream& of(quic::QuicStream& q) noexcept { return *static_cast<H3Stream*>(q.owner); }

    // ---- request streams ----

    // Frames off the stream: HEADERS assembled and decoded, DATA left for the handler to
    // pull (or discarded after the answer), the rest skipped (RFC 9114 7.2).
    void pump(H3Stream& s) {
        quic::QuicStream& q = s.q;
        for (int guard = 0; guard < 1024 && !s.closed && !closed_ && !s.blocked; ++guard) {
            const std::size_t avail = q.available();
            if (!s.in_frame) {
                if (avail == 0) break;
                const auto* p = reinterpret_cast<const unsigned char*>(q.data());
                const unsigned char* const start = p;
                const unsigned char* const end = p + avail;
                std::uint64_t type = 0, len = 0;
                if (!quic::read_varint(p, end, type) || !quic::read_varint(p, end, len)) {
                    if (q.at_end()) return connection_error(err::frame_error, "truncated frame header");
                    break;  // more bytes needed
                }
                quic_.stream_consumed(q, static_cast<std::size_t>(p - start));
                s.in_frame = true;
                s.frame_type = type;
                s.frame_remaining = len;
                if (type == frame::headers) {
                    if (len > live_->max_header_size) {
                        if (!s.headers_done) return fail_stream(s, 431);
                        s.frame_type = ~std::uint64_t{0};  // oversized trailers: skipped, not decoded
                    } else if (s.headers_done) {
                        s.trailers = true;  // decoded and discarded, so the QPACK state and the acknowledgements stay in step
                    }
                } else if (type == frame::data) {
                    if (!s.headers_done) return connection_error(err::frame_unexpected, "DATA before HEADERS");
                } else if (type == frame::settings || type == frame::goaway || type == frame::max_push_id ||
                           type == frame::cancel_push || type == frame::push_promise) {
                    return connection_error(err::frame_unexpected, "control frame on a request stream");
                } else {
                    s.frame_type = ~std::uint64_t{0};  // reserved or unknown: skipped (7.2.8)
                }
                continue;
            }
            if (s.frame_type == frame::headers) {
                const std::size_t take = std::min<std::size_t>(avail, static_cast<std::size_t>(s.frame_remaining));
                if (take == 0 && s.frame_remaining) break;
                s.section.append(q.data(), take);
                quic_.stream_consumed(q, take);
                s.frame_remaining -= take;
                if (s.frame_remaining == 0) {
                    s.in_frame = false;
                    if (s.trailers) decode_trailers(s);
                    else begin_request(s);
                }
                continue;
            }
            if (s.frame_type == frame::data) {
                if (s.frame_remaining == 0) {
                    s.in_frame = false;
                    continue;
                }
                if (s.pending_handler) {
                    const std::size_t take = std::min<std::size_t>(std::min<std::size_t>(avail, s.pending_len), static_cast<std::size_t>(s.frame_remaining));
                    if (take == 0) break;
                    std::memcpy(s.pending_buf, q.data(), take);
                    quic_.stream_consumed(q, take);
                    s.frame_remaining -= take;
                    s.body_received += take;
                    if (s.body_received > s.body_limit) return deliver_error(s, make_error_code(BodyError::too_large));
                    deliver(s, take);
                    continue;
                }
                if (s.responded) {  // an unread body after the answer: drained up to a point
                    const std::size_t take = std::min<std::size_t>(avail, static_cast<std::size_t>(s.frame_remaining));
                    if (take == 0) break;
                    quic_.stream_consumed(q, take);
                    s.frame_remaining -= take;
                    s.discarded += take;
                    if (s.discarded > kDiscardMax && !q.stop_sending_received) {
                        quic_.stream_stop_sending(q, err::no_error);
                        q.fin_delivered = true;
                        s.body_done = true;
                        maybe_close(s);
                        return;
                    }
                    continue;
                }
                break;  // the bytes wait for the handler's read
            }
            // A skipped frame's payload.
            const std::size_t take = std::min<std::size_t>(avail, static_cast<std::size_t>(s.frame_remaining));
            if (take == 0) break;
            quic_.stream_consumed(q, take);
            s.frame_remaining -= take;
            if (s.frame_remaining == 0) s.in_frame = false;
        }
        if (s.closed || closed_ || s.blocked) return;
        if (q.at_end() && !q.fin_delivered) {
            q.fin_delivered = true;
            if (s.in_frame && s.frame_remaining) return connection_error(err::frame_error, "stream ended inside a frame");
            s.body_done = true;
            if (!s.headers_done) {
                quic_.stream_reset(q, err::request_incomplete);
                return maybe_close(s);
            }
            if (s.pending_handler) deliver(s, 0);
            maybe_close(s);
        }
    }

    void begin_request(H3Stream& s) {
        Request& req = s.stream.request;
        http::RequestSeen seen;
        std::string& scratch = decode_scratch_;
        scratch.clear();
        std::uint64_t required = 0;
        const auto r = decoder_.decode(s.section, scratch, live_->max_header_size,
                                       [&](std::string_view n, std::string_view v, qpack::Origin o) { return http::sink_field(seen, req, n, v, o); },
                                       required);
        QUIC_TRACE("h3: section stream=%llu bytes=%zu result=%d required=%llu inserts=%llu\n", static_cast<unsigned long long>(s.q.id),
                   s.section.size(), static_cast<int>(r), static_cast<unsigned long long>(required), static_cast<unsigned long long>(decoder_.insert_count()));
        switch (r) {
            case qpack::Decoder::Result::ok: break;
            case qpack::Decoder::Result::malformed: return connection_error(err::qpack_decompression_failed, "QPACK error in the request");
            case qpack::Decoder::Result::too_large: s.section.clear(); return fail_stream(s, 431);
            case qpack::Decoder::Result::blocked: return block(s, required);
        }
        s.section.clear();
        if (required) acknowledge_section(s.q.id, required);
        s.arena.assign(scratch);
        req.headers.rebase(scratch.data(), scratch.size(), s.arena.data());
        seen.rebase(scratch.data(), scratch.size(), s.arena.data());
        if (seen.overflow) return fail_stream(s, 431);
        switch (http::finish_request(seen, req, s.cookie, "HTTP/3.0", s.length_known, s.content_length)) {
            case http::Assembled::ok: break;
            case http::Assembled::malformed: return malformed(s, seen.reason);
            case http::Assembled::bad_content_length: return malformed(s, "content-length not a number");
        }
        s.headers_done = true;
        quic::QuicStream& q = s.q;
        if (q.at_end()) {
            s.body_done = true;
            q.fin_delivered = true;
            if (s.length_known && s.content_length != 0) return malformed(s, "content-length without a body");
        } else {
            s.has_body = true;
            req.has_body = true;
            req.content_length = s.content_length;
            req.chunked = !s.length_known;  // "length unknown" for the handlers
            req.body = &s.body_source;
            s.body_limit = body_limit(req.host);
            if (s.length_known && s.content_length > s.body_limit) return fail_stream(s, 413);
            quic_.stream_window(q, std::min<std::uint64_t>(std::max<std::uint64_t>(s.body_limit, 1), kStreamWindowMax));
        }
        dispatch(s);
    }

    // The section references inserts the encoder stream has not delivered: the stream
    // waits, at most kMaxBlocked of them (RFC 9204 2.1.2; a seventeenth is a connection error).
    void block(H3Stream& s, std::uint64_t required) {
        if (blocked_.size() >= qpack::Decoder::kMaxBlocked) return connection_error(err::qpack_decompression_failed, "too many blocked streams");
        s.blocked = true;
        s.required = required;
        blocked_.push_back(&s);
    }

    // After encoder-stream inserts: every blocked stream the table now satisfies goes on.
    void unblock_streams() {
        for (std::size_t i = 0; i < blocked_.size() && !closed_;) {
            H3Stream* s = blocked_[i];
            if (s->required > decoder_.insert_count()) { ++i; continue; }
            blocked_.erase(blocked_.begin() + static_cast<std::ptrdiff_t>(i));
            s->blocked = false;
            QUIC_TRACE("h3: unblock stream=%llu\n", static_cast<unsigned long long>(s->q.id));
            if (s->trailers) decode_trailers(*s);
            else begin_request(*s);
            if (!s->closed && !s->blocked) pump(*s);
        }
    }

    // Trailers are decoded to keep the decoder's state and its acknowledgements in step,
    // and discarded (the handlers see none).
    void decode_trailers(H3Stream& s) {
        std::string& scratch = decode_scratch_;
        scratch.clear();
        std::uint64_t required = 0;
        const auto r = decoder_.decode(s.section, scratch, live_->max_header_size,
                                       [](std::string_view, std::string_view, qpack::Origin) { return true; }, required);
        if (r == qpack::Decoder::Result::blocked) return block(s, required);
        s.section.clear();
        s.trailers = false;
        if (r == qpack::Decoder::Result::malformed) return connection_error(err::qpack_decompression_failed, "QPACK error in the trailers");
        if (required) acknowledge_section(s.q.id, required);
    }

    void acknowledge_section(std::uint64_t stream_id, std::uint64_t required) {
        decoder_.section_acknowledged(stream_id, required, qdec_.q.head);
        decoder_dirty_ = true;
    }

public:
    // The transport is about to build packets: the decoder stream's pending instructions
    // (an insert count increment for inserts no section acknowledged) go on it now.
    void before_produce() {
        if (ici_due_) {
            decoder_.insert_count_increment(qdec_.q.head);
            ici_due_ = false;
            decoder_dirty_ = true;
        }
        if (decoder_dirty_ && qdec_.q.open) {
            decoder_dirty_ = false;
            qdec_.q.total = qdec_.q.head_end();
            quic_.stream_ready(qdec_.q);
        }
    }

private:
    std::size_t body_limit(std::string_view host) const noexcept {
        const SiteConfig* site = listener_->router.site(host);
        return site ? body_limit_of(*site, *live_) : live_->max_body_size;
    }

    void dispatch(H3Stream& s) {
        WorkerState& ws = worker_.state;
        ws.site = nullptr;
        fill_connection_info(s);
        if (!live_->trusted_proxies.empty()) apply_forwarded(s);
        const LocationConfig* loc = dispatcher_.route(s.stream, listener_->router, ws);
        s.site = static_cast<const SiteConfig*>(ws.site);
        int hops = 0;
        while (loc) {
            if (loc->kind == HandlerKind::control) {
                dispatcher_.static_handler().error(s.stream, 404, true);
                break;
            }
            if (loc->kind != HandlerKind::static_) {
                const unsigned gen = s.gen;
                H3Stream* sp = &s;
                if (loc->kind == HandlerKind::httparena) {
                    dispatcher_.httparena().start(s.stream, *loc, ws, [sp, gen] {
                        if (sp->gen != gen) return;
                        static_cast<Http3Connection*>(sp->body_source.owner)->respond(*sp);
                    });
                    return;
                }
                auto self = this->shared_from_this();
                auto done = [self, sp, gen] {
                    if (sp->gen != gen || self->closed_) return;
                    sp->upstream.reset();
                    self->respond(*sp);
                    self->flush_if_outside();
                };
                const auto* site = static_cast<const SiteConfig*>(ws.site);
                std::shared_ptr<UpstreamRequest> req =
                    loc->kind == HandlerKind::fastcgi
                        ? dispatcher_.fcgi().start(s.stream, *site, *loc, ws, worker_.upstream_pool, std::move(done))
                    : loc->kind == HandlerKind::cgi
                        ? dispatcher_.cgi().start(s.stream, *site, *loc, ws, worker_.upstream_pool, std::move(done))
                        : dispatcher_.proxy().start(s.stream, *loc, ws, worker_.upstream_pool, std::move(done));
                if (req && sp->gen == gen && !sp->closed) sp->upstream = std::move(req);
                return;
            }
            loc = dispatcher_.serve_static(s.stream, *loc, ws, hops);
            s.site = static_cast<const SiteConfig*>(ws.site);
        }
        respond(s);
    }

    // The response is filled: a HEADERS frame, the DATA frame's header, the body by
    // reference, the FIN; the transport frames it from there.
    void respond(H3Stream& s) {
        if (s.closed || s.responded || closed_) return;
        Response& r = s.stream.response;
        r.upgrade = false;
        quic::QuicStream& q = s.q;
        build_head(s, q.head);
        std::uint64_t body_len = 0;
        if (!r.head) {
            if (const auto* m = std::get_if<MemoryBody>(&r.body)) {
                q.mem = m->data;
                body_len = m->data.size();
            } else if (const auto* f = std::get_if<FileBody>(&r.body)) {
                q.file = f->file;
                q.file_offset = f->offset;
                q.file_len = f->size;
                body_len = f->size;
            } else if (std::holds_alternative<std::unique_ptr<StreamBody>>(r.body)) {
                // A streamed body (an unbuffered upstream) is phase I1b: the stream is reset.
                s.responded = true;
                quic_.stream_reset(q, err::internal);
                return;
            }
        }
        if (body_len) append_frame_header(q.head, frame::data, body_len);
        q.total = q.head.size() + body_len;
        q.fin = true;
        s.responded = true;
        s.body_sent = body_len;
        quic_.stream_ready(q);
    }

    void build_head(H3Stream& s, std::string& out) {
        Response& r = s.stream.response;
        WorkerState& ws = worker_.state;
        std::string& sec = s.scratch;
        sec.clear();
        qpack::append_section_prefix(sec);
        qpack::append_status(sec, r.status);
        if (!ws.server_line.empty()) {
            if (ws.h3_server_field.empty()) qpack::append_literal_name_ref(ws.h3_server_field, 92, cfg_.server_header);
            sec.append(ws.h3_server_field);
        }
        if (ws.h3_date_time != ws.now) {  // the date literal, once per second per worker
            ws.h3_date_field.clear();
            qpack::append_literal_name_ref(ws.h3_date_field, 6, ws.date.at(ws.now));
            ws.h3_date_time = ws.now;
        }
        sec.append(ws.h3_date_field);
        if (!r.prebuilt_h3.empty()) {
            if (!r.content_type.empty()) qpack::append_field(sec, "content-type", r.content_type);
            if (!r.content_encoding.empty()) qpack::append_field(sec, "content-encoding", r.content_encoding);
            if (r.vary) qpack::append_indexed(sec, 59);  // vary: accept-encoding
            sec.append(r.prebuilt_h3);
        } else if (!r.prebuilt_headers.empty()) {
            encode_text_block(sec, r.prebuilt_headers, s.section);
        }
        for (const HeaderField& f : r.headers) append_lower(sec, f.name, f.value, s.section);
        out.clear();
        append_frame_header(out, frame::headers, sec.size());
        out.append(sec);
    }

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
        qpack::append_field(out, scratch, value);
    }

    // A protocol-level answer (413, 431) with the canned page.
    void fail_stream(H3Stream& s, int status) {
        worker_.state.now = std::time(nullptr);
        worker_.state.site = nullptr;
        dispatcher_.static_handler().error(s.stream, status, true);
        s.headers_done = true;
        respond(s);
    }

    // A malformed request (RFC 9114 4.1.2): the stream is reset with H3_MESSAGE_ERROR.
    void malformed(H3Stream& s, const char* reason) {
        (void)reason;
        quic::QuicStream& q = s.q;
        s.headers_done = true;
        s.responded = true;
        if (!q.stop_sending_received && !q.at_end()) quic_.stream_stop_sending(q, err::message_error);
        quic_.stream_reset(q, err::message_error);
        q.fin_delivered = true;
        s.body_done = true;
        maybe_close(s);
    }

    // ---- the request body (BodyOwner) ----

    void read_body(H3Stream& s, char* buf, std::size_t len, StreamBody::ReadHandler handler) override {
        s.pending_buf = buf;
        s.pending_len = len;
        s.pending_handler = std::move(handler);
        if (s.body_done && s.q.available() == 0) return deliver(s, 0);
        // Data waiting is delivered at once; an empty buffer waits for the next STREAM frame.
        // Inline completions are bounded (the yield budget): beyond it the pump is posted.
        if (++inline_reads_ >= 16) {
            inline_reads_ = 0;
            auto self = this->shared_from_this();
            H3Stream* sp = &s;
            const unsigned gen = s.gen;
            asio::post(worker_.ctx, [self, sp, gen] {
                if (sp->gen == gen && !self->closed_) self->pump(*sp);
            });
            return;
        }
        pump(s);
    }

    void deliver(H3Stream& s, std::size_t n) {
        auto h = std::move(s.pending_handler);
        s.pending_handler = nullptr;
        s.pending_buf = nullptr;
        s.pending_len = 0;
        if (h) h(std::error_code(), n);
    }
    void deliver_error(H3Stream& s, std::error_code ec) {
        auto h = std::move(s.pending_handler);
        s.pending_handler = nullptr;
        s.pending_buf = nullptr;
        s.pending_len = 0;
        if (h) h(ec, 0);
    }

    // ---- the peer's unidirectional streams (RFC 9114 6.2) ----

    void on_uni_data(H3Stream& s) {
        quic::QuicStream& q = s.q;
        QUIC_TRACE("h3: uni stream=%llu known=%d type=%llu avail=%zu\n", static_cast<unsigned long long>(q.id), s.type_known ? 1 : 0,
                   static_cast<unsigned long long>(s.uni_type), q.available());
        if (!s.type_known) {
            const auto* p = reinterpret_cast<const unsigned char*>(q.data());
            const unsigned char* const start = p;
            std::uint64_t type = 0;
            if (!quic::read_varint(p, p + q.available(), type)) {
                if (q.at_end()) close_stream(s);
                return;
            }
            quic_.stream_consumed(q, static_cast<std::size_t>(p - start));
            s.type_known = true;
            s.uni_type = type;
            switch (type) {
                case stream_type::control:
                    if (peer_control_) return connection_error(err::stream_creation, "a second control stream");
                    peer_control_ = &s;
                    break;
                case stream_type::qpack_encoder:
                    if (peer_qenc_) return connection_error(err::stream_creation, "a second QPACK encoder stream");
                    peer_qenc_ = &s;
                    break;
                case stream_type::qpack_decoder:
                    if (peer_qdec_) return connection_error(err::stream_creation, "a second QPACK decoder stream");
                    peer_qdec_ = &s;
                    break;
                case stream_type::push:
                    return connection_error(err::stream_creation, "a push stream from a client");
                default:
                    break;  // reserved or unknown: its bytes are discarded
            }
        }
        for (int guard = 0; guard < 256 && !s.closed && !closed_; ++guard) {
            const std::size_t avail = q.available();
            if (avail == 0) break;
            if (s.uni_type == stream_type::control) {
                if (!s.in_frame) {
                    const auto* p = reinterpret_cast<const unsigned char*>(q.data());
                    const unsigned char* const start = p;
                    std::uint64_t type = 0, len = 0;
                    if (!quic::read_varint(p, p + avail, type) || !quic::read_varint(p, p + avail, len)) break;
                    quic_.stream_consumed(q, static_cast<std::size_t>(p - start));
                    s.in_frame = true;
                    s.frame_type = type;
                    s.frame_remaining = len;
                    if (!s.control_settings_seen) {
                        if (type != frame::settings) return connection_error(err::missing_settings, "the control stream did not start with SETTINGS");
                        if (len > 4096) return connection_error(err::frame_error, "SETTINGS too large");
                    } else if (type == frame::settings) {
                        return connection_error(err::frame_unexpected, "a second SETTINGS");
                    } else if (type == frame::data || type == frame::headers || type == frame::push_promise) {
                        return connection_error(err::frame_unexpected, "request frame on the control stream");
                    }
                    s.section.clear();
                    continue;
                }
                const std::size_t take = std::min<std::size_t>(avail, static_cast<std::size_t>(s.frame_remaining));
                if (s.frame_type == frame::settings) s.section.append(q.data(), take);
                quic_.stream_consumed(q, take);
                s.frame_remaining -= take;
                if (s.frame_remaining == 0) {
                    s.in_frame = false;
                    if (s.frame_type == frame::settings) {
                        if (!apply_settings(s.section)) return connection_error(err::settings_error, "invalid SETTINGS");
                        s.control_settings_seen = true;
                    }
                }
                if (take == 0) break;
                continue;
            }
            if (s.uni_type == stream_type::qpack_encoder) {
                const std::uint64_t before = decoder_.insert_count();
                std::size_t consumed = 0;
                if (!decoder_.encoder_stream(std::string_view(q.data(), avail), consumed))
                    return connection_error(err::qpack_encoder_stream, "invalid encoder stream instruction");
                QUIC_TRACE("h3: encoder stream avail=%zu consumed=%zu inserts=%llu capacity=%zu\n", avail, consumed,
                           static_cast<unsigned long long>(decoder_.insert_count()), decoder_.capacity());
                if (consumed) quic_.stream_consumed(q, consumed);
                if (decoder_.insert_count() != before) {
                    ici_due_ = true;
                    unblock_streams();
                }
                break;  // an incomplete instruction waits for more bytes
            }
            // The QPACK decoder stream (acknowledgements we never need while nothing is
            // indexed) and unknown types: their bytes are consumed and discarded.
            quic_.stream_consumed(q, avail);
        }
        if (q.at_end() && !q.fin_delivered) {
            q.fin_delivered = true;
            if (s.uni_type == stream_type::control || s.uni_type == stream_type::qpack_encoder || s.uni_type == stream_type::qpack_decoder)
                return connection_error(err::closed_critical_stream, "critical stream closed");
            close_stream(s);
        }
    }

    bool apply_settings(const std::string& payload) {
        const auto* p = reinterpret_cast<const unsigned char*>(payload.data());
        const unsigned char* const end = p + payload.size();
        std::uint64_t seen = 0;
        while (p < end) {
            std::uint64_t id = 0, value = 0;
            if (!quic::read_varint(p, end, id) || !quic::read_varint(p, end, value)) return false;
            if (id < 64) {
                if (seen & (std::uint64_t{1} << id)) return false;
                seen |= std::uint64_t{1} << id;
            }
            switch (id) {
                case setting::qpack_max_table_capacity: peer_qpack_capacity_ = value; break;
                case setting::max_field_section_size: peer_max_field_section_ = value; break;
                case setting::qpack_blocked_streams: peer_qpack_blocked_ = value; break;
                case 0x0: case 0x2: case 0x3: case 0x4: case 0x5: return false;  // HTTP/2 identifiers (7.2.4.1)
                default: break;
            }
        }
        return true;
    }

    // ---- stream lifecycle ----

    void maybe_close(H3Stream& s) {
        if (s.closed) return;
        const quic::QuicStream& q = s.q;
        const bool send_over = s.finished || (!s.responded && q.reset_sent) || (s.responded && q.send_done);
        const bool recv_over = q.fin_delivered || q.reset_received;
        if (send_over && recv_over) close_stream(s);
    }

    void close_stream(H3Stream& s) {
        if (s.closed) return;
        s.closed = true;
        if (s.upstream) {
            s.upstream->cancel();
            s.upstream.reset();
        }
        if (s.pending_handler) deliver_error(s, asio::error::operation_aborted);
        if (s.kind == H3Stream::Kind::request && s.headers_done) log_request(s);
        if (s.blocked) {  // the encoder learns that the section was never processed (RFC 9204 4.4.2)
            for (std::size_t i = 0; i < blocked_.size();)
                if (blocked_[i] == &s) blocked_.erase(blocked_.begin() + static_cast<std::ptrdiff_t>(i)); else ++i;
            decoder_.stream_cancelled(s.q.id, qdec_.q.head);
            decoder_dirty_ = true;
        }
        if (&s == peer_control_) peer_control_ = nullptr;
        if (&s == peer_qenc_) peer_qenc_ = nullptr;
        if (&s == peer_qdec_) peer_qdec_ = nullptr;
        quic_.stream_closed(s.q);
        streams_.release(s, live_->http2.max_concurrent_streams);
    }

    void connection_error(std::uint64_t code, std::string_view reason) {
        if (closed_) return;
        quic_.close(true, code, reason, now_);
    }

    // An answer produced outside a wake-up (an upstream's completion): its datagrams go
    // out now rather than with the next batch.
    void flush_if_outside() {
        if (quic_.touched || closed_) return;
        ep_.flush_connection(*this);
    }

    // ---- bookkeeping shared with HTTP/2 ----

    void remote_from(const sockaddr_storage& peer) {
        char text[INET6_ADDRSTRLEN] = {};
        if (peer.ss_family == AF_INET) {
            const auto* in = reinterpret_cast<const sockaddr_in*>(&peer);
            ::inet_ntop(AF_INET, &in->sin_addr, text, sizeof text);
            remote_port_ = ntohs(in->sin_port);
            asio::ip::address_v4::bytes_type b;
            std::memcpy(b.data(), &in->sin_addr, 4);
            remote_addr_ = asio::ip::address_v4(b);
        } else if (peer.ss_family == AF_INET6) {
            const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&peer);
            ::inet_ntop(AF_INET6, &in6->sin6_addr, text, sizeof text);
            remote_port_ = ntohs(in6->sin6_port);
            asio::ip::address_v6::bytes_type b;
            std::memcpy(b.data(), &in6->sin6_addr, 16);
            remote_addr_ = asio::ip::address_v6(b);
        }
        remote_ = text[0] ? text : "-";
    }

    void fill_connection_info(H3Stream& s) {
        ConnectionInfo& c = s.stream.conn;
        c.remote_address = remote_;
        c.remote_port = remote_port_;
        c.local_address = listener_->address_text;
        c.local_port = listener_->port;
        c.tls = true;
        c.cert = cert_names_.get();
        c.client_address = {};
        c.forwarded_https = false;
        c.trusted_peer = false;
    }

    void apply_forwarded(H3Stream& s) {
        if (!trusted_checked_) {
            trusted_peer_ = in_any(live_->trusted_proxies, remote_addr_);
            trusted_checked_ = true;
        }
        s.stream.conn.trusted_peer = trusted_peer_;
        if (trusted_peer_) resolve_forwarded(s.stream.request, live_->trusted_proxies, s.stream.conn, s.client_addr);
    }

    void refresh_generation() {
        if (gen_.get() == worker_.gen.get()) return;
        const Listener* l = worker_.gen->find(listener_->address);
        if (!l) return;  // the listener left the configuration: this connection keeps serving on the old one until it ends
        gen_ = worker_.gen;
        listener_ = l;
        live_ = &gen_->cfg;
    }

    void log_request(H3Stream& s) {
        if (s.logged) return;
        s.logged = true;
        const SiteConfig* site = s.site ? s.site : listener_->router.default_site();
        if (!site || site->access_log_sink < 0) return;
        const Request& req = s.stream.request;
        AccessRecord rec;
        rec.remote = s.stream.conn.client_address.empty() ? std::string_view(remote_) : s.stream.conn.client_address;
        rec.host = req.host;
        rec.method = req.method_name;
        rec.target = req.target;
        rec.version_minor = 1;
        rec.protocol = "HTTP/3.0";
        rec.status = s.stream.response.status;
        rec.bytes = s.body_sent;
        rec.referer = req.headers.get("referer");
        rec.user_agent = req.headers.get("user-agent");
        if (s.stream.response.upstream) rec.upstream = s.stream.response.upstream;
        worker_.state.logs.log(site->access_log_sink, worker_.state.now ? worker_.state.now : std::time(nullptr), rec);
    }

    Endpoint& ep_;
    Worker& worker_;
    std::shared_ptr<const Generation> gen_;
    const Listener* listener_;
    const Config* live_;
    const Config& cfg_;
    Dispatcher& dispatcher_;
    Quic quic_;
    TimePoint now_;
    std::shared_ptr<const CertNames> cert_names_;
    http::StreamPool<H3Stream> streams_;
    H3Stream ctl_, qenc_, qdec_;  // our unidirectional streams
    H3Stream* peer_control_ = nullptr;
    H3Stream* peer_qenc_ = nullptr;
    H3Stream* peer_qdec_ = nullptr;
    std::uint64_t peer_qpack_capacity_ = 0, peer_qpack_blocked_ = 0, peer_max_field_section_ = ~std::uint64_t{0};
    qpack::Decoder decoder_;
    std::vector<H3Stream*> blocked_;  // sections waiting for the encoder stream
    bool ici_due_ = false;            // inserts arrived that no section acknowledged yet
    bool decoder_dirty_ = false;      // the decoder stream has new bytes to send
    std::string decode_scratch_;
    std::string remote_;
    std::uint16_t remote_port_ = 0;
    asio::ip::address remote_addr_;
    bool trusted_checked_ = false, trusted_peer_ = false;
    bool closed_ = false;
    unsigned inline_reads_ = 0;
    std::uint64_t streams_opened_ = 0;
};

}  // namespace agensio::h3
