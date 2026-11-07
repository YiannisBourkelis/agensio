// Whether an application's answer is compressed, and why not (docs/design-compression.md 4, 6, 8):
// the one decision apply_upstream_result takes once it has read the answer's head, pure over the
// fields it was given, so the unit tests cover every rule and path_check names the reason. Nothing
// here allocates or reads a library; the encoder runs where the decision says yes.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "config.hpp"
#include "core/stream.hpp"
#include "handlers/encoding.hpp"
#include "mime.hpp"

namespace agensio::compress_answer {

enum class Reason : std::uint8_t {
    compress,         // yes, with Stream::coding: a buffered answer up to kWholeMax, compressed whole
    pieces,           // yes: a larger buffered answer, a spilled one or a stream, compressed as it is sent
    mode_off,         // compression is not enabled for the site
    no_accept,        // no Accept-Encoding, or none acceptable
    type,             // not a compressible media type (or none)
    size,             // under min_size
    status,           // a status without content, or a 206
    already_encoded,  // the application sent a Content-Encoding
    no_transform,     // Cache-Control: no-transform, in the request or the answer
    path_off,         // under one of the site's exclude_paths
    signed_in,        // the request carried a credential agensio itself knows (design 7) and compress_signed_in = false
    event_stream,     // text/event-stream without compress_event_streams = true
    no_streaming,     // in pieces, which the client's protocol cannot carry: HTTP/1.0 (no chunked framing), HTTP/3 (no streamed body yet)
    budget,           // in pieces, with the worker's encoders at kStreamBudget: sent as it came, counted in status
    head,             // a HEAD answer: the GET's bytes are not here to compress; Vary says what the GET varies on
};

inline std::string_view reason_name(Reason r) noexcept {
    switch (r) {
        case Reason::compress: return "compress";
        case Reason::pieces: return "pieces";
        case Reason::mode_off: return "mode_off";
        case Reason::no_accept: return "no_accept_encoding";
        case Reason::type: return "type";
        case Reason::size: return "size";
        case Reason::status: return "status";
        case Reason::already_encoded: return "already_encoded";
        case Reason::no_transform: return "no_transform";
        case Reason::path_off: return "path_off";
        case Reason::signed_in: return "signed_in";
        case Reason::event_stream: return "event_stream";
        case Reason::no_streaming: return "no_streaming";
        case Reason::budget: return "budget";
        case Reason::head: return "head";
    }
    return "";
}

// The most a worker compresses in one go (docs/design-compression.md 6): a buffered answer up to this
// is compressed whole between two reads of the loop, so the limit bounds the time one answer holds
// the worker: at 256 KB about 0.35 ms with zstd 3 (what Chrome and Firefox get), 1.4 ms with brotli 4,
// 2.1 ms with gzip 5 (bench/results/compression-levels-20261030.md). 256 KB covers a CMS home page
// (WordPress 70 KB, Laravel's welcome page 82 KB), which the 64 KB of steps 3 and 4 left out; a
// larger answer is compressed as the writer pulls it, in 64 KB pieces (handlers/compressed_body.hpp).
inline constexpr std::uint64_t kWholeMax = 256 * 1024;

// The site's level for the coding (levels = { zstd, br, gzip }, the main file's unless the site sets its own).
inline int level_for(const CompressionConfig& c, Encoding e) noexcept {
    switch (e) {
        case Encoding::zstd: return c.level_zstd;
        case Encoding::br: return c.level_br;
        case Encoding::gzip: return c.level_gzip;
        case Encoding::identity: break;
    }
    return 0;
}

// The fields the decision reads, as the head loop gathered them (empty when absent).
struct Answer {
    int status = 200;
    std::string_view content_type;
    std::string_view content_encoding;
    std::string_view cache_control;  // the answer's
    std::uint64_t body_size = 0;     // the buffered body's bytes; a streamed one's declared length (length_known)
    bool streamed = false;
    bool length_known = false;       // a streamed answer declared its length (Content-Length)
    bool streams_ok = true;          // the client's protocol carries a body of unknown length (streams_unknown_length)
    bool content_range = false;  // a Content-Range field: a 206 or a mislabelled one
    bool head = false;           // the request was HEAD: the application sends the head alone
};

// Cache-Control holds the no-transform directive (RFC 9111 5.2.1.6, 5.2.2.6), as a token.
// text/event-stream, judged without parameters and in any case (RFC 9110 8.3.1).
inline bool is_event_stream(std::string_view content_type) noexcept {
    static constexpr std::string_view kEs = "text/event-stream";
    if (content_type.size() < kEs.size()) return false;
    for (std::size_t k = 0; k < kEs.size(); ++k) {
        const char c = content_type[k];
        if ((c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c) != kEs[k]) return false;
    }
    return content_type.size() == kEs.size() || content_type[kEs.size()] == ';' || content_type[kEs.size()] == ' ';
}

inline bool has_no_transform(std::string_view cc) noexcept {
    std::size_t i = 0;
    while (i <= cc.size()) {
        std::size_t j = cc.find(',', i);
        if (j == std::string_view::npos) j = cc.size();
        std::string_view d = cc.substr(i, j - i);
        while (!d.empty() && (d.front() == ' ' || d.front() == '\t')) d.remove_prefix(1);
        while (!d.empty() && (d.back() == ' ' || d.back() == '\t')) d.remove_suffix(1);
        if (d.size() == 12) {
            bool eq = true;
            static constexpr std::string_view kNt = "no-transform";
            for (std::size_t k = 0; k < 12 && eq; ++k) {
                const char c = d[k];
                eq = (c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c) == kNt[k];
            }
            if (eq) return true;
        }
        i = j + 1;
    }
    return false;
}

// The request's path (the target before its query) lies under one of the site's exclude_paths.
inline bool under_off_path(std::string_view target, const std::vector<std::string>& off) noexcept {
    const std::size_t q = target.find('?');
    const std::string_view path = q == std::string_view::npos ? target : target.substr(0, q);
    for (const std::string& p : off) {
        if (path.size() < p.size() || path.compare(0, p.size(), p) != 0) continue;
        if (path.size() == p.size() || p.back() == '/' || path[p.size()] == '/') return true;
    }
    return false;
}

// An Authorization field whose scheme a browser replays on its own on a request another site's page
// made it send (RFC 9110 11.6.2's HTTP authentication, cached per realm: Basic, Digest, Negotiate,
// NTLM), the credential BREACH needs (docs/design-compression.md 7). A Bearer token is a script's,
// never attached by the browser itself, so a JSON API authenticated that way is compressed.
inline bool browser_credential(std::string_view authorization) noexcept {
    const std::size_t sp = authorization.find(' ');
    const std::string_view scheme = sp == std::string_view::npos ? authorization : authorization.substr(0, sp);
    return Headers::iequals(scheme, "basic") || Headers::iequals(scheme, "digest") || Headers::iequals(scheme, "negotiate") ||
           Headers::iequals(scheme, "ntlm");
}

// The visitor is signed in by what agensio itself knows (design 7): a path its own [[site.auth]]
// protects (verified, or let in by skip_for), admission by an address rule of [[site.access]], or a
// credential the browser replays. An application's own login is invisible here, as to every server.
inline bool signed_in_visitor(const Stream& s) noexcept {
    return s.auth.protected_path || s.access_admitted || browser_credential(s.request.headers.get("authorization"));
}

// Media types beyond the built-in list (extra_types, lower-case, no parameters).
inline bool added_type(std::string_view content_type, const std::vector<std::string>& types) noexcept {
    if (types.empty()) return false;
    std::string_view t = content_type;
    if (const auto semi = t.find(';'); semi != std::string_view::npos) t = t.substr(0, semi);
    while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) t.remove_suffix(1);
    for (const std::string& a : types) {
        if (a.size() != t.size()) continue;
        bool eq = true;
        for (std::size_t k = 0; k < t.size() && eq; ++k) {
            const char c = t[k];
            eq = (c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c) == a[k];
        }
        if (eq) return true;
    }
    return false;
}

// HTTP/1.1 frames a body of unknown length chunked and HTTP/2 in DATA frames; HTTP/1.0 has no
// chunked framing (RFC 9112 7: a close-delimited body is all it has, and nginx skips 1.0 for that),
// and HTTP/3 carries no streamed body yet (docs/design-http3.md, I1b), so an answer compressed in
// pieces goes to those as it came.
inline bool streams_unknown_length(const Request& r) noexcept {
    if (r.protocol.empty()) return r.version_minor >= 1;
    return r.protocol == "HTTP/2.0";
}

inline Reason decide(const Stream& s, const Answer& a) noexcept {
    if (!s.site_compression) return Reason::mode_off;
    const auto* site = static_cast<const CompressionConfig*>(s.site_compression);
    if (!site->enabled) return Reason::mode_off;
    if (s.coding == 0) return Reason::no_accept;
    if (a.status < 200 || a.status == 204 || a.status == 304 || a.status == 206 || a.content_range) return Reason::status;
    if (!a.content_encoding.empty()) return Reason::already_encoded;
    if (a.content_type.empty()) return Reason::type;
    // An event stream is compressed only when the site says so, and then like any other answer: the
    // rules below hold for it too.
    if (is_event_stream(a.content_type)) {
        if (!site->compress_event_streams) return Reason::event_stream;
    } else if (!compressible_type(a.content_type) && !added_type(a.content_type, site->extra_types)) {
        return Reason::type;
    }
    if (has_no_transform(a.cache_control) || has_no_transform(s.request.headers.get("cache-control"))) return Reason::no_transform;
    if (!site->exclude_paths.empty() && under_off_path(s.request.target, site->exclude_paths)) return Reason::path_off;
    if (!site->compress_signed_in && signed_in_visitor(s)) return Reason::signed_in;
    if (a.head) return Reason::head;  // before the size: a HEAD answer has no body to measure
    if (!a.streamed) {
        if (a.body_size < site->min_size) return Reason::size;
        if (a.body_size <= kWholeMax) return Reason::compress;
    } else if (a.length_known && a.body_size < site->min_size) {
        return Reason::size;  // a stream is measured by the length it declares, or not at all (nginx's gzip_min_length)
    }
    return a.streams_ok ? Reason::pieces : Reason::no_streaming;
}

}  // namespace agensio::compress_answer
