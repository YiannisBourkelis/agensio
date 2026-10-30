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
    compress,         // yes, with Stream::coding
    mode_off,         // the site has no key, or a client that sent no acceptable Accept-Encoding
    no_accept,        // no Accept-Encoding, or none acceptable
    type,             // not a compressible media type (or none)
    size,             // under min_size
    status,           // a status without content, or a 206
    already_encoded,  // the application sent a Content-Encoding
    no_transform,     // Cache-Control: no-transform, in the request or the answer
    path_off,         // under one of the site's `off` paths
    event_stream,     // text/event-stream without event_streams = true
    streamed,         // a streamed answer: compressed in pieces from step 6 on, identity until then
    large,            // a buffered answer above kWholeMax: in pieces from step 6 on, identity with Vary until then
    head,             // a HEAD answer: the GET's bytes are not here to compress; Vary says what the GET varies on
};

inline std::string_view reason_name(Reason r) noexcept {
    switch (r) {
        case Reason::compress: return "compress";
        case Reason::mode_off: return "mode_off";
        case Reason::no_accept: return "no_accept_encoding";
        case Reason::type: return "type";
        case Reason::size: return "size";
        case Reason::status: return "status";
        case Reason::already_encoded: return "already_encoded";
        case Reason::no_transform: return "no_transform";
        case Reason::path_off: return "path_off";
        case Reason::event_stream: return "event_stream";
        case Reason::streamed: return "streamed";
        case Reason::large: return "large";
        case Reason::head: return "head";
    }
    return "";
}

// The most a worker compresses in one go (docs/design-compression.md 6): a buffered answer up to this
// is compressed whole between two reads of the loop, about 0.5 ms with gzip 5; a larger one is
// compressed as the writer pulls it, in pieces of this size, from step 6 on.
inline constexpr std::uint64_t kWholeMax = 64 * 1024;

// The fields the decision reads, as the head loop gathered them (empty when absent).
struct Answer {
    int status = 200;
    std::string_view content_type;
    std::string_view content_encoding;
    std::string_view cache_control;  // the answer's
    std::uint64_t body_size = 0;     // the buffered body's bytes
    bool streamed = false;
    bool content_range = false;  // a Content-Range field: a 206 or a mislabelled one
    bool head = false;           // the request was HEAD: the application sends the head alone
};

// Cache-Control holds the no-transform directive (RFC 9111 5.2.1.6, 5.2.2.6), as a token.
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

// The request's path (the target before its query) lies under one of the site's `off` prefixes.
inline bool under_off_path(std::string_view target, const std::vector<std::string>& off) noexcept {
    const std::size_t q = target.find('?');
    const std::string_view path = q == std::string_view::npos ? target : target.substr(0, q);
    for (const std::string& p : off) {
        if (path.size() < p.size() || path.compare(0, p.size(), p) != 0) continue;
        if (path.size() == p.size() || p.back() == '/' || path[p.size()] == '/') return true;
    }
    return false;
}

// Media types beyond the built-in list (root's types_add, lower-case, no parameters).
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

inline Reason decide(const Stream& s, const Answer& a) noexcept {
    if (!s.site_compression || !s.root_compression) return Reason::mode_off;
    const auto* site = static_cast<const SiteConfig::Compression*>(s.site_compression);
    const auto* root = static_cast<const CompressionConfig*>(s.root_compression);
    if (!site->on) return Reason::mode_off;
    if (s.coding == 0) return Reason::no_accept;
    if (a.status < 200 || a.status == 204 || a.status == 304 || a.status == 206 || a.content_range) return Reason::status;
    if (!a.content_encoding.empty()) return Reason::already_encoded;
    if (a.content_type.empty()) return Reason::type;
    const bool event_stream = a.content_type.size() >= 17 && (a.content_type.substr(0, 17) == "text/event-stream");
    if (event_stream) return site->event_streams ? Reason::streamed : Reason::event_stream;
    if (!compressible_type(a.content_type) && !added_type(a.content_type, root->types_add)) return Reason::type;
    if (has_no_transform(a.cache_control) || has_no_transform(s.request.headers.get("cache-control"))) return Reason::no_transform;
    if (!site->off_paths.empty() && under_off_path(s.request.target, site->off_paths)) return Reason::path_off;
    if (a.head) return Reason::head;  // before the size: a HEAD answer has no body to measure
    if (a.streamed) return Reason::streamed;
    if (a.body_size < root->min_size) return Reason::size;
    if (a.body_size > kWholeMax) return Reason::large;
    return Reason::compress;
}

}  // namespace agensio::compress_answer
