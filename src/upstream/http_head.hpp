// HTTP/1.x response head parser for the reverse proxy: "HTTP/1.1 200 OK\r\n" + fields +
// blank line. Same field rules as the request parser (no obs-fold, no bare CR, no control
// characters, names are tokens). Views point into `in`; the caller owns that buffer for
// the response's life. Header-only and Asio-free so it can be fuzzed.
#pragma once

#include <cstddef>
#include <string_view>

#include "core/headers.hpp"

namespace agensio::http {

struct ResponseHead {
    int version_minor = 1;   // HTTP/1.0 -> 0, HTTP/1.1 -> 1
    int status = 200;
    Headers headers;         // every field, in order
    std::size_t length = 0;  // bytes of the head including the blank line
};

enum class HeadStatus { complete, incomplete, error };

inline HeadStatus parse_response_head(std::string_view in, ResponseHead& out) noexcept {
    out.headers.clear();
    out.length = 0;
    std::size_t nl = in.find("\r\n");
    if (nl == std::string_view::npos) return in.size() > 8192 ? HeadStatus::error : HeadStatus::incomplete;
    const std::string_view line = in.substr(0, nl);
    // "HTTP/1.x SP 3DIGIT SP reason" (the reason may be empty).
    if (line.size() < 12 || !line.starts_with("HTTP/1.") || line[7] < '0' || line[7] > '1' || line[8] != ' ')
        return HeadStatus::error;
    out.version_minor = line[7] - '0';
    int code = 0;
    for (std::size_t i = 9; i < 12; ++i) {
        if (line[i] < '0' || line[i] > '9') return HeadStatus::error;
        code = code * 10 + (line[i] - '0');
    }
    if (code < 100 || code > 599) return HeadStatus::error;
    if (line.size() > 12 && line[12] != ' ') return HeadStatus::error;
    for (unsigned char c : line.substr(12))
        if ((c < 0x20 && c != '\t') || c == 0x7f) return HeadStatus::error;
    out.status = code;
    std::size_t pos = nl + 2;
    for (;;) {
        nl = in.find('\n', pos);
        if (nl == std::string_view::npos) return HeadStatus::incomplete;  // the client bounds the head size
        std::string_view field = in.substr(pos, nl - pos);
        if (field.empty() || field.back() != '\r') return HeadStatus::error;  // bare LF
        field.remove_suffix(1);
        pos = nl + 1;
        if (field.empty()) break;  // end of head
        const std::size_t colon = field.find(':');
        if (colon == std::string_view::npos || colon == 0) return HeadStatus::error;
        std::string_view name = field.substr(0, colon);
        std::string_view value = field.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
        for (unsigned char c : name)
            if (c <= 0x20 || c == 0x7f || c == ':' || c == '(' || c == ')' || c == '<' || c == '>' || c == '@' ||
                c == ',' || c == ';' || c == '\\' || c == '"' || c == '/' || c == '[' || c == ']' || c == '?' ||
                c == '=' || c == '{' || c == '}')
                return HeadStatus::error;
        for (unsigned char c : value)
            if ((c < 0x20 && c != '\t') || c == 0x7f) return HeadStatus::error;
        if (!out.headers.add(name, value)) return HeadStatus::error;
    }
    out.length = pos;
    return HeadStatus::complete;
}

// Hop-by-hop fields never forwarded in either direction (RFC 9110 section 7.6.1), plus
// the ones the framing layer owns.
inline bool is_hop_by_hop(std::string_view name) noexcept {
    for (const char* h : {"connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding",
                          "upgrade", "content-length"})
        if (Headers::iequals(name, h)) return true;
    return false;
}

// True when `list` (a Connection field value) names `name` as a connection option.
inline bool connection_lists(std::string_view list, std::string_view name) noexcept {
    std::size_t pos = 0;
    while (pos <= list.size()) {
        std::size_t comma = list.find(',', pos);
        if (comma == std::string_view::npos) comma = list.size();
        std::string_view token = list.substr(pos, comma - pos);
        while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) token.remove_prefix(1);
        while (!token.empty() && (token.back() == ' ' || token.back() == '\t')) token.remove_suffix(1);
        if (Headers::iequals(token, name)) return true;
        pos = comma + 1;
    }
    return false;
}

}  // namespace agensio::http
