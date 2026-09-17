// FastCGI/1.1 wire format (https://fastcgi-archives.github.io/FastCGI_Specification.html)
// and the CGI response head: pure encode/decode over strings and views, no I/O, so the
// codec is unit-tested byte by byte and fuzzed (tests/fuzz/fuzz_fcgi.cpp). The client in
// fcgi_client.hpp does the sockets.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "core/headers.hpp"

namespace agensio::fcgi {

inline constexpr std::uint8_t kVersion = 1;
inline constexpr std::size_t kHeaderSize = 8;
inline constexpr std::size_t kMaxContent = 65535;  // per record
inline constexpr std::uint16_t kRoleResponder = 1;
inline constexpr std::uint8_t kFlagKeepConn = 1;

enum class RecordType : std::uint8_t {
    begin_request = 1,
    abort_request = 2,
    end_request = 3,
    params = 4,
    stdin_ = 5,
    stdout_ = 6,
    stderr_ = 7,
    data = 8,
    get_values = 9,
    get_values_result = 10,
    unknown_type = 11,
};

enum class ProtocolStatus : std::uint8_t {
    request_complete = 0,
    cant_mpx_conn = 1,
    overloaded = 2,
    unknown_role = 3,
};

struct RecordHeader {
    std::uint8_t version = 0;
    std::uint8_t type = 0;
    std::uint16_t request_id = 0;
    std::uint16_t content_length = 0;
    std::uint8_t padding_length = 0;
};

// ---- encoding ----

// Appends one record: header, content and padding to a multiple of 8 bytes.
// content.size() must be <= kMaxContent.
inline void append_record(std::string& out, RecordType type, std::uint16_t request_id, std::string_view content) {
    const std::size_t len = content.size();
    const std::uint8_t padding = static_cast<std::uint8_t>((8 - (len % 8)) % 8);
    const char header[kHeaderSize] = {
        static_cast<char>(kVersion),
        static_cast<char>(type),
        static_cast<char>(request_id >> 8),
        static_cast<char>(request_id & 0xff),
        static_cast<char>(len >> 8),
        static_cast<char>(len & 0xff),
        static_cast<char>(padding),
        0,
    };
    out.append(header, kHeaderSize);
    out.append(content);
    out.append(padding, '\0');
}

// Appends `content` as one or more records of at most kMaxContent bytes each, followed by
// the empty record that ends the stream when `terminate` is set.
inline void append_stream(std::string& out, RecordType type, std::uint16_t request_id, std::string_view content,
                          bool terminate) {
    while (!content.empty()) {
        const std::size_t n = content.size() < kMaxContent ? content.size() : kMaxContent;
        append_record(out, type, request_id, content.substr(0, n));
        content.remove_prefix(n);
    }
    if (terminate) append_record(out, type, request_id, {});
}

inline void append_begin_request(std::string& out, std::uint16_t request_id, bool keep_conn) {
    const char body[8] = {0, static_cast<char>(kRoleResponder), static_cast<char>(keep_conn ? kFlagKeepConn : 0),
                          0, 0, 0, 0, 0};
    append_record(out, RecordType::begin_request, request_id, std::string_view(body, 8));
}

inline void append_abort_request(std::string& out, std::uint16_t request_id) {
    append_record(out, RecordType::abort_request, request_id, {});
}

// One name-value pair in the FCGI_PARAMS encoding (1-byte lengths below 128, else 4-byte).
inline void append_param(std::string& params, std::string_view name, std::string_view value) {
    auto put_len = [&](std::size_t n) {
        if (n < 128) {
            params.push_back(static_cast<char>(n));
        } else {
            params.push_back(static_cast<char>(0x80 | ((n >> 24) & 0x7f)));
            params.push_back(static_cast<char>((n >> 16) & 0xff));
            params.push_back(static_cast<char>((n >> 8) & 0xff));
            params.push_back(static_cast<char>(n & 0xff));
        }
    };
    put_len(name.size());
    put_len(value.size());
    params.append(name);
    params.append(value);
}

// ---- decoding ----

inline bool parse_header(std::string_view in, RecordHeader& h) noexcept {
    if (in.size() < kHeaderSize) return false;
    const auto* b = reinterpret_cast<const unsigned char*>(in.data());  // NOLINT: byte view of the wire header
    h.version = b[0];
    h.type = b[1];
    h.request_id = static_cast<std::uint16_t>((b[2] << 8) | b[3]);
    h.content_length = static_cast<std::uint16_t>((b[4] << 8) | b[5]);
    h.padding_length = b[6];
    return true;
}

struct EndRequest {
    std::uint32_t app_status = 0;
    ProtocolStatus protocol_status = ProtocolStatus::request_complete;
};

inline bool parse_end_request(std::string_view content, EndRequest& out) noexcept {
    if (content.size() < 8) return false;
    const auto* b = reinterpret_cast<const unsigned char*>(content.data());  // NOLINT: byte view
    out.app_status = (static_cast<std::uint32_t>(b[0]) << 24) | (static_cast<std::uint32_t>(b[1]) << 16) |
                     (static_cast<std::uint32_t>(b[2]) << 8) | b[3];
    out.protocol_status = static_cast<ProtocolStatus>(b[4]);
    return true;
}

// Cuts complete records off the front of a buffer. Feed the unconsumed bytes again after
// more input arrived; a record is only reported once header, content and padding are all
// present, so `content` is a view into `in` that stays valid until the caller compacts.
enum class ReadStatus { need_more, record, error };

inline ReadStatus next_record(std::string_view in, std::size_t& consumed, RecordHeader& h,
                              std::string_view& content) noexcept {
    consumed = 0;
    if (!parse_header(in, h)) return ReadStatus::need_more;
    if (h.version != kVersion) return ReadStatus::error;
    const std::size_t total = kHeaderSize + h.content_length + h.padding_length;
    if (in.size() < total) return ReadStatus::need_more;
    content = in.substr(kHeaderSize, h.content_length);
    consumed = total;
    return ReadStatus::record;
}

// ---- CGI response head ----
// "Status: 302 Found\r\nLocation: /x\r\nContent-Type: text/html\r\n\r\n" (LF or CRLF, RFC 3875
// section 6). Status defaults to 200, or 302 when only Location is present (absolute or
// local URL). Views point into `in`; the caller owns that buffer for the response's life.

struct CgiHead {
    int status = 200;
    Headers headers;      // every field except Status (Location and the rest are passed through)
    std::size_t length = 0;  // bytes of the head including the blank line
};

enum class HeadStatus { complete, incomplete, error };

inline HeadStatus parse_cgi_head(std::string_view in, CgiHead& out) noexcept {
    out.status = 200;
    out.headers.clear();
    out.length = 0;
    std::size_t pos = 0;
    bool seen_status = false, seen_location = false;
    for (;;) {
        const std::size_t nl = in.find('\n', pos);
        if (nl == std::string_view::npos) return HeadStatus::incomplete;  // the client bounds the head size
        std::string_view line = in.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        pos = nl + 1;
        if (line.empty()) break;  // end of head
        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0) return HeadStatus::error;
        std::string_view name = line.substr(0, colon);
        std::string_view value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
        for (unsigned char c : name)
            if (c <= 0x20 || c == 0x7f || c == ':') return HeadStatus::error;
        for (unsigned char c : value)
            if ((c < 0x20 && c != '\t') || c == 0x7f) return HeadStatus::error;
        if (Headers::iequals(name, "status")) {
            if (value.size() < 3) return HeadStatus::error;
            int code = 0;
            for (std::size_t i = 0; i < 3; ++i) {
                if (value[i] < '0' || value[i] > '9') return HeadStatus::error;
                code = code * 10 + (value[i] - '0');
            }
            if (code < 100 || code > 599) return HeadStatus::error;
            out.status = code;
            seen_status = true;
            continue;
        }
        if (Headers::iequals(name, "location")) seen_location = true;
        if (!out.headers.add(name, value)) return HeadStatus::error;
    }
    if (!seen_status && seen_location) out.status = 302;
    out.length = pos;
    return HeadStatus::complete;
}

}  // namespace agensio::fcgi
