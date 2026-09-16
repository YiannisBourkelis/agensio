#include "http_parser.hpp"

#include <cstring>

#include "strings.hpp"

namespace agensio {

namespace {

inline char lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
}

inline std::string_view trim(std::string_view s) noexcept {
    std::size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t'))
        ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t'))
        --e;
    return slice(s, b, e - b);
}

// Finds the next line end. Returns the line (without CR/LF) and the index just past it.
// Returns false if no LF is present yet.
inline bool next_line(std::string_view buf, std::size_t pos, std::string_view& line, std::size_t& next) noexcept {
    const char* start = buf.data() + pos;
    const void* lf = std::memchr(start, '\n', buf.size() - pos);
    if (!lf) return false;
    std::size_t lf_idx = static_cast<std::size_t>(static_cast<const char*>(lf) - buf.data());
    std::size_t end = lf_idx;
    if (end > pos && buf[end - 1] == '\r') --end;
    line = slice(buf, pos, end - pos);
    next = lf_idx + 1;
    return true;
}

inline bool is_tchar(unsigned char c) noexcept {
    if (c >= 'a' && c <= 'z') return true;
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= '0' && c <= '9') return true;
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            return true;
        default:
            return false;
    }
}

}  // namespace

bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (lower(a[i]) != lower(b[i])) return false;
    return true;
}

bool has_token(std::string_view value, std::string_view token) noexcept {
    std::size_t i = 0;
    while (i < value.size()) {
        std::size_t j = value.find(',', i);
        if (j == std::string_view::npos) j = value.size();
        if (iequals(trim(slice(value, i, j - i)), token)) return true;
        i = j + 1;
    }
    return false;
}

ParseStatus parse_request(std::string_view buf, Request& out) noexcept {
    out = Request{};
    std::size_t pos = 0;
    std::string_view line;
    std::size_t next = 0;

    // Tolerate leading CRLFs (RFC 7230 3.5).
    while (pos < buf.size() && (buf[pos] == '\r' || buf[pos] == '\n'))
        ++pos;

    if (!next_line(buf, pos, line, next)) return ParseStatus::incomplete;

    // request-line = method SP request-target SP HTTP-version
    std::size_t sp1 = line.find(' ');
    if (sp1 == std::string_view::npos || sp1 == 0) return ParseStatus::bad_request;
    std::size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos || sp2 == sp1 + 1) return ParseStatus::bad_request;

    out.method_name = slice(line, 0, sp1);
    for (unsigned char c : out.method_name)
        if (!is_tchar(c)) return ParseStatus::bad_request;
    if (out.method_name == "GET") out.method = Method::GET;
    else if (out.method_name == "HEAD") out.method = Method::HEAD;
    else out.method = Method::OTHER;

    out.target = slice(line, sp1 + 1, sp2 - sp1 - 1);
    for (unsigned char c : out.target)
        if (c <= 0x20 || c == 0x7f) return ParseStatus::bad_request;

    std::string_view version = slice(line, sp2 + 1);
    if (version.size() != 8 || slice(version, 0, 5) != "HTTP/" || version[6] != '.') return ParseStatus::bad_request;
    if (version[5] != '1') return ParseStatus::version_not_supported;
    if (version[7] == '1') out.version_minor = 1;
    else if (version[7] == '0') out.version_minor = 0;
    else return ParseStatus::version_not_supported;

    pos = next;
    std::size_t header_count = 0;
    bool seen_host = false, seen_content_length = false, seen_transfer_encoding = false;
    std::string_view content_length;
    for (;;) {
        if (!next_line(buf, pos, line, next)) return ParseStatus::incomplete;
        pos = next;
        if (line.empty()) break;  // end of head
        if (++header_count > kMaxHeaderCount) return ParseStatus::too_many_headers;

        // obs-fold (RFC 9112 5.2) and bare CR (RFC 9112 2.2) are rejected outright.
        if (line[0] == ' ' || line[0] == '\t') return ParseStatus::bad_request;
        if (std::memchr(line.data(), '\r', line.size()) != nullptr) return ParseStatus::bad_request;

        std::size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0) return ParseStatus::bad_request;
        std::string_view name = slice(line, 0, colon);
        for (unsigned char c : name)
            if (!is_tchar(c)) return ParseStatus::bad_request;  // also rejects whitespace before the colon
        std::string_view value = trim(slice(line, colon + 1));
        for (unsigned char c : value)
            if ((c < 0x20 && c != '\t') || c == 0x7f) return ParseStatus::bad_request;  // field-value: no CTLs

        switch (lower(name[0])) {
            case 'h':
                if (iequals(name, "host")) {
                    if (seen_host) return ParseStatus::bad_request;  // RFC 9112 3.2: exactly one Host
                    seen_host = true;
                    for (unsigned char c : value)
                        if (c <= 0x20 || c == '/' || c == '\\' || c == '"' || c == '<' || c == '>')
                            return ParseStatus::bad_request;
                    out.host = value;
                }
                break;
            case 'c':
                if (iequals(name, "connection")) out.connection = value;
                else if (iequals(name, "content-length")) {
                    if (value.empty() || value.size() > kMaxContentLengthDigits) return ParseStatus::bad_request;
                    bool nonzero = false;
                    for (unsigned char c : value) {
                        if (c < '0' || c > '9') return ParseStatus::bad_request;
                        if (c != '0') nonzero = true;
                    }
                    // Duplicates are only tolerated when identical (RFC 9110 8.6).
                    if (seen_content_length && value != content_length) return ParseStatus::bad_request;
                    seen_content_length = true;
                    content_length = value;
                    if (nonzero) out.has_body = true;
                }
                break;
            case 'i':
                if (iequals(name, "if-none-match")) out.if_none_match = value;
                else if (iequals(name, "if-modified-since")) out.if_modified_since = value;
                break;
            case 't':
                if (iequals(name, "transfer-encoding")) {
                    if (out.version_minor == 0) return ParseStatus::bad_request;  // not defined for HTTP/1.0
                    seen_transfer_encoding = true;
                    out.has_body = true;
                }
                break;
            default:
                break;
        }
    }
    // Both framing headers present is the request-smuggling signature (RFC 9112 6.1).
    if (seen_content_length && seen_transfer_encoding) return ParseStatus::bad_request;

    if (out.version_minor == 1) out.keep_alive = !has_token(out.connection, "close");
    else out.keep_alive = has_token(out.connection, "keep-alive");
    out.length = pos;
    return ParseStatus::complete;
}

}  // namespace agensio
