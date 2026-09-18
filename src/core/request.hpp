// A parsed request head, protocol-independent. Views point into storage owned by the
// stream (HTTP/1: the connection's receive buffer). The body, if any, is a pull source
// the connection provides (Content-Length or chunked decoded, size limit and body
// timeout applied); a handler that does not read it gets it drained after the response.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "core/headers.hpp"

namespace agensio {

class StreamBody;

enum class Method : std::uint8_t { get, head, post, put, del, patch, options, trace, connect, other };

// A set of methods as bits (Allow header, per-location policy).
using MethodSet = std::uint16_t;
constexpr MethodSet method_bit(Method m) noexcept { return static_cast<MethodSet>(1u << static_cast<unsigned>(m)); }
constexpr MethodSet kStaticMethods = method_bit(Method::get) | method_bit(Method::head) | method_bit(Method::options);

// "GET" -> Method::get; unknown tokens give false (the request keeps Method::other).
bool parse_method(std::string_view name, Method& out) noexcept;
// "GET, HEAD, OPTIONS" for a set, in the RFC's customary order.
std::string allow_header(MethodSet set);

struct Request {
    Method method = Method::other;
    std::string_view method_name;
    std::string_view target;  // as sent, e.g. "/a/b?x=1"
    int version_minor = 1;    // HTTP/1.0 -> 0, HTTP/1.1 -> 1 (HTTP/2, /3 report 1 for handler purposes)
    Headers headers;          // every field, in order

    // Fields the request core looks at on every request, extracted once by the parser.
    std::string_view host;
    std::string_view connection;
    std::string_view if_none_match;
    std::string_view if_modified_since;
    std::string_view range;     // "bytes=..." as sent (static files: one range, RFC 9110 section 14)
    std::string_view if_range;  // the validator the range is conditional on

    bool has_body = false;             // Content-Length > 0 or Transfer-Encoding: chunked
    bool chunked = false;              // Transfer-Encoding: chunked (HTTP/1.1 only)
    bool expect_continue = false;      // Expect: 100-continue (HTTP/1.1 only)
    std::uint64_t content_length = 0;  // declared length when !chunked
    StreamBody* body = nullptr;        // the body as a pull source when has_body; owned by the connection
    bool keep_alive = true;
    std::size_t length = 0;  // HTTP/1: bytes of the head consumed from the buffer

    void reset() noexcept {  // cheaper than *this = Request{}: leaves the field array alone
        method = Method::other;
        method_name = target = host = connection = if_none_match = if_modified_since = range = if_range = {};
        version_minor = 1;
        headers.clear();
        has_body = chunked = expect_continue = false;
        content_length = 0;
        body = nullptr;
        keep_alive = true;
        length = 0;
    }
};

}  // namespace agensio
