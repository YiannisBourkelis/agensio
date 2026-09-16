// A parsed request head, protocol-independent. Views point into storage owned by the
// stream (HTTP/1: the connection's receive buffer). Request bodies arrive in phase A3.
#pragma once

#include <cstddef>
#include <string_view>

#include "core/headers.hpp"

namespace agensio {

enum class Method { GET, HEAD, OTHER };

struct Request {
    Method method = Method::OTHER;
    std::string_view method_name;
    std::string_view target;  // as sent, e.g. "/a/b?x=1"
    int version_minor = 1;    // HTTP/1.0 -> 0, HTTP/1.1 -> 1 (HTTP/2, /3 report 1 for handler purposes)
    Headers headers;          // every field, in order

    // Fields the request core looks at on every request, extracted once by the parser.
    std::string_view host;
    std::string_view connection;
    std::string_view if_none_match;
    std::string_view if_modified_since;

    bool has_body = false;   // Content-Length > 0 or Transfer-Encoding present
    bool keep_alive = true;
    std::size_t length = 0;  // HTTP/1: bytes of the head consumed from the buffer

    void reset() noexcept {  // cheaper than *this = Request{}: leaves the field array alone
        method = Method::OTHER;
        method_name = target = host = connection = if_none_match = if_modified_since = {};
        version_minor = 1;
        headers.clear();
        has_body = false;
        keep_alive = true;
        length = 0;
    }
};

}  // namespace agensio
