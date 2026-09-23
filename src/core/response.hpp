// What a handler produces. The HTTP/1 writer turns it into bytes; HTTP/2 and HTTP/3
// writers will turn it into frames. Nothing here is protocol text except the optional
// prebuilt header block, which is the cache's zero-concatenation fast path for HTTP/1.
#pragma once

#include <string>
#include <string_view>

#include "cache.hpp"
#include "core/body.hpp"
#include "core/headers.hpp"
#include "file.hpp"

namespace agensio {

struct Response {
    int status = 200;

    // Optional serialized "Name: value\r\n..." block prepared ahead of time (cache entries,
    // error pages). If `prebuilt_terminated` it already ends with the blank line, so the
    // writer can send it untouched when there are no extra fields.
    std::string_view prebuilt_headers;
    bool prebuilt_terminated = false;
    // The same fields as an HPACK block (cache entries, error pages: built once, copied
    // per response by the HTTP/2 writer). Empty: the HTTP/2 writer encodes the text block.
    std::string_view prebuilt_h2;

    // Per-request fields (Connection, Location, Allow, ETag on a 304, ...). Values must
    // outlive the response: static text, or views into `entry`.
    Headers headers;

    Body body;
    bool keep_alive = true;
    bool head = false;  // HEAD request: headers only, body length still declared
    const char* upstream = nullptr;  // upstream outcome for the access log ("ok", "read_timeout", ...), static text
    // A 101 from a proxied origin: after this head the connection tunnels bytes between the
    // client and the origin (the handler's exchange holds the origin connection).
    bool upgrade = false;
    std::uint32_t tunnel_timeout_s = 0;  // idle limit for the tunnel, 0 = none

    // Resources the views above may point into.
    EntryPtr entry;
    File owned_file;
    std::string scratch;  // owned text built per response (capacity retained); views may point here
    std::string buffer;   // owned body bytes (buffered upstream responses)

    void reset() {
        status = 200;
        prebuilt_headers = {};
        prebuilt_terminated = false;
        prebuilt_h2 = {};
        headers.clear();
        body = NoBody{};
        keep_alive = true;
        head = false;
        upstream = nullptr;
        upgrade = false;
        tunnel_timeout_s = 0;
        entry.reset();
        owned_file.close();
        scratch.clear();
        buffer.clear();
    }
};

}  // namespace agensio
