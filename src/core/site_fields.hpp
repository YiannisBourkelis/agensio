// The fields a site sets on its answers (docs/headers.md 1), resolved when the configuration
// loads. The first of them is HSTS (docs/redirects.md 4), on the answers a site gives over TLS;
// the response-header rules and the security baseline will add theirs here.
#pragma once

#include <string>

namespace agensio {

// Pointed at by the request once its site is known (Dispatcher::route), never copied per
// request: the HTTP/1 writer appends `h1` to the head, the HTTP/2 and HTTP/3 writers send each
// value through their connection's table (one index byte after the first answer).
struct SiteFields {
    std::string h1;    // the fields as HTTP/1 lines, "Strict-Transport-Security: max-age=31536000\r\n"
    std::string hsts;  // the Strict-Transport-Security value; "" when the site sends none
    bool empty() const noexcept { return h1.empty(); }
};

}  // namespace agensio
