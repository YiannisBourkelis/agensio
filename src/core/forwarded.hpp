// Behind a trusted proxy (server.trusted_proxies): the client is the rightmost
// X-Forwarded-For entry that is not itself a trusted proxy, and X-Forwarded-Proto says
// whether it used TLS. Shared by the HTTP/1, HTTP/2 and HTTP/3 connections; called only when
// the list is configured and the peer is on it.
//
// Several X-Forwarded-For lines are one list in order (RFC 9110 5.3), so the walk starts at
// the end of the last line: a proxy that adds a line of its own (HAProxy's option forwardfor)
// puts the hop it saw there, and a client's own line before it is reached only through hops
// the server trusts. Until 2026-10-07 only the first line was read, which let a client
// behind such a proxy choose the address agensio logs and hands to PHP. The nearest proxy's
// X-Forwarded-Proto counts the same way: the last value of the last line.
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <asio.hpp>

#include "core/headers.hpp"
#include "core/request.hpp"
#include "core/stream.hpp"
#include "net/cidr.hpp"

namespace agensio {

// The port an X-Forwarded-For entry may carry: digits for 1 to 65535 (alpha.53 report:
// "198.51.100.7:99999" was taken as 198.51.100.7; a bad port is garbage and stops the walk).
inline bool valid_port(std::string_view s) noexcept {
    if (s.empty() || s.size() > 5) return false;
    unsigned v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<unsigned>(c - '0');
    }
    return v >= 1 && v <= 65535;
}

// `storage` keeps the chosen address alive for the request (conn.client_address views it).
inline void resolve_forwarded(const Request& req, const std::vector<Cidr>& trusted, ConnectionInfo& conn,
                              std::string& storage) {
    const Headers& h = req.headers;
    bool done = false;
    for (std::size_t i = h.size(); i-- > 0 && !done;) {
        if (!Headers::iequals(h[i].name, "x-forwarded-for")) continue;
        std::string_view xff = h[i].value;
        while (!xff.empty()) {
            const std::size_t comma = xff.rfind(',');
            std::string_view entry = comma == std::string_view::npos ? xff : xff.substr(comma + 1);
            xff = comma == std::string_view::npos ? std::string_view() : xff.substr(0, comma);
            while (!entry.empty() && (entry.front() == ' ' || entry.front() == '\t')) entry.remove_prefix(1);
            while (!entry.empty() && (entry.back() == ' ' || entry.back() == '\t')) entry.remove_suffix(1);
            if (entry.empty()) continue;
            // With a port, as some load balancers write it: "198.51.100.7:1234" and
            // "[2001:db8::1]:443" (or bracketed without a port) are the address alone; a bare IPv6
            // address has several colons and is taken as it is (alpha.52 report).
            if (entry.front() == '[') {
                const std::size_t close = entry.find(']');
                const std::string_view port = close == std::string_view::npos ? std::string_view() : entry.substr(close + 1);
                if (close == std::string_view::npos || !(port.empty() || (port.size() > 1 && port[0] == ':' && valid_port(port.substr(1))))) {
                    done = true;
                    break;
                }
                entry = entry.substr(1, close - 1);
            } else if (const std::size_t colon = entry.find(':'); colon != std::string_view::npos && entry.find(':', colon + 1) == std::string_view::npos) {
                if (!valid_port(entry.substr(colon + 1))) {
                    done = true;
                    break;
                }
                entry = entry.substr(0, colon);
            }
            asio::error_code ec;
            const auto given = asio::ip::make_address(std::string(entry), ec);
            if (ec || entry.find('%') != std::string_view::npos) {  // garbage or a zone id: trust nothing further left
                done = true;
                break;
            }
            const asio::ip::address a = unmapped(given);
            if (a == given) storage = entry;
            else storage = a.to_string();  // ::ffff:a.b.c.d is recorded as a.b.c.d
            conn.client_address = storage;
            conn.client_ip = a;
            if (!in_any(trusted, a)) {  // first hop that is not one of ours
                done = true;
                break;
            }
        }
    }
    conn.forwarded_https = false;
    for (std::size_t i = h.size(); i-- > 0;) {
        if (!Headers::iequals(h[i].name, "x-forwarded-proto")) continue;
        std::string_view proto = h[i].value;
        if (const std::size_t comma = proto.rfind(','); comma != std::string_view::npos) proto = proto.substr(comma + 1);
        while (!proto.empty() && (proto.front() == ' ' || proto.front() == '\t')) proto.remove_prefix(1);
        while (!proto.empty() && (proto.back() == ' ' || proto.back() == '\t')) proto.remove_suffix(1);
        conn.forwarded_https = Headers::iequals(proto, "https");
        break;
    }
}

}  // namespace agensio
