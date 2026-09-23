// Behind a trusted proxy (server.trusted_proxies): the client is the rightmost
// X-Forwarded-For entry that is not itself a trusted proxy, and X-Forwarded-Proto says
// whether it used TLS. Shared by the HTTP/1 and HTTP/2 connections; called only when the
// list is configured and the peer is on it.
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

// `storage` keeps the chosen address alive for the request (conn.client_address views it).
inline void resolve_forwarded(const Request& req, const std::vector<Cidr>& trusted, ConnectionInfo& conn,
                              std::string& storage) {
    std::string_view xff = req.headers.get("x-forwarded-for");
    while (!xff.empty()) {
        const std::size_t comma = xff.rfind(',');
        std::string_view entry = comma == std::string_view::npos ? xff : xff.substr(comma + 1);
        xff = comma == std::string_view::npos ? std::string_view() : xff.substr(0, comma);
        while (!entry.empty() && (entry.front() == ' ' || entry.front() == '\t')) entry.remove_prefix(1);
        while (!entry.empty() && (entry.back() == ' ' || entry.back() == '\t')) entry.remove_suffix(1);
        if (entry.empty()) continue;
        asio::error_code ec;
        const auto a = asio::ip::make_address(std::string(entry), ec);
        if (ec) break;  // garbage: trust nothing further left
        storage = entry;
        conn.client_address = storage;
        if (!in_any(trusted, a)) break;  // first hop that is not one of ours
    }
    const std::string_view proto = req.headers.get("x-forwarded-proto");
    conn.forwarded_https = Headers::iequals(proto, "https");
}

}  // namespace agensio
