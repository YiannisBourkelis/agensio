// A blocking HTTPS downloader for site-install (F9), run in the install child process as
// the site user, never on a worker. One rule set for every hop: https only, the host's
// addresses resolved and each one checked against the private-address fence before a
// connection is made (so a redirect to 127.0.0.1, 10.0.0.1, 169.254.169.254 or ::1 is
// refused as well), certificate and host name verified, a body cap, a redirect cap and
// a deadline. `is_private_address` is pure and unit tested.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include <asio/ip/address.hpp>

namespace agensio::fetch {

struct Options {
    std::uint64_t max_bytes = 1ull << 30;  // body cap
    bool allow_private = false;            // [control] install_private
    int max_redirects = 5;
    int timeout_s = 60;                    // per read/write
    int deadline_s = 900;                  // the whole download
    std::string ca_file;                   // "" = the system store
};

struct Result {
    std::uint64_t bytes = 0;
    std::string final_url;  // after redirects
    std::string content_type;
    int status = 0;
};

// Called with each body chunk; false with `error` aborts.
using Chunk = std::function<bool(const char*, std::size_t, std::string& error)>;

// GET `url`, streaming the body to `chunk`. False with `error` on any refusal or fault.
bool https_get(const std::string& url, const Options& options, const Chunk& chunk, Result& result, std::string& error);

// Loopback, link-local, private (RFC 1918, ULA), shared (100.64/10), multicast,
// unspecified and the IPv4-mapped forms of those: nothing a public download should
// resolve to.
bool is_private_address(const asio::ip::address& a) noexcept;

// https://host[:port]/path; false for anything else.
bool split_url(const std::string& url, std::string& host, std::string& port, std::string& path);

}  // namespace agensio::fetch
