#include "services/fetch.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <asio.hpp>
#ifdef AGENSIO_HAS_TLS
#include <asio/ssl.hpp>
#endif

#include "http1/chunked.hpp"

namespace agensio::fetch {

bool is_private_address(const asio::ip::address& a) noexcept {
    if (a.is_v4()) {
        const auto b = a.to_v4().to_bytes();
        if (a.is_loopback() || a.is_unspecified() || a.is_multicast()) return true;
        if (b[0] == 10) return true;                                  // 10/8
        if (b[0] == 172 && (b[1] & 0xf0) == 16) return true;          // 172.16/12
        if (b[0] == 192 && b[1] == 168) return true;                  // 192.168/16
        if (b[0] == 169 && b[1] == 254) return true;                  // link-local, cloud metadata
        if (b[0] == 100 && (b[1] & 0xc0) == 64) return true;          // 100.64/10 shared
        if (b[0] == 0) return true;                                   // "this" network
        if (b[0] >= 240) return true;                                 // reserved, broadcast
        return false;
    }
    const auto v6 = a.to_v6();
    if (v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || v6.is_link_local() || v6.is_site_local()) return true;
    const auto b = v6.to_bytes();
    if ((b[0] & 0xfe) == 0xfc) return true;  // fc00::/7 unique local
    if (v6.is_v4_mapped() || (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
                              b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0)) {  // ::ffff:a.b.c.d or ::a.b.c.d
        const asio::ip::address_v4 mapped(std::array<unsigned char, 4>{b[12], b[13], b[14], b[15]});
        return is_private_address(asio::ip::address(mapped));
    }
    if (b[0] == 0x20 && b[1] == 0x02) {  // 6to4: the embedded IPv4 decides
        const asio::ip::address_v4 inner(std::array<unsigned char, 4>{b[2], b[3], b[4], b[5]});
        return is_private_address(asio::ip::address(inner));
    }
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0) return true;  // Teredo: hides the real peer
    return false;
}

bool split_url(const std::string& url, std::string& host, std::string& port, std::string& path) {
    if (!url.starts_with("https://")) return false;
    const std::string rest = url.substr(8);
    const std::size_t slash = rest.find_first_of("/?#");
    std::string authority = rest.substr(0, slash);
    path = slash == std::string::npos ? "/" : (rest[slash] == '/' ? rest.substr(slash) : "/" + rest.substr(slash));
    const std::size_t hash = path.find('#');
    if (hash != std::string::npos) path.erase(hash);
    if (authority.find('@') != std::string::npos) return false;  // no credentials in a download URL
    port = "443";
    if (!authority.empty() && authority.front() == '[') {
        const std::size_t close = authority.find(']');
        if (close == std::string::npos) return false;
        host = authority.substr(1, close - 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return false;
            port = authority.substr(close + 2);
        }
    } else {
        const std::size_t colon = authority.rfind(':');
        if (colon != std::string::npos) {
            host = authority.substr(0, colon);
            port = authority.substr(colon + 1);
        } else {
            host = authority;
        }
    }
    if (host.empty() || port.empty()) return false;
    for (char c : host)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == ':')) return false;
    for (char c : port)
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    for (unsigned char c : path)
        if (c <= 0x20 || c == 0x7f) return false;
    return true;
}

#ifdef AGENSIO_HAS_TLS

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Resolves `host`, applies the fence to every address, connects to the first that answers.
bool connect_checked(asio::io_context& io, asio::basic_socket<asio::ip::tcp>& socket, const std::string& host, const std::string& port,
                     const Options& options, std::string& error) {
    asio::error_code ec;
    asio::ip::tcp::resolver resolver(io);
    const auto results = resolver.resolve(host, port, ec);
    if (ec) {
        error = "cannot resolve " + host + ": " + ec.message();
        return false;
    }
    std::vector<asio::ip::tcp::endpoint> allowed;
    std::string refused;
    for (const auto& r : results) {
        if (!options.allow_private && is_private_address(r.endpoint().address())) {
            refused += (refused.empty() ? "" : ", ") + r.endpoint().address().to_string();
            continue;
        }
        allowed.push_back(r.endpoint());
    }
    if (allowed.empty()) {
        error = host + " resolves to " + (refused.empty() ? "nothing" : refused + ", a private or local address") +
                "; refused (an internal mirror needs [control] install_private = true)";
        return false;
    }
    asio::connect(socket, allowed, ec);
    if (ec) {
        error = "cannot connect to " + host + ": " + ec.message();
        return false;
    }
    return true;
}

struct Head {
    int status = 0;
    std::uint64_t content_length = 0;
    bool has_length = false;
    bool chunked = false;
    std::string location, content_type;
};

bool parse_head(std::string_view text, Head& h) {
    const std::size_t eol = text.find("\r\n");
    if (eol == std::string_view::npos || eol < 12 || !text.starts_with("HTTP/1.")) return false;
    h.status = std::atoi(std::string(text.substr(9, 3)).c_str());
    std::size_t pos = eol + 2;
    while (pos < text.size()) {
        const std::size_t next = text.find("\r\n", pos);
        const std::string_view line = text.substr(pos, next == std::string_view::npos ? std::string_view::npos : next - pos);
        pos = next == std::string_view::npos ? text.size() : next + 2;
        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos) continue;
        const std::string name = lower(std::string(line.substr(0, colon)));
        std::string_view value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
        if (name == "content-length") {
            h.has_length = true;
            h.content_length = std::strtoull(std::string(value).c_str(), nullptr, 10);
        } else if (name == "transfer-encoding") {
            h.chunked = lower(std::string(value)).find("chunked") != std::string::npos;
        } else if (name == "location") {
            h.location = value;
        } else if (name == "content-type") {
            h.content_type = value;
        }
    }
    return h.status >= 100 && h.status <= 599;
}

// One hop: false with error; true with `redirect` set when the answer was a redirect.
bool hop(const std::string& url, const Options& options, const Chunk& chunk, Result& result, std::string& redirect,
         std::chrono::steady_clock::time_point deadline, std::string& error) {
    std::string host, port, path;
    if (!split_url(url, host, port, path)) {
        error = "only https:// URLs are accepted: " + url;
        return false;
    }
    try {
        asio::io_context io;
        asio::ssl::context tls(asio::ssl::context::tls_client);
        tls.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 | asio::ssl::context::no_sslv3 |
                        asio::ssl::context::no_tlsv1 | asio::ssl::context::no_tlsv1_1);
        if (!options.ca_file.empty()) tls.load_verify_file(options.ca_file);
        else tls.set_default_verify_paths();
        tls.set_verify_mode(asio::ssl::verify_peer);
        asio::ssl::stream<asio::ip::tcp::socket> stream(io, tls);
        if (!connect_checked(io, stream.lowest_layer(), host, port, options, error)) return false;
        const timeval timeout{options.timeout_s, 0};
        ::setsockopt(stream.lowest_layer().native_handle(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        ::setsockopt(stream.lowest_layer().native_handle(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
        SSL_set_tlsext_host_name(stream.native_handle(), host.c_str());
        SSL_set1_host(stream.native_handle(), host.c_str());
        asio::error_code ec;
        stream.handshake(asio::ssl::stream_base::client, ec);
        if (ec) {
            error = "TLS to " + host + ": " + ec.message();
            return false;
        }
        const std::string req = "GET " + path + " HTTP/1.1\r\nHost: " + host + (port == "443" ? "" : ":" + port) +
                                "\r\nUser-Agent: agensio/" AGENSIO_VERSION "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        asio::write(stream, asio::buffer(req), ec);
        if (ec) {
            error = "sending the request to " + host + ": " + ec.message();
            return false;
        }
        std::string raw;
        char buf[64 * 1024];
        std::size_t head_end = std::string::npos;
        while (head_end == std::string::npos) {
            if (std::chrono::steady_clock::now() > deadline) {
                error = "download deadline passed";
                return false;
            }
            const std::size_t n = stream.read_some(asio::buffer(buf), ec);
            if (n) raw.append(buf, n);
            head_end = raw.find("\r\n\r\n");
            if (ec && head_end == std::string::npos) {
                error = "no HTTP response head from " + host + " (" + ec.message() + ")";
                return false;
            }
            if (raw.size() > 64 * 1024 && head_end == std::string::npos) {
                error = host + " sent a response head over 64 KB";
                return false;
            }
        }
        Head h;
        if (!parse_head(std::string_view(raw).substr(0, head_end), h)) {
            error = host + " sent a malformed response head";
            return false;
        }
        result.status = h.status;
        result.content_type = h.content_type;
        if (h.status == 301 || h.status == 302 || h.status == 303 || h.status == 307 || h.status == 308) {
            if (h.location.empty()) {
                error = host + " answered " + std::to_string(h.status) + " without a Location";
                return false;
            }
            if (h.location.starts_with("https://")) redirect = h.location;
            else if (h.location.starts_with("//")) redirect = "https:" + h.location;
            else if (h.location.starts_with("/")) redirect = "https://" + host + (port == "443" ? "" : ":" + port) + h.location;
            else if (h.location.starts_with("http://")) {
                error = host + " redirects to plain http (" + h.location + "); refused";
                return false;
            } else {
                redirect = "https://" + host + (port == "443" ? "" : ":" + port) + path.substr(0, path.rfind('/') + 1) + h.location;
            }
            return true;
        }
        if (h.status != 200) {
            error = host + " answered HTTP " + std::to_string(h.status) + " for " + path;
            return false;
        }
        if (h.has_length && h.content_length > options.max_bytes) {
            error = "the file is " + std::to_string(h.content_length) + " bytes, above the limit of " + std::to_string(options.max_bytes);
            return false;
        }
        // The body: what arrived with the head first, then the socket until the framing ends.
        ChunkedDecoder chunked;
        std::string_view pending = std::string_view(raw).substr(head_end + 4);
        std::uint64_t total = 0;
        bool complete = false;
        char out[64 * 1024];
        auto feed = [&](std::string_view in) -> bool {
            if (h.chunked) {
                while (!in.empty() && !complete) {
                    std::size_t used = 0, produced = 0;
                    const auto st = chunked.decode(in, used, out, sizeof out, produced);
                    if (st == ChunkedDecoder::Status::error) {
                        error = host + " sent malformed chunked framing";
                        return false;
                    }
                    in.remove_prefix(used);
                    if (produced) {
                        total += produced;
                        if (total > options.max_bytes) {
                            error = "the download exceeds the limit of " + std::to_string(options.max_bytes) + " bytes";
                            return false;
                        }
                        if (!chunk(out, produced, error)) return false;
                    }
                    if (st == ChunkedDecoder::Status::done) complete = true;
                }
                return true;
            }
            if (h.has_length) in = in.substr(0, static_cast<std::size_t>(std::min<std::uint64_t>(in.size(), h.content_length - total)));
            if (in.empty()) return true;
            total += in.size();
            if (total > options.max_bytes) {
                error = "the download exceeds the limit of " + std::to_string(options.max_bytes) + " bytes";
                return false;
            }
            if (!chunk(in.data(), in.size(), error)) return false;
            if (h.has_length && total == h.content_length) complete = true;
            return true;
        };
        if (!feed(pending)) return false;
        while (!complete) {
            if (std::chrono::steady_clock::now() > deadline) {
                error = "download deadline passed";
                return false;
            }
            const std::size_t n = stream.read_some(asio::buffer(buf), ec);
            if (n && !feed(std::string_view(buf, n))) return false;
            if (ec) {
                if (h.chunked || h.has_length) {
                    if (!complete) {
                        error = "the connection to " + host + " ended before the body did (" + ec.message() + ")";
                        return false;
                    }
                } else {
                    complete = true;  // close-delimited
                }
            }
        }
        result.bytes = total;
        result.final_url = url;
        return true;
    } catch (const std::exception& e) {
        error = std::string("GET ") + url + ": " + e.what();
        return false;
    }
}

}  // namespace

bool https_get(const std::string& url, const Options& options, const Chunk& chunk, Result& result, std::string& error) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(options.deadline_s);
    std::string current = url;
    for (int i = 0; i <= options.max_redirects; ++i) {
        std::string redirect;
        if (!hop(current, options, chunk, result, redirect, deadline, error)) return false;
        if (redirect.empty()) return true;
        current = redirect;
    }
    error = "more than " + std::to_string(options.max_redirects) + " redirects";
    return false;
}

#else

bool https_get(const std::string&, const Options&, const Chunk&, Result&, std::string& error) {
    error = "this build has no TLS: downloads are not available; upload the archive instead";
    return false;
}

#endif

}  // namespace agensio::fetch
