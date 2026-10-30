// libFuzzer target for the request fields agensio reads itself, the input given whole to each as
// a field value: Range and If-Range (http1/range.hpp), Accept-Encoding with its q-values
// (handlers/encoding.hpp), X-Forwarded-For and X-Forwarded-Proto from a trusted proxy
// (core/forwarded.hpp), and a CIDR (net/cidr.hpp) as [addresses] and trusted_proxies take one.
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "core/forwarded.hpp"
#include "handlers/encoding.hpp"
#include "http1/range.hpp"
#include "net/cidr.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace agensio;
    const std::string_view value(reinterpret_cast<const char*>(data), size);

    // Range: a single range lies within the body.
    for (const std::uint64_t body : {std::uint64_t{0}, std::uint64_t{1}, std::uint64_t{1024}, std::uint64_t{1} << 40}) {
        std::uint64_t first = 0, last = 0;
        if (parse_range(value, body, first, last) == RangeStatus::single) assert(first <= last && last < body);
    }
    (void)if_range_matches(value, "\"5f2a1c-400\"", "Thu, 01 Oct 2026 10:00:00 GMT");

    // Accept-Encoding: never an encoding the file has no twin for; q within 0..1000.
    for (int twins = 0; twins < 4; ++twins) {
        const bool br = twins & 1, gzip = twins & 2;
        const Encoding e = choose_encoding(value, br, gzip);
        assert(e == Encoding::identity || (e == Encoding::br && br) || (e == Encoding::gzip && gzip));
    }
    // The general chooser (docs/design-compression.md 4): never a coding not offered, whatever the
    // header and the order; nothing offered is identity.
    for (unsigned mask = 0; mask < 8; ++mask) {
        Codings c;
        c.mask = static_cast<std::uint8_t>(mask);
        c.order = {Encoding::zstd, Encoding::br, Encoding::gzip};
        if (size & 1) c.order = {Encoding::br, Encoding::zstd, Encoding::gzip};
        const Encoding e = choose_encoding(value, c);
        assert(e == Encoding::identity || c.has(e));
        if (mask == 0) assert(e == Encoding::identity);
    }
    const int q = encoding_detail::parse_q(value);
    assert(q >= 0 && q <= 1000);

    // X-Forwarded-For / -Proto from a trusted peer: a client address taken is an address, and the
    // one recorded parses back to the one compared.
    {
        std::vector<Cidr> trusted(3);
        std::string err;
        parse_cidr("127.0.0.0/8", trusted[0], err);
        parse_cidr("10.0.0.0/8", trusted[1], err);
        parse_cidr("::1/128", trusted[2], err);
        Request req;
        req.headers.add("X-Forwarded-For", value);
        req.headers.add("X-Forwarded-Proto", value);
        ConnectionInfo conn;
        conn.remote_address = "127.0.0.1";
        std::string storage;
        resolve_forwarded(req, trusted, conn, storage);
        if (!conn.client_address.empty()) {
            asio::error_code ec;
            const auto back = asio::ip::make_address(std::string(conn.client_address), ec);
            assert(!ec && unmapped(back) == conn.client_ip);
        }
    }

    // A CIDR contains the address it was written with.
    {
        Cidr c;
        std::string err;
        if (parse_cidr(value, c, err)) {
            asio::error_code ec;
            const auto a = asio::ip::make_address(std::string(value.substr(0, value.find('/'))), ec);
            if (!ec) assert(in_any({c}, unmapped(a)));
        }
    }
    return 0;
}
