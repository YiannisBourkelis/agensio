// Minimal self-contained unit tests (no framework dependency).
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <map>
#include <set>
#include <sstream>
#include <thread>
#include <string_view>
#include <unistd.h>

#include "cache.hpp"
#include "http1/chunked.hpp"
#include "config.hpp"
#include "services/pools.hpp"
#include "upstream/http_head.hpp"
#include "http1/range.hpp"
#include "services/acme.hpp"
#include "control/roles.hpp"
#include "control/commands.hpp"
#include "control/protection.hpp"
#include "core/strings.hpp"
#include "control/reference.hpp"
#include "control/mcp.hpp"
#include "control/settings.hpp"
#include "control/sites.hpp"
#include "services/provision.hpp"
#include "services/archive.hpp"
#include "services/fetch.hpp"
#include "services/install.hpp"
#include "services/json.hpp"
#include "services/tasks.hpp"
#include "http/request_assembly.hpp"
#include "services/appenv.hpp"
#include <chrono>
#include <csignal>
#ifdef AGENSIO_HAS_ZLIB
#include <zlib.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#include "handlers/proxy.hpp"
#include "core/headers.hpp"
#include "core/result.hpp"
#include "core/host.hpp"
#include "core/cpus.hpp"
#include "core/router.hpp"
#include "handlers/fastcgi.hpp"
#include "handlers/httparena.hpp"
#include "handlers/static.hpp"
#include "core/fields.hpp"
#include "http2/frame.hpp"
#include "http2/hpack.hpp"
#include "http3/qpack.hpp"
#ifdef AGENSIO_HAS_QUIC
#include "quic/connection.hpp"
#include "quic_vectors.hpp"
#endif
#include "http2/settings.hpp"
#include "hpack_vectors.hpp"
#include "http1/parser.hpp"
#include "http_date.hpp"
#include "mime.hpp"
#include "net/cidr.hpp"
#include "path.hpp"
#include "services/log.hpp"
#include "upstream/fcgi.hpp"
#include "upstream/options.hpp"

using namespace agensio;

static int failures = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                 \
        }                                                               \
    } while (0)
#define CHECK_EQ(a, b)                                                         \
    do {                                                                       \
        auto _a = (a);                                                         \
        auto _b = (b);                                                         \
        if (!(_a == _b)) {                                                     \
            std::printf("FAIL %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b); \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

static std::string norm(std::string_view t) {
    std::string out;
    return normalize_target(t, out) ? out : std::string("<invalid>");
}

static void test_path() {
    CHECK_EQ(norm("/"), "/");
    // An encoded separator is reported (2026-10-02 alpha.45 report): %2F and %5C in either
    // case, never a plain slash or another escape; the path itself still decodes.
    {
        std::string out;
        bool enc = true;
        CHECK(normalize_target("/a/b%20c", out, &enc) && !enc && out == "/a/b c");
        enc = false;
        CHECK(normalize_target("/x%2F..%2Fwp-login.php", out, &enc) && enc && out == "/wp-login.php");
        enc = false;
        CHECK(normalize_target("/a%2fb", out, &enc) && enc && out == "/a/b");
        enc = false;
        CHECK(normalize_target("/a%5Cb", out, &enc) && enc);
        enc = false;
        CHECK(normalize_target("/a%2Eb/%2e%2e/c", out, &enc) && !enc && out == "/c");
        CHECK(normalize_target("/plain/%2F", out) && out == "/plain/");  // without the flag: as before
    }
    CHECK_EQ(norm("/index.html"), "/index.html");
    CHECK_EQ(norm("/a/b/c"), "/a/b/c");
    CHECK_EQ(norm("/a/b/"), "/a/b/");
    CHECK_EQ(norm("/a//b"), "/a/b");
    CHECK_EQ(norm("/a/./b"), "/a/b");
    CHECK_EQ(norm("/a/b/../c"), "/a/c");
    CHECK_EQ(norm("/a/b/.."), "/a/");
    CHECK_EQ(norm("/a/.."), "/");
    CHECK_EQ(norm("/a/."), "/a/");
    CHECK_EQ(norm("/a%20b/c%2Fd"), "/a b/c/d");
    CHECK_EQ(norm("index.html"), "<invalid>");
    CHECK_EQ(norm("/a?b=c/../d"), "/a");
    CHECK_EQ(norm("/a/b?x"), "/a/b");
    CHECK_EQ(norm("/%CE%B1%CE%B2"), "/\xCE\xB1\xCE\xB2");  // UTF-8 stays as bytes
    CHECK_EQ(norm("/a/../b/../c/"), "/c/");
    CHECK_EQ(norm("/..a/b"), "/..a/b");
    CHECK_EQ(norm("/.hidden"), "/.hidden");
}

// ---- security: path traversal, hidden files, Windows filesystem rules ----
static void test_security_path() {
    CHECK_EQ(norm("/%2e%2e/etc/passwd"), "<invalid>");
    CHECK_EQ(norm("/../etc/passwd"), "<invalid>");
    CHECK_EQ(norm("/a/../../x"), "<invalid>");
    CHECK_EQ(norm("/..%2f..%2fetc/passwd"), "<invalid>");
    CHECK_EQ(norm("/%2e%2e%2f%2e%2e%2fetc/passwd"), "<invalid>");
    CHECK_EQ(norm("/a%00b"), "<invalid>");
    CHECK_EQ(norm("/a%zz"), "<invalid>");
    CHECK_EQ(norm("/a%2"), "<invalid>");
    CHECK_EQ(norm("/%c0%ae%c0%ae/x"), "/\xC0\xAE\xC0\xAE/x");  // overlong UTF-8 is not a dot

    CHECK(has_hidden_segment("/.env"));
    CHECK(has_hidden_segment("/.git/config"));
    CHECK(has_hidden_segment("/a/.hidden/b"));
    CHECK(!has_hidden_segment("/a.b/c.d"));
    CHECK(!has_hidden_segment("/"));
    CHECK(!has_hidden_segment("/a/b."));

    CHECK(windows_path_ok("/a/b.txt"));
    CHECK(!windows_path_ok("/a\\b"));
    CHECK(!windows_path_ok("/a:b"));
    CHECK(!windows_path_ok("/file.txt::$DATA"));
    CHECK(!windows_path_ok("/a/.. /b"));
    CHECK(!windows_path_ok("/a/b."));
    CHECK(!windows_path_ok("/CON"));
    CHECK(!windows_path_ok("/a/nul.txt"));
    CHECK(!windows_path_ok("/com1"));
    CHECK(!windows_path_ok("/LPT9.log"));
    CHECK(windows_path_ok("/com10"));
    CHECK(windows_path_ok("/console"));
}

static void test_parser() {
    Request r;
    std::string_view req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
    CHECK(parse_request(req, r) == ParseStatus::complete);
    CHECK(r.method == Method::get);
    CHECK_EQ(r.target, "/index.html");
    CHECK_EQ(r.host, "example.com");
    CHECK_EQ(r.version_minor, 1);
    CHECK(r.keep_alive);
    CHECK_EQ(r.length, req.size());

    CHECK(parse_request("GET / HTTP/1.1\r\nHost: a\r\n", r) == ParseStatus::incomplete);
    CHECK(parse_request("GET / HT", r) == ParseStatus::incomplete);
    CHECK(parse_request("", r) == ParseStatus::incomplete);

    CHECK(parse_request("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", r) == ParseStatus::complete);
    CHECK(!r.keep_alive);
    CHECK(parse_request("GET / HTTP/1.0\r\nHost: a\r\n\r\n", r) == ParseStatus::complete);
    CHECK(!r.keep_alive);
    CHECK_EQ(r.version_minor, 0);
    CHECK(parse_request("GET / HTTP/1.0\r\nHost: a\r\nConnection: Keep-Alive\r\n\r\n", r) == ParseStatus::complete);
    CHECK(r.keep_alive);

    CHECK(parse_request("HEAD / HTTP/1.1\r\nhost: a\r\n\r\n", r) == ParseStatus::complete);
    CHECK(r.method == Method::head);
    CHECK_EQ(r.host, "a");
    CHECK(parse_request("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello", r) == ParseStatus::complete);
    CHECK(r.method == Method::post);
    CHECK(r.has_body);
    CHECK(parse_request("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n", r) == ParseStatus::complete);
    CHECK(!r.has_body);

    // Bare LF line endings are tolerated.
    CHECK(parse_request("GET / HTTP/1.1\nHost: a\n\n", r) == ParseStatus::complete);
    CHECK_EQ(r.host, "a");
    // Leading CRLF tolerated.
    CHECK(parse_request("\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n", r) == ParseStatus::complete);

    // Pipelining: length only covers the first request.
    std::string_view two = "GET /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: a\r\n\r\n";
    CHECK(parse_request(two, r) == ParseStatus::complete);
    CHECK_EQ(r.target, "/a");
    CHECK(parse_request(two.substr(r.length), r) == ParseStatus::complete);
    CHECK_EQ(r.target, "/b");
    CHECK_EQ(r.length, two.size() / 2);

    // Conditional headers.
    CHECK(parse_request("GET / HTTP/1.1\r\nHost: a\r\nIf-None-Match: \"abc\"\r\nIf-Modified-Since: x\r\n\r\n", r) ==
          ParseStatus::complete);
    CHECK_EQ(r.if_none_match, "\"abc\"");
    CHECK_EQ(r.if_modified_since, "x");

    // Malformed.
    CHECK(parse_request("GET /\r\n\r\n", r) == ParseStatus::bad_request);
    CHECK(parse_request("GET / HTTP/2.0\r\n\r\n", r) == ParseStatus::version_not_supported);
    CHECK(parse_request("GET / HTTP/1.1\r\nBadHeader\r\n\r\n", r) == ParseStatus::bad_request);
    CHECK(parse_request("GET / HTTP/1.1\r\nHost : a\r\n\r\n", r) == ParseStatus::bad_request);
    CHECK(parse_request("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: x\r\n\r\n", r) == ParseStatus::bad_request);
    CHECK(parse_request("G\x01T / HTTP/1.1\r\n\r\n", r) == ParseStatus::bad_request);

    CHECK(has_token("keep-alive, Upgrade", "upgrade"));
    CHECK(!has_token("keep-alive", "close"));
    CHECK(iequals("Host", "hOST"));
}

// ---- security: request smuggling and field-syntax hardening (RFC 9112) ----
static void test_security_parser() {
    Request r;
    auto st = [&](std::string_view req) { return parse_request(req, r); };
    CHECK(st("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n") ==
          ParseStatus::bad_request);
    CHECK(st("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n") ==
          ParseStatus::bad_request);
    CHECK(st("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n") == ParseStatus::complete);
    CHECK(st("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\n") == ParseStatus::bad_request);
    CHECK(st("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n") == ParseStatus::bad_request);
    CHECK(st("GET / HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n") == ParseStatus::bad_request);
    CHECK(st("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n") == ParseStatus::bad_request);
    CHECK(st("GET / HTTP/1.1\r\nHost: a b\r\n\r\n") == ParseStatus::bad_request);
    CHECK(st("GET / HTTP/1.1\r\nHost: a/b\r\n\r\n") == ParseStatus::bad_request);
    CHECK(st("GET / HTTP/1.1\r\nHost: a\r\nX-Fold: 1\r\n continued\r\n\r\n") == ParseStatus::bad_request);
    CHECK(st("GET / HTTP/1.1\r\nHost: a\r\nX-Bare: a\rb\r\n\r\n") == ParseStatus::bad_request);
    CHECK(st("GET / HTTP/1.1\r\nHost: a\r\nX-Ctl: a\x01b\r\n\r\n") == ParseStatus::bad_request);
    CHECK(st("GET / HTTP/1.1\r\nHost: a\r\nX-Tab: a\tb\r\n\r\n") == ParseStatus::complete);
    CHECK(st("GET / HTTP/1.1\r\nHost: a\r\nBad Name: x\r\n\r\n") == ParseStatus::bad_request);
    CHECK(st("GET / HTTP/1.1\r\nHost: a\r\nX-(paren): x\r\n\r\n") == ParseStatus::bad_request);
    {
        std::string many = "GET / HTTP/1.1\r\nHost: a\r\n";
        for (int i = 0; i < 101; ++i)
            many += "X-H: v\r\n";
        many += "\r\n";
        CHECK(st(many) == ParseStatus::too_many_headers);
    }
}

static void test_date() {
    char buf[kHttpDateLength + 1] = {};
    format_http_date(784111777, buf);  // RFC 7231 example
    CHECK_EQ(std::string(buf), "Sun, 06 Nov 1994 08:49:37 GMT");
    format_http_date(0, buf);
    CHECK_EQ(std::string(buf), "Thu, 01 Jan 1970 00:00:00 GMT");
    DateCache dc;
    CHECK_EQ(dc.now().size(), kHttpDateLength);
}

static void test_mime() {
    CHECK_EQ(mime_for_path("/a/b.html"), "text/html; charset=utf-8");
    CHECK_EQ(mime_for_path("/a/B.JPG"), "image/jpeg");
    CHECK_EQ(mime_for_path("/a/style.css"), "text/css; charset=utf-8");
    CHECK_EQ(mime_for_path("/a/noext"), "application/octet-stream");
    CHECK_EQ(mime_for_path("/a.b/noext"), "application/octet-stream");
    CHECK_EQ(mime_for_path("/x.unknownext"), "application/octet-stream");
    CHECK_EQ(mime_for_path("/x."), "application/octet-stream");
}

static void test_size() {
    CHECK_EQ(parse_size("4096"), 4096u);
    CHECK_EQ(parse_size("4k"), 4096u);
    CHECK_EQ(parse_size("4KB"), 4096u);
    CHECK_EQ(parse_size("2 MB"), 2u * 1024 * 1024);
    CHECK_EQ(parse_size("1g"), 1024u * 1024 * 1024);
    bool threw = false;
    try {
        parse_size("abc");
    } catch (const std::exception&) { threw = true; }
    CHECK(threw);
}

// The response encoder's dynamic table (design 6.2.1) against our own decoder: every block
// an Encoder produces decodes to the fields it was given, across insertions, evictions,
// a SETTINGS change mid-connection, a zero limit and a value larger than the table.
static void test_hpack_encoder() {
    using namespace hpack;
    struct Field {
        std::string name, value;
    };
    auto decode = [](Decoder& d, const std::string& block) {
        std::vector<Field> got;
        std::string arena;
        const auto r = d.decode(block, arena, 16384, [&](std::string_view n, std::string_view v) {
            got.push_back({std::string(n), std::string(v)});
            return true;
        });
        CHECK(r == Decoder::Result::ok);
        return got;
    };
    auto same = [](const std::vector<Field>& got, std::vector<Field> want) {
        if (got.size() != want.size()) return false;
        for (std::size_t i = 0; i < got.size(); ++i)
            if (got[i].name != want[i].name || got[i].value != want[i].value) return false;
        return true;
    };
    std::string server_insert, date_insert;
    append_insert(server_insert, "server", "agensio");
    append_insert(date_insert, "date", "Wed, 24 Sep 2026 10:00:00 GMT");
    Encoder e;
    Decoder d(4096);
    // First block: the size update to our 1 KB, then everything inserted; a second block
    // is nearly all indexes and no update.
    std::string b1;
    e.begin(b1);
    append_status(b1, 200);
    e.server(b1, "agensio", server_insert);
    e.date(b1, 1000, "Wed, 24 Sep 2026 10:00:00 GMT", date_insert);
    e.field(b1, "content-type", "text/plain");
    e.field(b1, "content-length", "2");
    CHECK(static_cast<unsigned char>(b1[0]) == 0x3f && static_cast<unsigned char>(b1[1]) == 0xe1);  // 001 + 1024 (5-bit prefix: 31 then 993)
    CHECK(same(decode(d, b1), {{":status", "200"}, {"server", "agensio"}, {"date", "Wed, 24 Sep 2026 10:00:00 GMT"}, {"content-type", "text/plain"}, {"content-length", "2"}}));
    CHECK(d.table_limit() == 1024 && d.table_entries() == 3 && e.table_entries() == 3 && e.table_size() == d.table_size());
    std::string b2;
    e.begin(b2);
    append_status(b2, 200);
    e.server(b2, "agensio", server_insert);
    e.date(b2, 1000, "Wed, 24 Sep 2026 10:00:00 GMT", date_insert);
    e.field(b2, "content-type", "text/plain");
    e.field(b2, "content-length", "55");
    CHECK(b2.size() == 9 && same(decode(d, b2), {{":status", "200"}, {"server", "agensio"}, {"date", "Wed, 24 Sep 2026 10:00:00 GMT"}, {"content-type", "text/plain"}, {"content-length", "55"}}));
    // A new second inserts a new date; the old one stays until evicted. content-length,
    // etag and set-cookie never enter the table.
    std::string date2;
    append_insert(date2, "date", "Wed, 24 Sep 2026 10:00:01 GMT");
    std::string b3;
    e.begin(b3);
    e.date(b3, 1001, "Wed, 24 Sep 2026 10:00:01 GMT", date2);
    e.field(b3, "etag", "\"abc\"");
    e.field(b3, "set-cookie", "a=1");
    e.field(b3, "content-length", "3");
    e.field(b3, "vary", "Accept-Encoding");
    CHECK(same(decode(d, b3), {{"date", "Wed, 24 Sep 2026 10:00:01 GMT"}, {"etag", "\"abc\""}, {"set-cookie", "a=1"}, {"content-length", "3"}, {"vary", "Accept-Encoding"}}));
    CHECK(e.table_entries() == 5 && d.table_entries() == 5 && b3.find("\x1f\x28") != std::string::npos);  // set-cookie never indexed: 0001 + index 55
    // Fill the table with content types until server is evicted: it is re-inserted, the
    // decoder agrees at every step.
    for (int i = 0; i < 40; ++i) {
        std::string b;
        e.begin(b);
        e.server(b, "agensio", server_insert);
        e.field(b, "content-type", "application/x-" + std::to_string(i));
        CHECK(same(decode(d, b), {{"server", "agensio"}, {"content-type", "application/x-" + std::to_string(i)}}));
        CHECK(e.table_size() == d.table_size() && e.table_entries() == d.table_entries() && d.table_size() <= 1024);
    }
    // alt-svc (design-http3 7.4) is not in the static table: a literal with a new name
    // enters the dynamic table once, then it is one index byte per answer.
    {
        std::string b;
        e.begin(b);
        e.alt_svc(b, "h3=\":8443\"; ma=86400");
        CHECK(same(decode(d, b), {{"alt-svc", "h3=\":8443\"; ma=86400"}}) && static_cast<unsigned char>(b[0]) == 0x40);
        std::string c;
        e.begin(c);
        e.alt_svc(c, "h3=\":8443\"; ma=86400");
        CHECK(c.size() == 1 && same(decode(d, c), {{"alt-svc", "h3=\":8443\"; ma=86400"}}));
    }
    // A value larger than the table stays a literal and leaves the table alone.
    {
        const std::string big(2000, 'v');
        std::string b;
        e.begin(b);
        e.field(b, "x-big", big);
        e.field(b, "content-type", "text/css");
        const std::size_t before = e.table_entries();
        CHECK(same(decode(d, b), {{"x-big", big}, {"content-type", "text/css"}}) && e.table_entries() == before && d.table_entries() == before);
    }
    // The peer lowers its limit below ours: the next block starts with the update, both
    // tables evict alike; then to zero: literals only, both tables empty.
    e.set_peer_max(300);
    {
        std::string b;
        e.begin(b);
        e.server(b, "agensio", server_insert);
        e.field(b, "content-type", "text/css");
        e.field(b, "content-type", "text/html");
        CHECK(static_cast<unsigned char>(b[0]) == 0x3f);  // an update first
        CHECK(same(decode(d, b), {{"server", "agensio"}, {"content-type", "text/css"}, {"content-type", "text/html"}}));
        CHECK(d.table_limit() == 300 && e.table_limit() == 300 && e.table_size() == d.table_size() && d.table_size() <= 300);
    }
    e.set_peer_max(0);
    {
        std::string b;
        e.begin(b);
        e.server(b, "agensio", server_insert);
        e.date(b, 1002, "Wed, 24 Sep 2026 10:00:02 GMT", date2);
        e.field(b, "content-type", "text/css");
        CHECK(same(decode(d, b), {{"server", "agensio"}, {"date", "Wed, 24 Sep 2026 10:00:02 GMT"}, {"content-type", "text/css"}}));
        CHECK(d.table_entries() == 0 && e.table_entries() == 0 && d.table_limit() == 0);
        std::string c;
        e.begin(c);
        CHECK(c.empty());  // no pending update
    }
    // Raised again: back to our size, an update first, insertions resume.
    e.set_peer_max(4096);
    {
        std::string b;
        e.begin(b);
        e.server(b, "agensio", server_insert);
        CHECK(same(decode(d, b), {{"server", "agensio"}}) && d.table_limit() == 1024 && d.table_entries() == 1);
    }
    // The limit drops to 0 and rises again before a block goes out: the block walks the
    // decoder down to 0 and up to our size, so the entries we emptied are gone there too.
    e.set_peer_max(0);
    e.set_peer_max(4096);
    {
        std::string b;
        e.begin(b);
        e.field(b, "content-type", "text/plain");
        CHECK(static_cast<unsigned char>(b[0]) == 0x20 && static_cast<unsigned char>(b[1]) == 0x3f);  // update 0, then update 1024
        CHECK(same(decode(d, b), {{"content-type", "text/plain"}}) && d.table_entries() == 1 && e.table_entries() == 1 && d.table_limit() == 1024);
    }
    // A fresh connection whose peer announced 512 before the first block: the update says 512.
    Encoder e2;
    Decoder d2(4096);
    e2.set_peer_max(512);
    std::string b;
    e2.begin(b);
    e2.field(b, "content-type", "text/plain");
    CHECK(same(decode(d2, b), {{"content-type", "text/plain"}}) && d2.table_limit() == 512);
}

// Accept-Encoding against the twins an entry holds (RFC 9110 12.5.3): the arena's header,
// browsers', q-values, refusals and wildcards.
static void test_encoding() {
    using E = Encoding;
    struct Case {
        const char* accept;
        bool br, gz;
        E want;
    };
    const Case cases[] = {
        {"br;q=1, gzip;q=0.8", true, true, E::br},        {"gzip, deflate, br, zstd", true, true, E::br},
        {"gzip, deflate", true, true, E::gzip},            {"br", false, true, E::identity},
        {"gzip", true, false, E::identity},                {"", true, true, E::identity},
        {"br;q=0, gzip", true, true, E::gzip},             {"br;q=0.5, gzip;q=0.9", true, true, E::gzip},
        {"br;q=0.9, gzip;q=0.9", true, true, E::br},       {"*", true, true, E::br},
        {"*;q=0", true, true, E::identity},                {"gzip;q=0, *", true, true, E::br},
        {"br;q=0, *", true, true, E::gzip},                {"identity", true, true, E::identity},
        {"deflate, zstd", true, true, E::identity},        {"BR, GZIP", true, true, E::br},
        {"x-gzip", false, true, E::gzip},                  {" br ; q=0.001 ", true, true, E::br},
        {"br;q=0.000", true, true, E::identity},           {"br;q=abc, gzip", true, true, E::br},
        {"gzip;q=1.0, br;q=1.0", true, true, E::br},       {", , gzip", true, true, E::gzip},
        {"br;level=11;q=0.7, gzip;q=0.8", true, true, E::gzip}, {"gzip;q=0.8, br;q=1.5", true, true, E::br},
    };
    for (const Case& c : cases) {
        const E got = choose_encoding(c.accept, c.br, c.gz);
        if (got != c.want) std::printf("choose_encoding(\"%s\", %d, %d) = %d, want %d\n", c.accept, c.br, c.gz, static_cast<int>(got), static_cast<int>(c.want));
        CHECK(got == c.want);
    }
}

// The static handler with twins on disk: the chosen representation, its headers and
// validators, ranges over it, a stale twin ignored, a replaced twin picked up by the
// revalidation, and the switch.
static void test_precompressed() {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("agensio-twins-" + std::to_string(::getpid()));
    fs::remove_all(dir);
    fs::create_directories(dir / "www");
    auto write = [&](const char* name, const std::string& text) { std::ofstream(dir / "www" / name, std::ios::binary) << text; };
    const std::string css(100, 'c'), br(60, 'b'), gz(70, 'g');
    write("a.css", css);
    write("a.css.br", br);
    write("a.css.gz", gz);
    write("b.css", css);
    write("b.css.br", br);
    fs::last_write_time(dir / "www" / "b.css.br", fs::last_write_time(dir / "www" / "b.css") - std::chrono::seconds(10));  // a build not redone
    std::ofstream(dir / "agensio.toml") << "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n";
    Config cfg = load_config(dir / "agensio.toml");
    FileCache cache(4 << 20, 256 << 20, 0.2, 64);
    StaticHandler handler(cfg, cache);
    WorkerState ws;
    ws.now = std::time(nullptr);
    ws.site = &cfg.sites[0];
    Stream s;
    auto serve = [&](const char* path, std::string_view accept, std::string_view if_none_match = {}, std::string_view range = {}) {
        s.request.reset();
        s.response.reset();
        s.request.method = Method::get;
        s.request.accept_encoding = accept;
        s.request.if_none_match = if_none_match;
        s.request.range = range;
        ws.path = path;
        handler.serve_location(s, Router::location(cfg.sites[0], ws.path), ws);
    };
    auto body = [&]() -> std::string_view {
        const auto* m = std::get_if<MemoryBody>(&s.response.body);
        return m ? m->data : std::string_view{};
    };
    auto has = [&](std::string_view field) { return s.response.prebuilt_headers.find(field) != std::string_view::npos; };
    auto vary_field = [&]() {
        for (const auto& f : s.response.headers)
            if (f.name == "Vary" && f.value == "Accept-Encoding") return true;
        return false;
    };
    serve("/a.css", "br;q=1, gzip;q=0.8");
    CHECK(s.response.status == 200 && body() == br && has("Content-Type: text/css") && has("Content-Length: 60\r\n") &&
          has("\r\nContent-Encoding: br\r\nVary: Accept-Encoding\r\nAccept-Ranges: bytes\r\n\r\n") && !s.response.prebuilt_h2.empty());
    const std::string br_etag(s.response.entry->etag);
    const std::string br_h2(s.response.prebuilt_h2);
    serve("/a.css", "gzip");
    CHECK(body() == gz && has("Content-Encoding: gzip\r\n") && has("Content-Length: 70\r\n") && s.response.entry->etag != br_etag);
    serve("/a.css", "");
    CHECK(body() == css && !has("Content-Encoding") && has("\r\nVary: Accept-Encoding\r\nAccept-Ranges") && s.response.entry->etag != br_etag &&
          s.response.prebuilt_h2 != br_h2);
    const std::string id_etag(s.response.entry->etag);
    serve("/a.css", "br;q=0, gzip");
    CHECK(body() == gz);
    serve("/a.css", "*");
    CHECK(body() == br);
    serve("/a.css", "deflate, identity");
    CHECK(body() == css);
    // One entry with its three bodies, inserted once; the choice is per request.
    CHECK(cache.entry_count() == 1 && cache.total_bytes() == 230u);
    // Validators are per representation: the twin's ETag gives 304 (with Vary), the file's does not match the twin.
    serve("/a.css", "br", br_etag);
    CHECK(s.response.status == 304 && vary_field());
    serve("/a.css", "br", id_etag);
    CHECK(s.response.status == 200 && body() == br);
    serve("/a.css", "", id_etag);
    CHECK(s.response.status == 304 && vary_field());
    // A Range on the twin slices the compressed bytes and keeps its Content-Encoding.
    serve("/a.css", "br", {}, "bytes=0-9");
    CHECK(s.response.status == 206 && body() == std::string_view(br).substr(0, 10) && has("Content-Range: bytes 0-9/60\r\n") &&
          has("Content-Encoding: br\r\nVary: Accept-Encoding\r\nAccept-Ranges"));
    // HEAD declares the twin.
    s.request.reset();
    s.response.reset();
    s.request.method = Method::head;
    s.request.accept_encoding = "br";
    ws.path = "/a.css";
    handler.serve_location(s, Router::location(cfg.sites[0], ws.path), ws);
    CHECK(s.response.head && has("Content-Length: 60\r\n") && has("Content-Encoding: br\r\n"));
    // A twin older than its file is a build that was not redone: the file is served, without Vary.
    serve("/b.css", "br");
    CHECK(body() == css && !has("Content-Encoding") && !has("Vary"));
    // A replaced twin shows within the revalidation interval, as a change of the file would.
    const std::string br2(61, 'B');
    write("a.css.br", br2);
    fs::last_write_time(dir / "www" / "a.css.br", fs::last_write_time(dir / "www" / "a.css") + std::chrono::seconds(5));
    const CacheKeyView key{Router::location(cfg.sites[0], "/a.css").id, "/a.css"};
    cache.find(key)->last_validated.store(0);
    ws.now += 2;
    serve("/a.css", "br");
    CHECK(body() == br2 && has("Content-Length: 61\r\n") && cache.entry_count() == 2 && cache.total_bytes() == 331u);  // a.css with twins, b.css alone
    // Twins removed: the file alone, and no Vary any more.
    fs::remove(dir / "www" / "a.css.br");
    fs::remove(dir / "www" / "a.css.gz");
    cache.find(key)->last_validated.store(0);
    ws.now += 2;
    serve("/a.css", "br, gzip");
    CHECK(body() == css && !has("Vary") && cache.total_bytes() == 200u);
    // The switch: twins on disk are not looked at.
    write("a.css.br", br);
    fs::last_write_time(dir / "www" / "a.css.br", fs::last_write_time(dir / "www" / "a.css") + std::chrono::seconds(5));
    cfg.cache_precompressed = false;
    FileCache plain(4 << 20, 256 << 20, 0.2, 64);
    StaticHandler off(cfg, plain);
    WorkerState fresh;  // its own local index: the entries above belong to the other cache
    fresh.now = ws.now;
    fresh.site = ws.site;
    fresh.path = "/a.css";
    s.request.reset();
    s.response.reset();
    s.request.method = Method::get;
    s.request.accept_encoding = "br";
    off.serve_location(s, Router::location(cfg.sites[0], fresh.path), fresh);
    CHECK(body() == css && !has("Vary") && plain.total_bytes() == 100u);
    fs::remove_all(dir);
}

// Per-site protocols (HttpArena needs a TLS port kept at HTTP/1.1 next to one offering h2):
// inherited from [server], overridden per site, sites on one address must agree.
static void test_site_protocols() {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("agensio-protocols-" + std::to_string(::getpid()));
    fs::remove_all(dir);
    fs::create_directories(dir / "www");
    auto load = [&](const std::string& text) {
        std::ofstream(dir / "p.toml") << text;
        return load_config(dir / "p.toml");
    };
    const Config a = load("[server]\nprotocols = [\"h2c\", \"h2\", \"h1\"]\n"
                          "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n"
                          "[[site]]\nserver_name = [\"b\"]\nlisten = [\"127.0.0.1:18081\"]\nroot = \"www\"\nprotocols = [\"http/1.1\"]\n");
    CHECK(a.sites[0].h2 && a.sites[0].h2c && a.sites[0].alpn_wire == std::string("\x02h2\x08http/1.1", 12) && a.sites[0].protocols.size() == 3);
    CHECK(!a.sites[1].h2 && !a.sites[1].h2c && a.sites[1].alpn_wire == std::string("\x08http/1.1", 9) && a.sites[1].protocols == std::vector<std::string>{"h1"});
    bool refused = false;
    try {
        load("[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n"
             "[[site]]\nserver_name = [\"b\"]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\nprotocols = [\"h1\"]\n");
    } catch (const std::exception& e) {
        refused = std::string(e.what()).find("share 127.0.0.1:18080 but list different protocols") != std::string::npos;
    }
    CHECK(refused);
    refused = false;
    try {
        load("[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\nprotocols = [\"spdy\"]\n");
    } catch (const std::exception& e) {
        refused = std::string(e.what()).find("protocols") != std::string::npos;
    }
    CHECK(refused);
    CHECK(available_cpus() >= 1);
    fs::remove_all(dir);
}

#ifdef AGENSIO_HTTPARENA
// The benchmark handler against a three-item dataset: the sums, the JSON shape and
// arithmetic, /pipeline, the refusals.
static void test_httparena() {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("agensio-arena-" + std::to_string(::getpid()));
    fs::remove_all(dir);
    fs::create_directories(dir / "www");
    std::ofstream(dir / "dataset.json") << R"([
      {"id": 1, "name": "Alpha \"W\"", "category": "electronics", "price": 328, "quantity": 15, "active": true, "tags": ["sale", "popular"], "rating": {"score": 48, "count": 53}},
      {"id": 2, "name": "Pro Valve", "category": "tools", "price": 347, "quantity": 95, "active": false, "tags": [], "rating": {"score": 40, "count": 7}},
      {"id": 3, "name": "Gizmo", "category": "toys", "price": 5, "quantity": 2, "active": true, "tags": ["new"], "rating": {"score": 10, "count": 1}}])";
    std::ofstream(dir / "a.toml") << "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n"
                                     "[[site.location]]\npath = \"/\"\nhandler = \"httparena\"\nhttparena = { dataset = \"dataset.json\" }\n";
    Config cfg = load_config(dir / "a.toml");
    const LocationConfig& loc = Router::location(cfg.sites[0], "/baseline11");
    CHECK(loc.kind == HandlerKind::httparena && loc.httparena && loc.httparena->items.size() == 3 && loc.allow == "GET, HEAD, POST");
    HttparenaHandler handler;
    WorkerState ws;
    ws.site = &cfg.sites[0];
    Stream s;
    int done = 0;
    auto serve = [&](Method m, const char* target, const char* path) {
        s.request.reset();
        s.response.reset();
        s.request.method = m;
        s.request.target = target;
        ws.path = path;
        handler.start(s, loc, ws, [&] { ++done; });
    };
    auto body = [&]() -> std::string_view {
        const auto* mb = std::get_if<MemoryBody>(&s.response.body);
        return mb ? mb->data : std::string_view{};
    };
    serve(Method::get, "/baseline11?a=13&b=42", "/baseline11");
    CHECK(s.response.status == 200 && body() == "55" && s.response.prebuilt_headers == "Content-Type: text/plain\r\nContent-Length: 2\r\n\r\n" && done == 1);
    serve(Method::get, "/baseline2?a=-5&b=7&c=100", "/baseline2");
    CHECK(body() == "102");
    serve(Method::get, "/baseline11", "/baseline11");
    CHECK(body() == "0");
    serve(Method::head, "/baseline11?a=1&b=2", "/baseline11");
    CHECK(s.response.head && body() == "3");
    serve(Method::get, "/pipeline", "/pipeline");
    CHECK(body() == "ok" && s.response.status == 200);
    serve(Method::get, "/json/2?m=3", "/json/2");
    CHECK(s.response.status == 200 &&
          body() == "{\"items\":[{\"id\":1,\"name\":\"Alpha \\\"W\\\"\",\"category\":\"electronics\",\"price\":328,\"quantity\":15,\"active\":true,\"tags\":[\"sale\",\"popular\"],\"rating\":{\"score\":48,\"count\":53},\"total\":14760},"
                    "{\"id\":2,\"name\":\"Pro Valve\",\"category\":\"tools\",\"price\":347,\"quantity\":95,\"active\":false,\"tags\":[],\"rating\":{\"score\":40,\"count\":7},\"total\":98895}],\"count\":2}" &&
          s.response.prebuilt_headers.starts_with("Content-Type: application/json\r\nContent-Length: "));
    serve(Method::get, "/json/3", "/json/3");
    CHECK(body().ends_with(",\"total\":10}],\"count\":3}"));  // m defaults to 1
    serve(Method::get, "/json/4?m=1", "/json/4");
    CHECK(s.response.status == 400 && body() == "Bad Request");
    serve(Method::get, "/json/0", "/json/0");
    CHECK(s.response.status == 400);
    serve(Method::get, "/json/x", "/json/x");
    CHECK(s.response.status == 400);
    serve(Method::get, "/other", "/other");
    CHECK(s.response.status == 404 && body() == "Not Found" && done == 11);
    fs::remove_all(dir);
}
#endif

static void test_cache() {
    FileCache cache(100, 250, 0.5, 2);
    auto make = [](std::size_t n, std::int64_t access) {
        auto e = std::make_shared<CacheEntry>();
        e->data.assign(n, 'x');
        e->last_access = access;
        return e;
    };
    CHECK(cache.insert(CacheKeyView{7, "/a"}, make(100, 1)) != nullptr);
    CHECK(cache.find(CacheKeyView{8, "/a"}) == nullptr);  // another location (another generation): no hit
    CHECK(cache.insert(CacheKeyView{7, "/b"}, make(100, 2)) != nullptr);
    CHECK_EQ(cache.total_bytes(), 200u);
    CHECK(cache.insert(CacheKeyView{7, "/big"}, make(101, 3)) == nullptr);  // above max_file_size
    auto a = cache.find(CacheKeyView{7, "/a"});
    CHECK(a != nullptr);
    // Third 100-byte entry does not fit: /a (oldest) must be evicted and marked stale.
    CHECK(cache.insert(CacheKeyView{7, "/c"}, make(100, 3)) != nullptr);
    CHECK(a->stale.load());
    CHECK(cache.find(CacheKeyView{7, "/a"}) == nullptr);
    CHECK(cache.total_bytes() <= 250u);
    // Same key twice returns the existing entry.
    auto c1 = cache.find(CacheKeyView{7, "/c"});
    auto c2 = cache.insert(CacheKeyView{7, "/c"}, make(10, 9));
    CHECK(c1 == c2);
    // erase only removes the expected pointer.
    cache.erase(CacheKeyView{7, "/c"}, a.get());
    CHECK(cache.find(CacheKeyView{7, "/c"}) != nullptr);
    cache.erase(CacheKeyView{7, "/c"}, c1.get());
    CHECK(cache.find(CacheKeyView{7, "/c"}) == nullptr);
    CHECK(c1->stale.load());

    // Descriptor entries (streamed files, A1b): no bytes, counted against max_open_files (2 here).
    auto make_fd = [](std::int64_t access) {
        auto e = std::make_shared<CacheEntry>();
        e->descriptor_only = true;
        e->size = 10'000'000;
        e->last_access = access;
        return e;
    };
    const std::size_t bytes_before = cache.total_bytes();  // /b only
    auto d1 = cache.insert(CacheKeyView{7, "/d1"}, make_fd(1));
    CHECK(d1 != nullptr);
    CHECK(cache.insert(CacheKeyView{7, "/d2"}, make_fd(5)) != nullptr);
    CHECK_EQ(cache.open_files(), 2u);
    CHECK_EQ(cache.total_bytes(), bytes_before);
    // Third descriptor exceeds the budget: the oldest descriptor entry goes, memory entries stay.
    auto d3 = cache.insert(CacheKeyView{7, "/d3"}, make_fd(6));
    CHECK(d3 != nullptr);
    CHECK(d1->stale.load());
    CHECK(cache.find(CacheKeyView{7, "/d1"}) == nullptr);
    CHECK(cache.open_files() <= 2u);
    CHECK(cache.find(CacheKeyView{7, "/b"}) != nullptr);
    // Byte pressure evicts memory entries only: /b (access 2) is older than the descriptors but
    // the descriptors free no bytes, so they survive.
    auto b = cache.find(CacheKeyView{7, "/b"});
    CHECK(cache.insert(CacheKeyView{7, "/e"}, make(100, 7)) != nullptr);
    CHECK(cache.insert(CacheKeyView{7, "/f"}, make(100, 8)) != nullptr);
    CHECK(b->stale.load());
    CHECK(!d3->stale.load());
    CHECK(cache.find(CacheKeyView{7, "/d3"}) != nullptr);
    CHECK_EQ(cache.open_files(), 2u);
    // erase releases the descriptor budget.
    cache.erase(CacheKeyView{7, "/d3"}, d3.get());
    CHECK_EQ(cache.open_files(), 1u);
    // Pre-compressed twins hang off their file's entry and count against the byte budget
    // with it; the file alone is held to max_file_size, so a file at the limit keeps its twins.
    {
        FileCache small(100, 400, 0.5, 2);
        auto t = make(100, 1);
        t->br = make(60, 1);
        t->gzip = make(70, 1);
        CHECK(bytes_of(*t) == 230u && t->has_variants());
        auto stored = small.insert(CacheKeyView{7, "/t"}, t);
        CHECK(stored != nullptr && small.total_bytes() == 230u);
        CHECK(small.insert(CacheKeyView{7, "/u"}, make(100, 2)) != nullptr && small.total_bytes() == 330u);
        CHECK(small.insert(CacheKeyView{7, "/v"}, make(100, 3)) != nullptr);  // no room: the oldest, the twins' file, goes whole
        CHECK(t->stale.load() && small.find(CacheKeyView{7, "/t"}) == nullptr && small.total_bytes() == 200u);
        small.erase(CacheKeyView{7, "/u"}, small.find(CacheKeyView{7, "/u"}).get());
        CHECK(small.total_bytes() == 100u);
    }
    // A zero-byte memory entry is not a descriptor entry.
    CHECK(cache.insert(CacheKeyView{7, "/empty"}, make(0, 9)) != nullptr);
    CHECK_EQ(cache.open_files(), 1u);
    // max_open_files = 0 refuses descriptor entries; the handler then streams uncached.
    FileCache none(100, 250, 0.5, 0);
    CHECK(none.insert(CacheKeyView{7, "/d"}, make_fd(1)) == nullptr);
    CHECK(none.insert(CacheKeyView{7, "/m"}, make(10, 1)) != nullptr);

    LocalIndex local(2);
    local.insert(CacheKeyView{7, "/x"}, make(1, 0));
    local.insert(CacheKeyView{7, "/y"}, make(1, 0));
    CHECK(local.find(CacheKeyView{7, "/x"}) != nullptr);
    local.insert(CacheKeyView{7, "/z"}, make(1, 0));  // exceeds max: cleared, then inserted
    CHECK(local.find(CacheKeyView{7, "/x"}) == nullptr);
    CHECK(local.find(CacheKeyView{7, "/z"}) != nullptr);
}

// Feeds `wire` to a fresh decoder in pieces of `step` bytes with an output buffer of
// `out_cap`; returns the decoded body, or "<error>" / "<incomplete>". `rest` receives the
// wire bytes the decoder did not consume (a pipelined next request).
static std::string decode_chunked(std::string_view wire, std::size_t step, std::size_t out_cap, std::string* rest) {
    ChunkedDecoder d;
    std::string body, out(out_cap, '\0');
    std::size_t pos = 0;
    while (pos < wire.size()) {
        std::string_view piece = wire.substr(pos, step);
        std::size_t used = 0, produced = 0;
        const auto st = d.decode(piece, used, out.data(), out.size(), produced);
        body.append(out.data(), produced);
        pos += used;
        if (st == ChunkedDecoder::Status::error) return "<error>";
        if (st == ChunkedDecoder::Status::done) {
            if (rest) *rest = std::string(wire.substr(pos));
            return body;
        }
        if (used == 0 && produced == 0) return "<stuck>";
    }
    return d.done() ? body : "<incomplete>";
}

static void test_chunked() {
    ChunkSizeBuffer buf;
    CHECK_EQ(chunk_size_line(0, buf), std::string_view("0\r\n"));
    CHECK_EQ(chunk_size_line(255, buf), std::string_view("ff\r\n"));
    CHECK_EQ(chunk_size_line(65536, buf), std::string_view("10000\r\n"));
    CHECK_EQ(chunk_size_line(0xffffffffffffffffull, buf), std::string_view("ffffffffffffffff\r\n"));
    CHECK_EQ(kLastChunk, std::string_view("0\r\n\r\n"));

    // Decoder: every split of the wire bytes and every output size yields the same body,
    // and the bytes after the final CRLF are left alone.
    const std::string_view wire = "4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\nGET / HTTP/1.1";
    for (std::size_t step : {1, 2, 3, 7, 64})
        for (std::size_t cap : {1, 4, 5, 1024}) {
            std::string rest;
            CHECK_EQ(decode_chunked(wire, step, cap, &rest), std::string("Wikipedia in\r\n\r\nchunks."));
            CHECK_EQ(rest, std::string("GET / HTTP/1.1"));
        }
    CHECK_EQ(decode_chunked("0\r\n\r\n", 1, 8, nullptr), std::string(""));
    CHECK_EQ(decode_chunked("A;ext=1\r\n0123456789\r\n0\r\nX-Trailer: v\r\n\r\n", 3, 4, nullptr),
             std::string("0123456789"));
    CHECK_EQ(decode_chunked("0002\r\nab\r\n0\r\n\r\n", 5, 8, nullptr), std::string("ab"));  // leading zeros
    CHECK_EQ(decode_chunked("aB\r\n", 1, 8, nullptr), std::string("<incomplete>"));       // uppercase hex accepted
    CHECK_EQ(decode_chunked("zz\r\n", 1, 8, nullptr), std::string("<error>"));            // not hex
    CHECK_EQ(decode_chunked("\r\n", 1, 8, nullptr), std::string("<error>"));              // empty size
    CHECK_EQ(decode_chunked("1\nA\r\n0\r\n\r\n", 1, 8, nullptr), std::string("<error>"));  // bare LF
    CHECK_EQ(decode_chunked("2\r\nabX\n", 1, 8, nullptr), std::string("<error>"));       // data not followed by CRLF
    CHECK_EQ(decode_chunked("0\r\n T: v\r\n\r\n", 1, 8, nullptr), std::string("<error>"));  // obs-fold trailer
    CHECK_EQ(decode_chunked("11111111111111111\r\n", 1, 8, nullptr), std::string("<error>"));  // 17 hex digits
    CHECK_EQ(decode_chunked(std::string("1;") + std::string(5000, 'x') + "\r\nA\r\n0\r\n\r\n", 64, 8, nullptr),
             std::string("<error>"));  // extension line too long

    // Methods.
    for (auto [name, m] : {std::pair{"GET", Method::get}, std::pair{"HEAD", Method::head},
                           std::pair{"POST", Method::post}, std::pair{"PUT", Method::put},
                           std::pair{"DELETE", Method::del}, std::pair{"PATCH", Method::patch},
                           std::pair{"OPTIONS", Method::options}, std::pair{"TRACE", Method::trace},
                           std::pair{"CONNECT", Method::connect}}) {
        Request m_r;
        CHECK(parse_request(std::string(name) + " / HTTP/1.1\r\nHost: a\r\n\r\n", m_r) == ParseStatus::complete);
        CHECK(m_r.method == m);
    }
    Request other;
    CHECK(parse_request("PURGE / HTTP/1.1\r\nHost: a\r\n\r\n", other) == ParseStatus::complete);
    CHECK(other.method == Method::other && other.method_name == "PURGE");
    CHECK(parse_request("get / HTTP/1.1\r\nHost: a\r\n\r\n", other) == ParseStatus::complete);
    CHECK(other.method == Method::other);  // methods are case-sensitive
    CHECK_EQ(allow_header(kStaticMethods), std::string("GET, HEAD, OPTIONS"));
    CHECK_EQ(allow_header(method_bit(Method::head) | method_bit(Method::get)), std::string("GET, HEAD"));

    // Parser: body framing fields.
    Request r;
    CHECK(parse_request("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n", r) == ParseStatus::complete);
    CHECK(r.has_body && !r.chunked && r.content_length == 12 && !r.expect_continue && r.body == nullptr);
    CHECK(parse_request("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n", r) == ParseStatus::complete);
    CHECK(!r.has_body && r.content_length == 0);
    CHECK(parse_request("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: Chunked\r\n\r\n", r) ==
          ParseStatus::complete);
    CHECK(r.has_body && r.chunked);
    CHECK(parse_request("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", r) ==
          ParseStatus::unsupported_transfer_encoding);
    CHECK(parse_request("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n"
                        "Transfer-Encoding: chunked\r\n\r\n",
                        r) == ParseStatus::bad_request);
    CHECK(parse_request("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n", r) ==
          ParseStatus::complete);
    CHECK(r.expect_continue);
    CHECK(parse_request("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nExpect: nope\r\n\r\n", r) ==
          ParseStatus::expectation_failed);
    CHECK(parse_request("POST / HTTP/1.0\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n", r) ==
          ParseStatus::complete);
    CHECK(!r.expect_continue);  // ignored on HTTP/1.0
    CHECK(parse_request("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n", r) ==
          ParseStatus::bad_request);  // 20 digits
}

static void test_core_types() {
    Headers h;
    CHECK(h.empty());
    CHECK(h.add("Host", "a"));
    CHECK(h.add("X-Test", "1"));
    CHECK_EQ(h.size(), 2u);
    CHECK_EQ(h.get("host"), "a");
    CHECK_EQ(h.get("HOST"), "a");
    CHECK(h.contains("x-test"));
    CHECK(!h.contains("missing"));
    CHECK(h.get("missing").empty());
    for (std::size_t i = h.size(); i < Headers::kCapacity; ++i)
        CHECK(h.add("X", "y"));
    CHECK(!h.add("Overflow", "z"));
    h.clear();
    CHECK(h.empty());

    Result<int> ok = 42;
    CHECK(ok && ok.value() == 42 && !ok.error());
    Result<int> bad = std::errc::no_such_file_or_directory;
    CHECK(!bad && bad.error() == std::errc::no_such_file_or_directory);
    Result<std::string> moved = std::string("abc");
    Result<std::string> taken = std::move(moved);
    CHECK(taken && *taken == "abc");
    Result<void> fine;
    CHECK(fine.ok());
    Result<void> failed = std::errc::permission_denied;
    CHECK(!failed && failed.error() == std::errc::permission_denied);

    // The parser fills the generic header list as well as the extracted fields.
    Request r;
    CHECK(parse_request("GET / HTTP/1.1\r\nHost: a\r\nX-Custom: v\r\nAccept: */*\r\n\r\n", r) == ParseStatus::complete);
    CHECK_EQ(r.headers.size(), 3u);
    CHECK_EQ(r.headers.get("x-custom"), "v");
    CHECK_EQ(r.headers.get("Accept"), "*/*");
    CHECK_EQ(r.headers[0].name, "Host");
}

static void test_route_and_etag() {
    SiteConfig a, b;
    a.server_names = {"example.com", "www.example.com"};
    a.is_default = true;
    b.server_names = {"other.test"};
    Router r;
    r.add_site(a);
    r.add_site(b);
    CHECK(r.site("example.com") == &a);
    CHECK(r.site("EXAMPLE.com:8080") == &a);
    CHECK(r.site("other.test:443") == &b);
    CHECK(r.site("other.test.") == &b);
    CHECK(r.site("[::1]:8080") == &a);
    CHECK(r.site("unknown.host") == &a);
    CHECK(r.site("") == &a);

    // Locations: exact beats prefix, longer prefix beats shorter, implicit "/" catches the rest.
    SiteConfig s;
    s.root = "/srv";
    s.index = {"index.html"};
    auto loc = [](std::string path, bool exact) {
        LocationConfig l;
        l.path = std::move(path);
        l.exact = exact;
        return l;
    };
    s.locations = {loc("/static/", false), loc("/static/app/", false), loc("/static/app/", true),
                   loc("/index.html", true)};
    finalize_site(s);
    CHECK_EQ(s.locations.size(), 5u);
    CHECK(s.locations.back().path == "/" && !s.locations.back().exact);
    CHECK_EQ(s.locations.back().root, "/srv");  // implicit location inherits the site
    CHECK_EQ(Router::location(s, "/").path, "/");
    CHECK_EQ(Router::location(s, "/style.css").path, "/");
    CHECK_EQ(Router::location(s, "/static/x.png").path, "/static/");
    CHECK_EQ(Router::location(s, "/static/app/x.js").path, "/static/app/");
    CHECK(!Router::location(s, "/static/app/x.js").exact);
    CHECK(Router::location(s, "/static/app/").exact);
    CHECK(Router::location(s, "/index.html").exact);
    CHECK_EQ(Router::location(s, "/index.htmlx").path, "/");  // exact does not prefix-match
    // final (nginx ^~): a shielded prefix keeps suffix locations out of its subtree.
    SiteConfig w;
    w.root = "/srv";
    LocationConfig php = loc(".php", false);
    php.suffix = true;
    LocationConfig uploads = loc("/uploads/", false);
    uploads.final = true;
    w.locations = {php, uploads, loc("/plugins/", false)};
    finalize_site(w);
    CHECK_EQ(Router::location(w, "/uploads/x.php").path, "/uploads/");
    CHECK_EQ(Router::location(w, "/plugins/x.php").path, ".php");  // not final: suffix wins
    CHECK_EQ(Router::location(w, "/uploads/a.jpg").path, "/uploads/");
    CHECK_EQ(Router::location(w, "/x.php").path, ".php");
    CHECK_EQ(Router::location(w, "/x.txt").path, "/");

    // try_files grammar.
    auto tf = parse_try_files({"$uri", "$uri/", "/index.html?$query_string"});
    CHECK_EQ(tf.size(), 3u);
    CHECK(tf[0].kind == TryStep::Kind::uri && tf[1].kind == TryStep::Kind::uri_dir);
    CHECK(tf[2].kind == TryStep::Kind::fallback);
    CHECK_EQ(tf[2].target, "/index.html");
    CHECK(parse_try_files({"$uri", "=404"})[1].status == 404);
    CHECK(parse_try_files({"/a/../b"})[0].target == "/b");
    auto throws = [](std::vector<std::string> items) {
        try {
            parse_try_files(items);
        } catch (const std::invalid_argument&) {
            return true;
        }
        return false;
    };
    CHECK(throws({"=404", "$uri"}));       // status must be last
    CHECK(throws({"/x", "$uri"}));         // fallback must be last
    CHECK(throws({"=500"}));               // only 403/404
    CHECK(throws({"$args"}));              // unknown variable
    CHECK(throws({"/x/$uri"}));            // variables in fallbacks not supported
    CHECK(throws({"index.html"}));         // must start with '/'

    std::string etag;
    make_etag(0x5a630d3c, 0x6b, etag);
    CHECK_EQ(etag, "\"5a630d3c-6b\"");
}

static void test_fcgi_codec() {
    using namespace fcgi;
    // Records: header, content, padding to 8; the stream terminator; params encoding.
    std::string out;
    append_begin_request(out, 1, true);
    CHECK_EQ(out.size(), 16u);
    CHECK_EQ(static_cast<unsigned char>(out[1]), 1u);   // begin_request
    CHECK_EQ(static_cast<unsigned char>(out[3]), 1u);   // request id 1
    CHECK_EQ(static_cast<unsigned char>(out[5]), 8u);   // content length 8
    CHECK_EQ(static_cast<unsigned char>(out[9]), 1u);   // role responder
    CHECK_EQ(static_cast<unsigned char>(out[10]), 1u);  // keep-conn flag
    std::string params;
    append_param(params, "A", "b");
    CHECK_EQ(params, std::string("\x01\x01" "Ab", 4));
    params.clear();
    append_param(params, "N", std::string(300, 'v'));
    CHECK_EQ(params.size(), 1u + 4u + 1u + 300u);
    CHECK_EQ(static_cast<unsigned char>(params[1]), 0x80u);  // 4-byte length, high bit set
    CHECK_EQ(static_cast<unsigned char>(params[4]), 300u & 0xff);
    out.clear();
    append_stream(out, RecordType::stdin_, 1, std::string(70000, 'x'), true);
    // 65535 (+1 padding) + 4465 (+7 padding) + empty terminator
    CHECK_EQ(out.size(), std::size_t{(8 + 65535 + 1) + (8 + 4465 + 7) + 8});
    // Reader: needs the whole record, reports content without padding, leaves the rest.
    std::string wire;
    append_record(wire, RecordType::stdout_, 1, "hello");
    append_record(wire, RecordType::end_request, 1, std::string("\0\0\0\x07\0\0\0\0", 8));
    std::size_t consumed = 0;
    RecordHeader h;
    std::string_view content;
    CHECK(next_record(std::string_view(wire).substr(0, 10), consumed, h, content) == ReadStatus::need_more);
    CHECK(next_record(wire, consumed, h, content) == ReadStatus::record);
    CHECK(h.type == static_cast<std::uint8_t>(RecordType::stdout_) && content == "hello" && consumed == 16u);
    std::string_view rest = std::string_view(wire).substr(consumed);
    CHECK(next_record(rest, consumed, h, content) == ReadStatus::record);
    EndRequest er;
    CHECK(parse_end_request(content, er) && er.app_status == 7 &&
          er.protocol_status == ProtocolStatus::request_complete);
    CHECK_EQ(consumed, rest.size());
    std::string bad = wire;
    bad[0] = 2;  // version
    CHECK(next_record(bad, consumed, h, content) == ReadStatus::error);
    // CGI head: Status, Location default, LF endings, folding rejected.
    CgiHead head;
    CHECK(parse_cgi_head("Content-Type: text/html\r\nX-A: 1\r\n\r\nbody", head) == HeadStatus::complete);
    CHECK(head.status == 200 && head.headers.size() == 2 && head.length == 35u);
    CHECK_EQ(head.headers.get("x-a"), std::string_view("1"));
    CHECK(parse_cgi_head("Status: 404 Not Found\nContent-Type: text/plain\n\n", head) == HeadStatus::complete);
    CHECK(head.status == 404 && head.headers.size() == 1);
    CHECK(parse_cgi_head("Location: /login\r\n\r\n", head) == HeadStatus::complete);
    CHECK(head.status == 302 && head.headers.get("location") == "/login");
    CHECK(parse_cgi_head("Status: 201\r\nLocation: /new\r\n\r\n", head) == HeadStatus::complete);
    CHECK_EQ(head.status, 201);
    CHECK(parse_cgi_head("Content-Type: text/html\r\n", head) == HeadStatus::incomplete);
    CHECK(parse_cgi_head("No colon here\r\n\r\n", head) == HeadStatus::error);
    CHECK(parse_cgi_head("Status: abc\r\n\r\n", head) == HeadStatus::error);
    CHECK(parse_cgi_head("X: a\r\n b\r\n\r\n", head) == HeadStatus::error);  // obs-fold
    CHECK(parse_cgi_head("X: a\x01\r\n\r\n", head) == HeadStatus::error);   // control char
}

static void test_log_format() {
    AccessRecord r;
    r.remote = "203.0.113.9";
    r.host = "example.com";
    r.method = "GET";
    r.target = "/a\"b?x=1";
    r.status = 200;
    r.bytes = 1024;
    r.referer = "";
    r.user_agent = "curl/8.0 \\ \x01";
    std::string out;
    WorkerLogs::format_combined(out, "17/Sep/2026:10:15:32 +0300", r);
    CHECK_EQ(out, std::string("203.0.113.9 - - [17/Sep/2026:10:15:32 +0300] \"GET /a\\x22b?x=1 HTTP/1.1\" 200 1024 "
                              "\"-\" \"curl/8.0 \\x5C \\x01\"\n"));
    out.clear();
    WorkerLogs::format_json(out, "2026-09-17T10:15:32+03:00", r);
    CHECK_EQ(out, std::string("{\"time\":\"2026-09-17T10:15:32+03:00\",\"remote\":\"203.0.113.9\","
                              "\"host\":\"example.com\","
                              "\"method\":\"GET\",\"target\":\"/a\\\"b?x=1\",\"proto\":\"HTTP/1.1\",\"status\":200,"
                              "\"bytes\":1024,\"referer\":\"\",\"user_agent\":\"curl/8.0 \\\\ \\u0001\"}\n"));
    // A request that never parsed: no request line, no method.
    AccessRecord bad;
    bad.status = 400;
    out.clear();
    WorkerLogs::format_combined(out, "t", bad);
    CHECK_EQ(out, std::string("- - - [t] \"-\" 400 0 \"-\" \"-\"\n"));
    LogLevel level;
    CHECK(parse_log_level("info", level) && level == LogLevel::info);
    CHECK(!parse_log_level("debug", level));
    // Registry: same path shares a sink, "off" is none, and the file receives whole lines.
    LogRegistry reg;
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("agensio-log-" + std::to_string(::getpid()));
    fs::create_directories(dir);
    const std::string path = (dir / "a.log").string();
    CHECK_EQ(reg.add("off"), -1);
    CHECK_EQ(reg.add(path), 0);
    CHECK_EQ(reg.add(path), 0);
    CHECK_EQ(reg.add((dir / "b.log").string()), 1);
    std::string err;
    CHECK(reg.open_all(err));
    WorkerLogs logs;
    logs.attach(&reg, AccessLogFormat::combined);
    logs.log(0, 1'000'000, r);
    logs.flush();
    fs::rename(dir / "a.log", dir / "a.log.1");
    reg.reopen_all();
    logs.log(0, 1'000'001, r);
    logs.flush();
    std::ifstream in1(dir / "a.log.1"), in2(dir / "a.log");
    std::string l1, l2;
    std::getline(in1, l1);
    std::getline(in2, l2);
    CHECK(l1.find("\"GET /a") != std::string::npos);
    CHECK(l2.find("\"GET /a") != std::string::npos);  // after reopen the new file gets the line
    fs::remove_all(dir);
}

// Loads a configuration with locations from a temporary directory.
// Decodes FCGI_PARAMS pairs back into name=value lines for assertions.
static std::string decode_params(std::string_view p) {
    std::string out;
    std::size_t i = 0;
    auto len = [&]() {
        std::size_t n = static_cast<unsigned char>(p[i++]);
        if (n & 0x80) {
            n = (n & 0x7f) << 24;
            n |= static_cast<std::size_t>(static_cast<unsigned char>(p[i++])) << 16;
            n |= static_cast<std::size_t>(static_cast<unsigned char>(p[i++])) << 8;
            n |= static_cast<unsigned char>(p[i++]);
        }
        return n;
    };
    while (i < p.size()) {
        const std::size_t nl = len(), vl = len();
        out.append(p.substr(i, nl)).append("=").append(p.substr(i + nl, vl)).append("\n");
        i += nl + vl;
    }
    return out;
}

static void test_fcgi_http_params() {
    Headers h;
    h.add("Host", "example.com");
    h.add("Proxy", "http://evil.example/");   // httpoxy: never forwarded
    h.add("X_Forwarded_For", "203.0.113.9");  // underscore: dropped, cannot spoof X-Forwarded-For
    h.add("X-Test", "a");
    h.add("Cookie", "a=1");
    h.add("X-Test", "b");
    h.add("Cookie", "b=2");
    h.add("x-test", "c");
    std::string out, scratch;
    FcgiHandler::append_http_params(out, h, scratch);
    const std::string lines = decode_params(out);
    CHECK_EQ(lines, std::string("HTTP_HOST=example.com\nHTTP_X_TEST=a, b, c\nHTTP_COOKIE=a=1; b=2\n"));
    CHECK(lines.find("PROXY") == std::string::npos && lines.find("FORWARDED") == std::string::npos);
}

static void test_presets() {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("agensio-preset-" + std::to_string(::getpid()));
    fs::create_directories(dir / "app" / "public" / "build");
    fs::create_directories(dir / "www");
    auto write = [&](const char* name, const std::string& text) { std::ofstream(dir / name) << text; };
    write("laravel.toml",
          "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"app\"\napp = \"laravel\"\n"
          "php = { socket = \"unix:/run/php/fpm.sock\" }\n"
          "[[site.location]]\npath = \"/build/\"\nadd_headers = { \"Cache-Control\" = \"no-store\" }\n");
    Config cfg = load_config(dir / "laravel.toml");
    const SiteConfig& s = cfg.sites[0];
    CHECK(s.app == "laravel" && s.root == fs::canonical(dir / "app" / "public").string());
    CHECK(s.index.size() == 1 && s.index[0] == "index.php");
    CHECK(s.try_files.size() == 3 && s.try_files[2].kind == TryStep::Kind::fallback &&
          s.try_files[2].target == "/index.php");
    const LocationConfig& fc = Router::location(s, "/index.php");
    CHECK(fc.exact && fc.kind == HandlerKind::fastcgi && fc.origin == "preset:laravel" && fc.try_files.size() == 3);
    // Only the front controller runs; any other .php is refused by the static handler, so
    // it is neither executed nor served as source (2026-09-19).
    const LocationConfig& other = Router::location(s, "/other.php");
    CHECK(other.kind == HandlerKind::static_ && std::find(other.deny_suffixes.begin(), other.deny_suffixes.end(), ".php") != other.deny_suffixes.end());
    const LocationConfig& build = Router::location(s, "/build/app.js");
    // A hand-written /build/ location that only sets fields joins the preset's: its value wins,
    // the preset's location stays (2026-09-28; before, it replaced the preset's location).
    CHECK(build.origin == "preset:laravel" && build.add_headers.size() == 1 && build.add_headers[0].second == "no-store");
    CHECK(Router::location(s, "/").try_files.size() == 3);
    std::ostringstream explain;
    explain_config(cfg, explain);
    const std::string text = explain.str();
    CHECK(text.find("# app = \"laravel\"") != std::string::npos);
    CHECK(text.find("# from preset:laravel") != std::string::npos);
    CHECK(text.find("try_files = [\"$uri\", \"$uri/\", \"/index.php\"]") != std::string::npos);
    CHECK(text.find("add_headers = { \"Cache-Control\" = \"no-store\" }") != std::string::npos);

    write("php.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\napp = \"php\"\n"
                      "php = { socket = \"unix:/run/php/fpm.sock\" }\n");
    Config pcfg = load_config(dir / "php.toml");
    const SiteConfig& p = pcfg.sites[0];
    CHECK(p.index.size() == 2 && Router::location(p, "/a/b.php").kind == HandlerKind::fastcgi);
    CHECK(Router::location(p, "/a/b.php").suffix && p.try_files.size() == 3 && p.try_files[2].status == 404);

    // Drupal: web/ is served, any .php runs, the front controller catches the rest, and what
    // Drupal's .htaccess protects is refused natively.
    fs::create_directories(dir / "drupal" / "web" / "sites" / "default" / "files");
    std::ofstream(dir / "drupal" / "web" / "index.php") << "<?php";
    write("drupal.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"drupal\"\napp = \"drupal\"\n"
                         "php = { socket = \"unix:/run/php/fpm.sock\" }\n");
    Config dcfg = load_config(dir / "drupal.toml");
    const SiteConfig& d = dcfg.sites[0];
    CHECK(d.root == fs::canonical(dir / "drupal" / "web").string() && d.try_files.size() == 3 && d.try_files[2].target == "/index.php");
    CHECK(Router::location(d, "/core/install.php").kind == HandlerKind::fastcgi);
    CHECK(Router::location(d, "/core/lib/Drupal.php").kind == HandlerKind::static_ && Router::location(d, "/core/lib/Drupal.php").final);
    CHECK(Router::location(d, "/sites/default/settings.php").exact && Router::location(d, "/sites/default/settings.php").try_files[0].status == 404);
    {
        // files/: a miss goes to the front controller (image styles, aggregates); core/lib does not.
        const LocationConfig& files = Router::location(d, "/sites/default/files/styles/thumb/x.jpg");
        const LocationConfig& lib = Router::location(d, "/core/lib/x.txt");
        CHECK(files.path == "/sites/default/files/" && files.try_files.size() == 2 && files.try_files[1].kind == TryStep::Kind::fallback && files.try_files[1].target == "/index.php");
        CHECK(lib.path == "/core/lib/" && lib.try_files.size() == 2 && lib.try_files[1].status == 404);
        CHECK(std::find(files.deny_suffixes.begin(), files.deny_suffixes.end(), ".php") != files.deny_suffixes.end());
    }
    CHECK(Router::location(d, "/sites/default/settings.php").handler == "deny" && Router::location(d, "/core/lib/x.inc").handler == "static");
    const LocationConfig& droot = Router::location(d, "/dump.sqlite");
    CHECK(droot.path == "/" && std::find(droot.deny_suffixes.begin(), droot.deny_suffixes.end(), ".sqlite") != droot.deny_suffixes.end() &&
          std::find(droot.deny_suffixes.begin(), droot.deny_suffixes.end(), ".inc") != droot.deny_suffixes.end());
    // WordPress: wp-config.php is never an entry point.
    fs::create_directories(dir / "wp2");
    write("wp2.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"wp2\"\napp = \"wordpress\"\nphp = { socket = \"unix:/run/php/fpm.sock\" }\n");
    Config wcfg2 = load_config(dir / "wp2.toml");
    CHECK(Router::location(wcfg2.sites[0], "/wp-config.php").try_files[0].status == 404 && Router::location(wcfg2.sites[0], "/wp-login.php").kind == HandlerKind::fastcgi);
    CHECK(Router::location(wcfg2.sites[0], "/readme.html").try_files[0].status == 404 && Router::location(wcfg2.sites[0], "/license.txt").try_files[0].status == 404);
    for (const char* dropin : {"/wp-content/db.php", "/wp-content/advanced-cache.php", "/wp-content/object-cache.php"})
        CHECK(Router::location(wcfg2.sites[0], dropin).try_files[0].status == 404);
    // Every PHP preset either runs .php through FastCGI or refuses it on every static
    // location: a preset that lets a .php reach the static handler cannot ship.
    for (const Config* c : {&cfg, &pcfg, &dcfg, &wcfg2}) {
        const SiteConfig& site = c->sites[0];
        const bool runs_php = Router::location(site, "/x/y.php").kind == HandlerKind::fastcgi;
        bool refused_everywhere = true;
        for (const auto& l : site.locations)  // the preset's locations; a hand-written one is the administrator's
            if (l.kind == HandlerKind::static_ && !l.exact && l.origin.starts_with("preset:") &&
                std::find(l.deny_suffixes.begin(), l.deny_suffixes.end(), ".php") == l.deny_suffixes.end())
                refused_everywhere = false;
        CHECK(runs_php || refused_everywhere);
    }

    auto rejects = [&](const char* name, const std::string& text) {
        write(name, text);
        try {
            load_config(dir / name);
        } catch (const std::runtime_error&) {
            return true;
        }
        return false;
    };
    CHECK(rejects("nosock.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"app\"\napp = \"laravel\"\n"));
    CHECK(rejects("unknown.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\napp = \"drupal\"\n"));
    CHECK(rejects("nopublic.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\napp = \"laravel\"\n"
                                   "php = { socket = \"unix:/run/php/fpm.sock\" }\n"));
    CHECK(rejects("badhdr.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n"
                                 "[[site.location]]\npath = \"/x/\"\nadd_headers = { \"Bad Name\" = \"v\" }\n"));
    write("wp.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\napp = \"wordpress\"\n"
                     "php = { socket = \"unix:/run/php/fpm.sock\" }\n");
    Config wcfg = load_config(dir / "wp.toml");
    const SiteConfig& w = wcfg.sites[0];
    CHECK(w.index.size() == 1 && w.index[0] == "index.php" && w.try_files.size() == 3);
    CHECK(Router::location(w, "/wp-login.php").kind == HandlerKind::fastcgi);
    CHECK(Router::location(w, "/wp-content/plugins/x/ajax.php").kind == HandlerKind::fastcgi);
    const LocationConfig& up = Router::location(w, "/wp-content/uploads/2026/shell.php");
    CHECK(up.path == "/wp-content/uploads/" && up.final && up.kind == HandlerKind::static_);
    CHECK(up.deny_suffixes.size() == 25 && up.add_headers.size() == 1 && up.origin == "preset:wordpress");
    CHECK(Router::location(w, "/wp-includes/js/x.js").final);
    CHECK(Router::location(w, "/wp-admin/").path == "/");
    CHECK(rejects("badfinal.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n"
                                   "[[site.location]]\npath = \".php\"\nmatch = \"suffix\"\nfinal = true\n"));
    CHECK(rejects("baddeny.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n"
                                  "[[site.location]]\npath = \"/u/\"\ndeny_suffixes = [\"php\"]\n"));
    CHECK(rejects("badallow.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n"
                                   "[[site.location]]\npath = \"/u/\"\nallow_suffixes = [\"png\"]\n"));
    write("allow.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n"
                        "[[site.location]]\npath = \"/u/\"\nallow_suffixes = [\".png\", \".pdf\"]\n");
    {
        const Config acfg = load_config(dir / "allow.toml");
        const LocationConfig& u = Router::location(acfg.sites[0], "/u/x.pdf");
        CHECK(u.path == "/u/" && u.allow_suffixes.size() == 2 && u.allow_suffixes[1] == ".pdf" && u.deny_suffixes.empty());
    }

    // Grav (2026-09-23 live report, run on the borrowed drupal preset): only index.php runs;
    // logs/, backup/, cache/, bin/, tests/, tmp/ are refused whole; system/ and vendor/
    // serve assets only; user/ hides pages, accounts and configuration; .log and .sql are
    // refused on every preset now.
    fs::create_directories(dir / "grav" / "bin");
    fs::create_directories(dir / "grav" / "system");
    write("grav/index.php", "<?php");
    write("grav/bin/grav", "#!");
    write("grav/system/defines.php", "<?php");
    write("grav.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"grav\"\napp = \"grav\"\n"
                       "php = { socket = \"unix:/run/php/fpm.sock\" }\n");
    Config gcfg = load_config(dir / "grav.toml");
    const SiteConfig& g = gcfg.sites[0];
    auto refuses = [](const LocationConfig& l, const char* s) { return std::find(l.deny_suffixes.begin(), l.deny_suffixes.end(), s) != l.deny_suffixes.end(); };
    CHECK(g.app == "grav" && g.root == fs::canonical(dir / "grav").string() && g.try_files.size() == 3 && g.try_files[2].target == "/index.php");
    CHECK(Router::location(g, "/index.php").kind == HandlerKind::fastcgi && Router::location(g, "/index.php").exact);
    const LocationConfig& gother = Router::location(g, "/other.php");
    CHECK(gother.path == "/" && gother.kind == HandlerKind::static_ && refuses(gother, ".php") && refuses(gother, ".log") && refuses(gother, ".sql"));
    const LocationConfig& glogs = Router::location(g, "/logs/grav.log");
    CHECK(glogs.path == "/logs/" && glogs.final && glogs.handler == "deny" && glogs.origin == "preset:grav" && glogs.try_files.size() == 1);
    CHECK(Router::location(g, "/logs").exact && Router::location(g, "/logs").handler == "deny" && Router::location(g, "/logstash.js").path == "/");
    CHECK(Router::location(g, "/backup/site.zip").handler == "deny" && Router::location(g, "/backup/pic.jpg").path == "/backup/" &&
          Router::location(g, "/cache/x").handler == "deny" && Router::location(g, "/bin/grav").handler == "deny" &&
          Router::location(g, "/tests/x").handler == "deny" && Router::location(g, "/tmp/x").handler == "deny");
    const LocationConfig& guser = Router::location(g, "/user/themes/quark/blueprints.yaml");  // user/config/ is refused whole now
    CHECK(guser.path == "/user/" && guser.final && guser.handler == "static" && refuses(guser, ".yaml") && refuses(guser, ".md") &&
          refuses(guser, ".twig") && refuses(guser, ".php") && refuses(guser, ".bak") && !refuses(guser, ".xml") && !refuses(guser, ".jpg"));
    const LocationConfig& gsys = Router::location(g, "/system/config/system.yaml");
    CHECK(gsys.path == "/system/" && gsys.final && refuses(gsys, ".xml") && refuses(gsys, ".html") && refuses(gsys, ".yaml") && refuses(gsys, ".php"));
    CHECK(Router::location(g, "/vendor/autoload.php").path == "/vendor/" && refuses(Router::location(g, "/vendor/x"), ".md"));
    CHECK(Router::location(g, "/user/config/security.yaml").exact && Router::location(g, "/user/config/security.yaml").handler == "deny");
    CHECK(Router::location(g, "/LICENSE.txt").exact && Router::location(g, "/composer.json").exact && Router::location(g, "/README.md").exact);
    CHECK(Router::location(g, "/user/pages/x.jpg").protects.size() == 12 && Router::location(g, "/user/pages/x.jpg").allow_suffixes.empty());
    // The user-folder-exposure guidance: avatars alone under user/accounts, public media alone
    // under user/data (json, yaml and the rest 404 whatever exists), user/config and user/env
    // whole, webserver-configs whole, the public caches without scripts, the root's markdown.
    auto allows = [](const LocationConfig& l, const char* s) { return std::find(l.allow_suffixes.begin(), l.allow_suffixes.end(), s) != l.allow_suffixes.end(); };
    const LocationConfig& gacc = Router::location(g, "/user/accounts/avatars/admin.png");
    CHECK(gacc.path == "/user/accounts/" && gacc.final && gacc.handler == "static" && allows(gacc, ".png") && !allows(gacc, ".svg") &&
          !allows(gacc, ".yaml") && refuses(gacc, ".php") && gacc.try_files.size() == 2);
    const LocationConfig& gdata = Router::location(g, "/user/data/flex/objects/x.json");
    CHECK(gdata.path == "/user/data/" && allows(gdata, ".pdf") && allows(gdata, ".woff2") && allows(gdata, ".css") && !allows(gdata, ".json") &&
          !allows(gdata, ".svg") && gdata.allow_suffixes.size() == 25);
    CHECK(Router::location(g, "/user/config/site.css").handler == "deny" && Router::location(g, "/user/config/site.css").path == "/user/config/" &&
          Router::location(g, "/user/env").exact && Router::location(g, "/user/env").handler == "deny" &&
          Router::location(g, "/webserver-configs/nginx.conf").handler == "deny" && Router::location(g, "/SECURITY.md").handler == "deny");
    const LocationConfig& gimg = Router::location(g, "/images/x.sh");
    CHECK(gimg.path == "/images/" && gimg.final && refuses(gimg, ".sh") && refuses(gimg, ".py") && refuses(gimg, ".php") && !refuses(gimg, ".jpg") &&
          gimg.try_files.size() == 2 && gimg.try_files[1].target == "/index.php" && Router::location(g, "/assets/x.py").path == "/assets/");
    CHECK(refuses(gsys, ".json") && refuses(gsys, ".htm") && refuses(guser, ".json") && refuses(gother, ".php2"));
    // The drupal preset on the same files, the report's shape: the .zip is served, the .log is not.
    write("gravmis.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"grav\"\napp = \"drupal\"\n"
                          "php = { socket = \"unix:/run/php/fpm.sock\" }\n");
    const Config mcfg = load_config(dir / "gravmis.toml");
    CHECK(mcfg.sites[0].root == g.root && Router::location(mcfg.sites[0], "/backup/site.zip").handler == "static" &&
          refuses(Router::location(mcfg.sites[0], "/logs/grav.log"), ".log"));

    fs::remove_all(dir);
}

static void test_cidr() {
    Cidr c;
    std::string err;
    CHECK(parse_cidr("10.0.0.0/8", c, err) && !c.v6 && c.prefix == 8);
    CHECK(c.contains(asio::ip::make_address("10.200.3.4")));
    CHECK(!c.contains(asio::ip::make_address("11.0.0.1")));
    CHECK(c.contains(asio::ip::make_address("::ffff:10.1.1.1")));  // v4-mapped client
    CHECK(parse_cidr("192.168.1.5", c, err) && c.prefix == 32);
    CHECK(c.contains(asio::ip::make_address("192.168.1.5")) && !c.contains(asio::ip::make_address("192.168.1.6")));
    CHECK(parse_cidr("fd00::/8", c, err) && c.v6);
    CHECK(c.contains(asio::ip::make_address("fd12::1")) && !c.contains(asio::ip::make_address("fe80::1")));
    CHECK(!c.contains(asio::ip::make_address("10.0.0.1")));
    CHECK(parse_cidr("::1", c, err) && c.prefix == 128);
    CHECK(!parse_cidr("10.0.0.0/33", c, err) && !parse_cidr("nope", c, err) && !parse_cidr("10.0.0.0/x", c, err));
    std::vector<Cidr> list;
    parse_cidr("127.0.0.1", c, err);
    list.push_back(c);
    CHECK(in_any(list, asio::ip::make_address("127.0.0.1")) && !in_any(list, asio::ip::make_address("127.0.0.2")));
    // Suffix matching with PATH_INFO.
    CHECK(Router::suffix_hit("/index.php", ".php") && Router::suffix_hit("/a/index.php/extra/x", ".php"));
    CHECK(!Router::suffix_hit("/index.phpx", ".php") && !Router::suffix_hit("/x.php.bak", ".php"));
}

static void test_config_locations() {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("agensio-test-" + std::to_string(::getpid()));
    fs::create_directories(dir / "www" / "assets");
    auto write = [&](const char* name, const std::string& text) {
        std::ofstream(dir / name) << text;
    };
    write("ok.toml",
          "[log]\naccess = \"logs/access.log\"\nformat = \"json\"\nlevel = \"info\"\n"
          "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\ntry_files = [\"$uri\", \"=404\"]\n"
          "php = { socket = \"unix:/run/php/fpm.sock\", read_timeout = 2.5 }\n"
          "[[site.location]]\npath = \".php\"\nmatch = \"suffix\"\nhandler = \"fastcgi\"\npriority = true\n"
          "fastcgi = { buffering = false, max_connections = 2, queue_depth = 3, queue_wait = 7, "
          "priority_reserve = 0.5 }\n"
          "[[site.location]]\npath = \"/api/\"\nhandler = \"fastcgi\"\nfastcgi = { socket = \"127.0.0.1:9000\" }\n"
          "[[site.location]]\npath = \"/assets/\"\nalias = \"www/assets\"\nhidden_files = true\ntry_files = []\n"
          "[[site.location]]\npath = \"/app/\"\ntry_files = [\"$uri\", \"/index.html\"]\nsymlinks = \"deny\"\n"
          "[[site.location]]\npath = \"/exact\"\nmatch = \"exact\"\nmethods = [\"GET\", \"HEAD\"]\n");
    Config cfg = load_config(dir / "ok.toml");
    CHECK_EQ(cfg.sites.size(), 1u);
    const SiteConfig& site = cfg.sites[0];
    CHECK(cfg.log.json && cfg.log.level == "info" && cfg.log.error == "stderr");
    CHECK(cfg.log.access.size() > 16 &&
          cfg.log.access.compare(cfg.log.access.size() - 16, 16, "/logs/access.log") == 0);
    CHECK(site.access_log == cfg.log.access);  // inherited
    CHECK_EQ(site.locations.size(), 6u);  // five configured + implicit "/"
    const LocationConfig& php = Router::location(site, "/dir/x.php");
    CHECK(php.suffix && php.path == ".php" && php.kind == HandlerKind::fastcgi && php.priority);
    CHECK(php.fastcgi.address.unix && php.fastcgi.address.path == "/run/php/fpm.sock");
    CHECK(php.fastcgi.options.read_timeout == std::chrono::milliseconds(2500));  // inherited from php = {...}
    CHECK(!php.fastcgi.options.buffering && php.fastcgi.options.max_connections == 2 &&
          php.fastcgi.options.queue_depth == 3 && php.fastcgi.options.priority_reserve == 0.5);
    CHECK_EQ(php.fastcgi.retry_after, std::string("7"));
    CHECK(!php.fastcgi.params_prefix.empty() && php.fastcgi.params_prefix.find("DOCUMENT_ROOT") != std::string::npos);
    CHECK_EQ(php.allow, std::string("GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS"));
    const LocationConfig& api = Router::location(site, "/api/x");
    CHECK(api.kind == HandlerKind::fastcgi && !api.fastcgi.address.unix && api.fastcgi.address.port == 9000);
    CHECK(api.fastcgi.options.buffering && !api.priority);
    CHECK_EQ(Router::location(site, "/x.phpx").path, "/");  // suffix means the ending
    const LocationConfig& assets = Router::location(site, "/assets/a.png");
    CHECK_EQ(assets.path, "/assets/");
    CHECK(assets.root == site.root);
    CHECK(assets.alias.size() > 7 && assets.alias.compare(assets.alias.size() - 7, 7, "/assets") == 0);
    CHECK(assets.hidden_files && assets.try_files.empty() && !assets.symlinks_deny);
    const LocationConfig& app = Router::location(site, "/app/route");
    CHECK(app.root == site.root && app.try_files.size() == 2 && app.symlinks_deny);
    CHECK(Router::location(site, "/exact").exact);
    CHECK(Router::location(site, "/exact").methods == (method_bit(Method::get) | method_bit(Method::head)));
    CHECK_EQ(Router::location(site, "/exact").allow, std::string("GET, HEAD"));
    CHECK_EQ(Router::location(site, "/other").allow, std::string("GET, HEAD, OPTIONS"));
    const LocationConfig& root = Router::location(site, "/other");
    CHECK(root.path == "/" && root.try_files.size() == 2 && root.try_files[1].status == 404);  // site default

    auto rejects = [&](const char* name, const std::string& text) {
        write(name, text);
        try {
            load_config(dir / name);
        } catch (const std::runtime_error&) {
            return true;
        }
        return false;
    };
    const std::string head = "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n";
    CHECK(rejects("bad1.toml", head + "[[site.location]]\npath = \"assets/\"\n"));            // no leading '/'
    CHECK(rejects("bad2.toml", head + "[[site.location]]\npath = \"/a/\"\nhandler = \"fastcgi\"\n"));
    CHECK(rejects("bad3.toml", head + "[[site.location]]\npath = \"/a/\"\nmatch = \"regex\"\n"));
    CHECK(rejects("bad4.toml", head + "[[site.location]]\npath = \"/a/\"\n[[site.location]]\npath = \"/a/\"\n"));
    CHECK(rejects("bad5.toml", head + "[[site.location]]\npath = \"/a/\"\nroot = \"nope\"\n"));
    CHECK(rejects("bad6.toml", head + "try_files = [\"=500\"]\n"));
    CHECK(rejects("bad7.toml", head + "[[site.location]]\npath = \"/a\"\nalias = \"www\"\n"));  // alias needs '/'
    CHECK(rejects("bad9.toml", "[log]\nformat = \"csv\"\n" + head));
    // The static handler does not implement POST.
    CHECK(rejects("bad11.toml", head + "[[site.location]]\npath = \"/a/\"\nmethods = [\"POST\"]\n"));
    CHECK(rejects("bad12.toml", head + "[[site.location]]\npath = \"/a/\"\nmethods = [\"TRACE\"]\n"));
    CHECK(rejects("bad13.toml", head + "[[site.location]]\npath = \"/a/\"\nmethods = []\n"));
    CHECK(rejects("bad14.toml", head + "[[site.location]]\npath = \"/a/\"\nhandler = \"fastcgi\"\n"));  // no socket
    CHECK(rejects("bad15.toml", head + "[[site.location]]\npath = \"/a/\"\nhandler = \"fastcgi\"\n"
                                      "fastcgi = { socket = \"localhost:9000\" }\n"));
    CHECK(rejects("bad16.toml", head + "[[site.location]]\npath = \".php\"\nmatch = \"suffix\"\nalias = \"www\"\n"));
    CHECK(rejects("bad17.toml", "[server]\ntrusted_proxies = [\"10.0.0.0/40\"]\n" + head));
    write("remote.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n"
                         "php = { socket = \"127.0.0.1:9000\", remote_root = \"/var/www/html/public/\" }\n"
                         "[[site.location]]\npath = \".php\"\nmatch = \"suffix\"\nhandler = \"fastcgi\"\n");
    Config rcfg = load_config(dir / "remote.toml");
    const LocationConfig& rl = Router::location(rcfg.sites[0], "/x.php");
    CHECK_EQ(rl.fastcgi.remote_root, std::string("/var/www/html/public"));
    CHECK(decode_params(rl.fastcgi.params_prefix).find("DOCUMENT_ROOT=/var/www/html/public\n") != std::string::npos);
    CHECK(rejects("badremote.toml", head + "php = { socket = \"127.0.0.1:9000\", remote_root = \"relative\" }\n"));
    write("proxies.toml", "[server]\ntrusted_proxies = [\"127.0.0.1\", \"10.0.0.0/8\"]\n" + head);
    CHECK(load_config(dir / "proxies.toml").trusted_proxies.size() == 2);
    // Two locations on one upstream must agree on the pool bounds.
    CHECK(rejects("bad18.toml", head + "php = { socket = \"/run/a.sock\" }\n"
                                       "[[site.location]]\npath = \"/a/\"\nhandler = \"fastcgi\"\n"
                                       "fastcgi = { max_connections = 4 }\n"
                                       "[[site.location]]\npath = \"/b/\"\nhandler = \"fastcgi\"\n"
                                       "fastcgi = { max_connections = 8 }\n"));
    write("pools.toml", head + "php = { socket = \"/run/a.sock\", max_connections = 4 }\n"
                               "[[site.location]]\npath = \"/a/\"\nhandler = \"fastcgi\"\n"
                               "fastcgi = { buffering = false }\n"
                               "[[site.location]]\npath = \"/b/\"\nhandler = \"fastcgi\"\n"
                               "fastcgi = { buffer_file_max = \"2MB\" }\n");
    CHECK(load_config(dir / "pools.toml").sites[0].locations.size() == 3);
    CHECK(load_config(dir / "pools.toml").sites[0].locations[1].fastcgi.options.buffer_file_max ==
          2u * 1024 * 1024);
    // Address grammar.
    FcgiAddress a;
    std::string err;
    CHECK(parse_fcgi_address("unix:/run/x.sock", a, err) && a.unix && a.key == "unix:/run/x.sock");
    CHECK(parse_fcgi_address("/run/x.sock", a, err) && a.unix);
    CHECK(parse_fcgi_address("127.0.0.1:9000", a, err) && !a.unix && a.port == 9000 && a.key == "127.0.0.1:9000");
    CHECK(parse_fcgi_address("[::1]:9000", a, err) && a.host == "::1" && a.key == "[::1]:9000");
    CHECK(!parse_fcgi_address("php-fpm:9000", a, err));
    CHECK(!parse_fcgi_address("127.0.0.1:0", a, err));
    CHECK(!parse_fcgi_address("relative.sock", a, err));
    CHECK(status_for(FcgiFailure::pool_saturated) == 503 && status_for(FcgiFailure::read_timeout) == 504 &&
          status_for(FcgiFailure::closed_early) == 502);
    CHECK(rejects("bad10.toml", "[log]\nlevel = \"debug\"\n" + head));
    write("off.toml", "[log]\naccess = \"x.log\"\n" + head + "access_log = \"off\"\n");
    CHECK(load_config(dir / "off.toml").sites[0].access_log.empty());
    write("default.toml", head);  // no [log]: on by default, next to the config file
    CHECK(load_config(dir / "default.toml").log.access == (dir / "logs" / "access.log").string());
    CHECK(rejects("bad8.toml", head + "[[site.location]]\npath = \"/a/\"\nroot = \"www\"\nalias = \"www\"\n"));
    fs::remove_all(dir);
}

// ---- security: replay every recorded fuzz/attack input with the fuzzers' invariants ----
static void test_security_regressions() {
    namespace fs = std::filesystem;
    const fs::path base = AGENSIO_REGRESSIONS_DIR;
    std::size_t parser_files = 0, path_files = 0;

    for (const auto& entry : fs::directory_iterator(base / "parser")) {
        if (!entry.is_regular_file()) continue;
        ++parser_files;
        std::ifstream in(entry.path(), std::ios::binary);
        std::string buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        Request r;
        const auto st = parse_request(buf, r);
        if (st == ParseStatus::complete) {
            auto inside = [&](std::string_view v) {
                return v.empty() || (v.data() >= buf.data() && v.data() + v.size() <= buf.data() + buf.size());
            };
            CHECK(r.length > 0 && r.length <= buf.size());
            CHECK(inside(r.method_name) && inside(r.target) && inside(r.host) && inside(r.connection));
            CHECK(!r.target.empty() && r.target.find(' ') == std::string_view::npos);
        }
        // Known attack files must be rejected outright.
        const std::string name = entry.path().filename().string();
        if (name == "cl-te-smuggle" || name == "obs-fold") CHECK(st == ParseStatus::bad_request);
    }
    std::size_t chunked_files = 0;
    for (const auto& entry : fs::directory_iterator(base / "chunked")) {
        if (!entry.is_regular_file()) continue;
        ++chunked_files;
        std::ifstream in(entry.path(), std::ios::binary);
        std::string wire((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        for (std::size_t step : {1, 3, 4096})
            CHECK(decode_chunked(wire, step, 7, nullptr) != "<stuck>");  // never spins, never crashes
    }
    CHECK(chunked_files > 0);
    std::size_t fcgi_files = 0;
    for (const auto& entry : fs::directory_iterator(base / "fcgi")) {
        if (!entry.is_regular_file()) continue;
        ++fcgi_files;
        std::ifstream in(entry.path(), std::ios::binary);
        std::string wire((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        std::string_view rest = wire;
        for (int guard = 0; guard < 100000; ++guard) {
            std::size_t used = 0;
            fcgi::RecordHeader h;
            std::string_view content;
            const auto st = fcgi::next_record(rest, used, h, content);
            if (st != fcgi::ReadStatus::record) break;
            CHECK(used > 0 && used <= rest.size() && content.size() == h.content_length);
            rest.remove_prefix(used);
        }
        fcgi::CgiHead head;
        (void)fcgi::parse_cgi_head(wire, head);  // must not crash on any input
    }
    CHECK(fcgi_files > 0);
    for (const auto& entry : fs::directory_iterator(base / "path")) {
        if (!entry.is_regular_file()) continue;
        ++path_files;
        std::ifstream in(entry.path(), std::ios::binary);
        std::string target((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        std::string out;
        const bool ok = normalize_target(target, out);
        if (ok) {
            CHECK(!out.empty() && out[0] == '/');
            CHECK(out.find("//") == std::string::npos);
            CHECK(out.find("/./") == std::string::npos && out.find("/../") == std::string::npos);
            CHECK(!(out.size() >= 3 && out.compare(out.size() - 3, 3, "/..") == 0));
            for (unsigned char c : out)
                CHECK(c >= 0x20 && c != 0x7f);
        }
        const std::string name = entry.path().filename().string();
        if (name == "encoded-traversal" || name == "mixed-encoded" || name == "nul") CHECK(!ok);
    }
    CHECK(parser_files >= 3);
    CHECK(path_files >= 3);
}

// C3b-1: `user` on a site derives a php-fpm pool; `agensio pools` writes it.
static void test_pools() {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("agensio-pools-" + std::to_string(::getpid()));
    fs::create_directories(dir / "app" / "public");
    fs::create_directories(dir / "blog");
    fs::create_directories(dir / "pool.d");
    auto write = [&](const char* name, const std::string& text) { std::ofstream(dir / name) << text; };
    const std::string server = "[server]\nworkers = 2\ngroup = \"www\"\npools_run = \"" + dir.string() +
                               "/run\"\nstate_dir = \"" + dir.string() + "/state\"\n";
    const std::string shop = "[[site]]\nserver_name = [\"shop\"]\nlisten = [\"127.0.0.1:18090\"]\nroot = \"app\"\n"
                             "user = \"web1\"\napp = \"laravel\"\n";
    write("a.toml", server + shop + "php = { children = 6, memory_limit = \"512M\", extra = { \"date.timezone\" = \"UTC\" } }\n"
                    "[[site]]\nserver_name = [\"blog\"]\nlisten = [\"127.0.0.1:18090\"]\nroot = \"blog\"\n"
                    "user = \"web2\"\ngroup = \"client2\"\napp = \"wordpress\"\nphp = { pm = \"dynamic\", keep_conn = false, max_connections = 5 }\n");
    Config cfg = load_config(dir / "a.toml");
    const SiteConfig& a = cfg.sites[0];
    const SiteConfig& b = cfg.sites[1];
    // Derived socket, keep-alive sized to children / workers, project root in open_basedir.
    CHECK(a.pool.generated && a.pool.name == "agensio-web1" &&
          a.php.address.key == "unix:" + dir.string() + "/run/agensio-web1.sock");
    CHECK(a.php.options.keep_conn && a.php.options.max_connections == 3);
    CHECK(a.pool.open_basedir.size() == 3 && a.pool.open_basedir[0] == fs::canonical(dir / "app").string());
    CHECK(a.pool.state_dir == dir.string() + "/state/web1");
    // Hand-written FastCGI options win over the pool's defaults.
    CHECK(!b.php.options.keep_conn && b.php.options.max_connections == 5 && b.group == "client2");
    const std::string ini = render_pool(cfg, a, "www");
    for (const char* line : {"[agensio-web1]", "user = web1", "group = web1", "listen.group = www",
                             "listen.mode = 0660", "pm = ondemand", "pm.process_idle_timeout = 60s", "pm.max_children = 6", "clear_env = yes",
                             "php_admin_value[memory_limit] = 512M", "php_admin_value[date.timezone] = UTC",
                             "php_admin_value[upload_max_filesize] = 1M"})
        CHECK(ini.find(std::string(line) + "\n") != std::string::npos);
    CHECK(ini.find("php_admin_value[open_basedir] = " + a.pool.open_basedir[0] + ":") != std::string::npos);
    CHECK(render_pool(cfg, b, "www").find("pm.start_servers = 4\n") != std::string::npos);
    CHECK(generated_pools(cfg, "www").size() == 2);
    // health names the dynamic pool (what it keeps resident) and not the ondemand one.
    {
        using control::Finding;
        const auto hf = control::health_findings(cfg, cfg, false, std::time(nullptr));
        const auto resident = [&](const std::string& site) {
            return std::count_if(hf.begin(), hf.end(), [&](const Finding& f) { return f.code == "php_pool_resident" && f.site == site; });
        };
        CHECK(resident("shop") == 0 && resident("blog") == 1);
        const auto it = std::find_if(hf.begin(), hf.end(), [](const Finding& f) { return f.code == "php_pool_resident"; });
        CHECK(it != hf.end() && it->message.find("pm = dynamic: at least 4 PHP processes") != std::string::npos && it->fix.find("--set pm=ondemand") != std::string::npos);
        CHECK(control::pool_residency("agensio-no-such-pool").processes == 0);
    }

    // Writing: files appear, a rerun changes nothing, a dropped user's file is removed,
    // a foreign file with our name is refused.
    std::ostringstream log;
    CHECK(write_pools(cfg, dir / "pool.d", true, log) == 3 && !fs::exists(dir / "pool.d" / "agensio-web1.conf"));
    CHECK(write_pools(cfg, dir / "pool.d", false, log) == 3);
    CHECK(fs::is_regular_file(dir / "pool.d" / "agensio-web2.conf") && fs::is_directory(dir / "state" / "web2" / "sessions"));
    CHECK(write_pools(cfg, dir / "pool.d", false, log) == 0);
    write("b.toml", server + shop + "\n");
    Config one = load_config(dir / "b.toml");
    CHECK(write_pools(one, dir / "pool.d", false, log) == 3 && !fs::exists(dir / "pool.d" / "agensio-web2.conf") &&
          fs::exists(dir / "pool.d" / "agensio-web1.conf"));
    write("pool.d/agensio-web1.conf", "[agensio-web1]\nuser = someone\n");
    CHECK(write_pools(one, dir / "pool.d", false, log) == 1);

    // Refusals at load time.
    auto refused = [&](const char* name, const std::string& text, const char* needle) {
        write(name, text);
        try {
            load_config(dir / name);
            return false;
        } catch (const std::exception& e) {
            return std::string(e.what()).find(needle) != std::string::npos;
        }
    };
    CHECK(refused("nouser.toml", server + "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"blog\"\nphp = { socket = \"unix:/x.sock\", children = 4 }\n", "need 'user'"));
    CHECK(refused("badname.toml", server + "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"blog\"\nuser = \"../web1\"\n", "not a valid account name"));
    CHECK(refused("badpm.toml", server + shop + "php = { pm = \"forever\" }\n", "pm must be"));
    CHECK(refused("strict.toml", "[server]\nstrict_users = true\n[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"blog\"\n", "'user' is required"));
    CHECK(refused("differs.toml", server + shop + "php = { children = 6 }\n" + shop + "php = { children = 8 }\n", "php.children differs"));
    CHECK(refused("shared.toml", server + "[[site]]\nserver_name = [\"x\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"blog\"\nuser = \"web1\"\napp = \"php\"\nphp = { socket = \"unix:/one.sock\" }\n"
                                     "[[site]]\nserver_name = [\"y\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"blog\"\nuser = \"web2\"\napp = \"php\"\nphp = { socket = \"unix:/one.sock\" }\n", "different users but the same php socket"));
    // An existing pool given by hand under a user is kept as is.
    write("own.toml", server + shop + "php = { socket = \"unix:/run/php/mine.sock\" }\n");
    Config own = load_config(dir / "own.toml");
    CHECK(!own.sites[0].pool.generated && own.sites[0].php.address.key == "unix:/run/php/mine.sock" && !own.sites[0].php.options.keep_conn);
    // A site that runs no PHP derives no pool from its user (2026-09-26 live report: a Rails
    // site behind app = "proxy" got php_tmp_missing and pools_stale, and `agensio pools`
    // would have written a php-fpm pool for it); a hand-written fastcgi location still does.
    fs::create_directories(dir / "rails");
    write("rails.toml", server + "[[site]]\nserver_name = [\"rails\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"rails\"\nuser = \"ag5\"\napp = \"proxy\"\nupstream = \"http://127.0.0.1:3000\"\n"
                                 "[[site]]\nserver_name = [\"files\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"blog\"\nuser = \"web3\"\n");
    Config rails = load_config(dir / "rails.toml");
    CHECK(!rails.sites[0].pool.generated && !rails.sites[0].php.configured && rails.sites[0].pool.state_dir.empty());
    CHECK(!rails.sites[1].pool.generated && generated_pools(rails, "www").empty());
    {
        using control::Finding;
        const auto hf = control::health_findings(rails, rails, false, std::time(nullptr));
        CHECK(std::none_of(hf.begin(), hf.end(), [](const Finding& f) { return f.code == "php_tmp_missing" || f.code == "pools_stale" || f.code == "pools_dir_unknown"; }));
    }
    write("hand.toml", server + "[[site]]\nserver_name = [\"hand\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"blog\"\nuser = \"web1\"\n"
                                "[[site.location]]\npath = \".php\"\nmatch = \"suffix\"\nhandler = \"fastcgi\"\n");
    Config hand = load_config(dir / "hand.toml");
    const auto fl = std::find_if(hand.sites[0].locations.begin(), hand.sites[0].locations.end(), [](const LocationConfig& l) { return l.kind == HandlerKind::fastcgi; });
    CHECK(hand.sites[0].pool.generated && fl != hand.sites[0].locations.end() && fl->fastcgi.address.key == "unix:" + dir.string() + "/run/agensio-web1.sock");
    CHECK(refused("proxykeys.toml", server + "[[site]]\nserver_name = [\"rails\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"rails\"\nuser = \"ag5\"\napp = \"proxy\"\nupstream = \"http://127.0.0.1:3000\"\nphp = { children = 4 }\n", "need a PHP handler"));
    fs::remove_all(dir);
}

// F13: site tasks. The table, the parameter checks, the plan (argv and environment
// exactly), the output capture, the text cleaning, the interpreter rule, the runner and the
// sweep on real processes and files (as the test's own account), execute's refusals, the
// helper's validation, the [control] keys and app = "rails".
static void test_tasks() {
    namespace fs = std::filesystem;
    std::string err;
    auto js = [&](const char* text) {
        json::Value x;
        CHECK(json::parse(text, x, err));
        return x;
    };
    for (const auto& r : tasks::rows()) {
        // A program row runs an interpreter by name; a template row writes one fixed file below the site.
        if (r.writes) CHECK(!*r.runtime && !*r.program && r.args.empty() && r.content && std::string_view(r.writes).find("..") == std::string_view::npos && r.writes[0] != '/');
        else CHECK(((std::string_view(r.runtime) == "ruby" && r.timeout >= 600) || (std::string_view(r.runtime) == "python3" && r.timeout >= 300) ||
                    (std::string_view(r.runtime) == "node" && std::string_view(r.program) == "npm" && r.timeout >= 600)) &&
                   std::string_view(r.program).find('/') == std::string_view::npos);
        // A row that runs under another name runs root's interpreter as the site's virtualenv's python.
        if (r.argv0) CHECK(std::string_view(r.argv0) == "{venv}/bin/python" && std::string_view(r.runtime) == "python3" && std::string_view(r.program) == "python3");
        CHECK(tasks::find(r.app, r.name) == &r && tasks::family(r.app) != nullptr);
    }
    CHECK(tasks::names("rails").size() == 7 && tasks::names("proxy").empty() && !tasks::has_tasks("wordpress") && tasks::has_tasks("rails"));
    CHECK(tasks::find("rails", "rails_new") && !tasks::find("proxy", "rails_new") && !tasks::find("rails", "sh"));
    CHECK(tasks::all_names().size() == 21 && tasks::all_params().size() == 7);
    // Redmine: the Rails rows for an existing application and its own; never the new-application ones.
    const auto redmine = tasks::names("redmine");
    CHECK(redmine.size() == 8 && !tasks::find("redmine", "rails_new") && !tasks::find("redmine", "gem_install_rails") && tasks::find("redmine", "bundle_install") &&
          tasks::find("redmine", "database_config") && tasks::find("redmine", "gemfile_local") && !tasks::find("rails", "gemfile_local"));
    {
        const tasks::Row& ld = *tasks::find("redmine", "load_default_data");
        CHECK(tasks::check_params(ld, js(R"({"lang":"pt-BR"})")).empty() && tasks::check_params(ld, js(R"({"lang":"el"})")).empty() &&
              !tasks::check_params(ld, js(R"({"lang":"en; rm -rf /"})")).empty() && !tasks::check_params(ld, json::Value()).empty());
        tasks::Context rc;
        rc.runtime_dir = "/opt/ruby/bin";
        rc.root = "/var/www/r.test/app";
        rc.home = "/var/lib/agensio/r1";
        const tasks::Plan lp = tasks::build(ld, js(R"({"lang":"de"})"), rc, "/opt/ruby/bin/bundle");
        CHECK(lp.argv == (std::vector<std::string>{"/opt/ruby/bin/bundle", "exec", "rake", "redmine:load_default_data"}) && lp.env.back() == "REDMINE_LANG=de");
        const tasks::Row& dbc = *tasks::find("rails", "database_config");
        CHECK(std::string_view(dbc.writes) == "config/database.yml" && dbc.mode == 0600 && dbc.needs_env.size() == 1 &&
              std::string_view(dbc.content).find("ENV[\"DATABASE_URL\"]") != std::string_view::npos);
        // What exit 0 hides, and what a failure means.
        const tasks::Row& bi = *tasks::find("redmine", "bundle_install");
        CHECK(tasks::output_problem(bi, "Please configure your config/database.yml first\nBundle complete!").find("database_config") != std::string::npos &&
              tasks::output_problem(bi, "Bundle complete!").empty());
        CHECK(tasks::failure_hint(*tasks::find("redmine", "db_migrate"), "Cannot load database configuration:\nCould not load database configuration. No such file - [\"config/database.yml\"]", rc)
                  .find("database_config") != std::string::npos);
        // The summary a task's answer leads with (alpha.33 report: 68 KB of output to read).
        CHECK(tasks::summarize(*tasks::find("redmine", "db_migrate"), "== 1 A: migrating\n== 1 A: migrated (0.01s)\n== 2 B: migrated (0.1s)\n", -1) == "2 migrations applied" &&
              tasks::summarize(*tasks::find("rails", "db_migrate"), "", -1) == "no migration was pending" &&
              tasks::summarize(*tasks::find("redmine", "plugins_migrate"), "== 3 C: migrated (0.2s)\n", -1) == "1 migration applied");
        CHECK(tasks::summarize(bi, "Fetching puma\nBundle complete! 60 Gemfile dependencies, 91 gems now installed.\nBundled gems are installed into `./vendor/bundle`\n", -1) ==
                  "Bundle complete! 60 Gemfile dependencies, 91 gems now installed." &&
              tasks::summarize(*tasks::find("redmine", "load_default_data"), "Default configuration data loaded.\n", -1) == "Default configuration data loaded." &&
              tasks::summarize(*tasks::find("rails", "gem_install_rails"), "Successfully installed rails-8.0.2\n", -1).empty());
        {
            namespace fs = std::filesystem;
            const fs::path ar = fs::temp_directory_path() / ("agensio-assets-" + std::to_string(::getpid()));
            fs::create_directories(ar);
            const int afd = ::open(ar.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            const tasks::Row& ap = *tasks::find("redmine", "assets_precompile");
            CHECK(tasks::summarize(ap, "", afd).starts_with("public/assets holds no file"));
            fs::create_directories(ar / "public" / "assets" / "plugin_assets");
            std::ofstream(ar / "public" / "assets" / "application-1f2e.css") << "a";
            std::ofstream(ar / "public" / "assets" / "plugin_assets" / "x-9a.js") << "b";
            CHECK(tasks::summarize(ap, "", afd) == "public/assets holds 2 files");
            ::close(afd);
            fs::remove_all(ar);
        }
        CHECK(std::string_view(tasks::find("redmine", "gemfile_local")->content).find("puma is listed more than once") != std::string_view::npos);
    }
    // Django (2026-09-28): root's python3 run under the virtualenv's name, the site's facts in
    // the environment, the rows a wagtail site gets, the template, the summaries and hints.
    {
        const std::size_t npos = std::string::npos;
        tasks::Context dc;
        dc.runtime_dir = "/usr/bin";
        dc.root = "/var/www/w.test/app";
        dc.home = "/var/lib/agensio/w1";
        dc.app = "wagtail";
        dc.site = "w.test";
        dc.project = "mysite";
        dc.hosts = "w.test";
        dc.origins = "https://w.test";
        dc.base_url = "https://w.test";
        const std::string venv = "/var/lib/agensio/w1/venvs/w.test";
        CHECK(tasks::venv_path(dc) == venv);
        const tasks::Row& mig = *tasks::find("wagtail", "migrate");
        const tasks::Plan mp = tasks::build(mig, json::Value::object(), dc, "/usr/bin/python3.13");
        CHECK(mp.exec == "/usr/bin/python3.13" && mp.argv == (std::vector<std::string>{venv + "/bin/python", "manage.py", "migrate", "--noinput"}));
        auto has_env = [&](const std::string& e) { return std::find(mp.env.begin(), mp.env.end(), e) != mp.env.end(); };
        CHECK(has_env("DJANGO_SETTINGS_MODULE=agensio_settings") && has_env("AGENSIO_DJANGO_PROJECT=mysite") && has_env("VIRTUAL_ENV=" + venv) &&
              has_env("AGENSIO_STATIC_ROOT=/var/www/w.test/app/static") && has_env("AGENSIO_MEDIA_ROOT=/var/www/w.test/app/media") && has_env("PYTHONNOUSERSITE=1") &&
              has_env("AGENSIO_HOSTS=w.test") && has_env("AGENSIO_ORIGINS=https://w.test") && has_env("PIP_NO_INPUT=1"));
        const tasks::Plan vp = tasks::build(*tasks::find("django", "venv_create"), json::Value::object(), dc, "/usr/bin/python3.13");
        CHECK(vp.argv == (std::vector<std::string>{"/usr/bin/python3.13", "-m", "venv", venv}) && tasks::find("django", "venv_create")->needs_venv_support);
        // startproject: one name, the preset's command (wagtail start for wagtail, django-admin for django).
        const tasks::Row& ws = *tasks::find("wagtail", "startproject");
        const tasks::Plan wp = tasks::build(ws, json::Value::object(), dc, "/usr/bin/python3.13");
        CHECK(wp.argv == (std::vector<std::string>{venv + "/bin/python", venv + "/bin/wagtail", "start", "mysite", "."}) && ws.needs_empty &&
              std::string_view(ws.app) == "wagtail");
        const tasks::Row& djs = *tasks::find("django", "startproject");
        CHECK(std::string_view(djs.app) == "django" && tasks::build(djs, json::Value::object(), dc, "/x").argv[1] == venv + "/bin/django-admin");
        // pip_install: any packages, one argument each after --, shaped as requirement specifiers
        // only, and confirmed by the user in person (2026-09-28).
        const tasks::Row& pi = *tasks::find("wagtail", "pip_install");
        CHECK(pi.user_confirm && tasks::needs_user_confirmation("pip_install") && !tasks::needs_user_confirmation("pip_install_requirements") &&
              !tasks::needs_user_confirmation("migrate") && !pi.new_app_only && &pi == tasks::find("django", "pip_install"));
        CHECK(tasks::build(pi, js(R"({"packages":"wagtail==8.0 gunicorn psycopg[binary]>=3.2,<4"})"), dc, "/x").argv ==
              (std::vector<std::string>{venv + "/bin/python", "-m", "pip", "install", "--", "wagtail==8.0", "gunicorn", "psycopg[binary]>=3.2,<4"}));
        for (const char* ok : {"wagtail", "Django", "django-taggit", "zope.interface", "psycopg[binary]", "a[b,c]==1.0", "x~=2.0", "x===1.0", "x!=1.*,>=0.9",
                               "x==1.0rc1", "x==1.0.post1+local", "a b c d e f g h i j"})
            CHECK(tasks::check_params(pi, json::Value::object().set("packages", ok)).empty());
        for (const char* bad : {"", "-e", "--index-url=https://evil", "-r", "git+https://x/y", "pkg @ https://x/y.whl", "pkg@https://x", "a;b", "../x",
                                "/tmp/x.whl", "x.whl ", " x", "a  b", "a b c d e f g h i j k", "x==", "x==-1", "x[", "x[]", "x[a,]", "x>=1,", "x;python_version>'3'",
                                "x==1 --pre", "wagtail\n", "_x", "x-", "x=1"})
            if (!tasks::check_params(pi, json::Value::object().set("packages", bad)).empty() == false) {
                std::printf("pip_install accepted '%s'\n", bad);
                CHECK(false);
            }
        const std::string warn = tasks::confirmation_warning("w.test", "wagtail==8.0 psycopg[binary]", "w1", venv);
        CHECK(warn.find("https://pypi.org/project/wagtail/") != npos && warn.find("https://pypi.org/project/psycopg/") != npos && warn.find(" w1:") != npos &&
              warn.find("look-alike") != npos);
        const tasks::Row& su = *tasks::find("wagtail", "createsuperuser");
        CHECK(tasks::check_params(su, js(R"({"username":"admin","email":"a@example.com"})")).empty() &&
              !tasks::check_params(su, js(R"({"username":"-h","email":"a@example.com"})")).empty() &&
              !tasks::check_params(su, js(R"({"username":"admin","email":"a b@x.com"})")).empty() &&
              !tasks::check_params(su, js(R"({"username":"admin","email":"-x@x.com"})")).empty() && !tasks::check_params(su, js(R"({"username":"admin"})")).empty());
        CHECK(tasks::build(su, js(R"({"username":"admin","email":"a@example.com"})"), dc, "/x").argv[4] == "--username=admin" && su.needs_env.size() == 1 &&
              std::string_view(su.needs_env[0].path) == "DJANGO_SUPERUSER_PASSWORD");
        CHECK(tasks::names("wagtail").size() == 9 && tasks::names("django").size() == 9);
        const tasks::Row& ds = *tasks::find("django", "django_settings");
        const std::string_view tmpl = ds.content;
        CHECK(std::string_view(ds.writes) == "agensio_settings.py" && ds.mode == 0640 && std::string_view(ds.needs_env[0].path) == "DJANGO_SECRET_KEY" &&
              tmpl.find("SECRET_KEY = os.environ[\"DJANGO_SECRET_KEY\"]") != npos && tmpl.find("SECURE_PROXY_SSL_HEADER = (\"HTTP_X_FORWARDED_PROTO\", \"https\")") != npos &&
              tmpl.find("DEBUG = False") != npos && tmpl.find(".settings.production") != npos && tmpl.find("DATABASE_URL") != npos);
        CHECK(tasks::summarize(mig, "Operations to perform:\n  Applying a.0001_initial... OK\n  Applying b.0001_initial... OK\n", -1) == "2 migrations applied" &&
              tasks::summarize(mig, "  No migrations to apply.\n", -1) == "no migration was pending");
        // check_deploy names its checks (alpha.35 report, P4 a).
        const tasks::Row& cd = *tasks::find("django", "check_deploy");
        CHECK(tasks::summarize(cd, "System check identified some issues:\n\nWARNINGS:\n?: (security.W004) You have not set...\n?: (security.W008) Your "
                                   "SECURE_SSL_REDIRECT...\n?: (security.W012) SESSION_COOKIE_SECURE...\n?: (security.W016) You have...\n\n"
                                   "System check identified 4 issues (0 silenced).\n", -1) ==
                  "4 warnings: security.W004, security.W008, security.W012, security.W016" &&
              tasks::summarize(cd, "ERRORS:\n?: (security.E100) x\nWARNINGS:\n?: (security.W004) y\n", -1) == "1 error: security.E100; 1 warning: security.W004" &&
              tasks::summarize(cd, "System check identified no issues (2 silenced).\n", -1) == "System check identified no issues (2 silenced).");
        // The settings: https-only cookies on a TLS site, the edge's own checks silenced only where they apply (P3 b);
        // django_settings replaces agensio's own earlier version.
        CHECK(tmpl.find("SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = os.environ.get(\"AGENSIO_BASE_URL\", \"\").startswith(\"https://\")") != npos &&
              tmpl.find("(\"security.W008\", os.environ.get(\"AGENSIO_HTTPS_REDIRECT\") == \"1\")") != npos &&
              tmpl.find("(\"security.W004\", os.environ.get(\"AGENSIO_HSTS\") == \"1\")") != npos && ds.replace_own &&
              !tasks::find("rails", "database_config")->replace_own);
        dc.https_redirect = true;
        const std::vector<std::string> redirect_env = tasks::build(mig, json::Value::object(), dc, "/x").env;
        CHECK(has_env("AGENSIO_HSTS=") && std::find(redirect_env.begin(), redirect_env.end(), "AGENSIO_HTTPS_REDIRECT=1") != redirect_env.end());
        dc.https_redirect = false;
        CHECK(tasks::summarize(*tasks::find("django", "collectstatic"), "\n245 static files copied to '/x/static', 612 post-processed.\n", -1) ==
                  "245 static files copied to '/x/static', 612 post-processed." &&
              tasks::summarize(*tasks::find("django", "pip_install_requirements"), "Collecting x\nSuccessfully installed Django-6.1.1 wagtail-8.0 pillow-11.0\n", -1) ==
                  "installed 3 packages into the site's virtualenv" &&
              tasks::summarize(su, "Superuser created successfully.\n", -1) == "Superuser created successfully.");
        CHECK(tasks::failure_hint(*tasks::find("django", "venv_create"), "was not created successfully because ensurepip is not\navailable.", dc).find("python3-venv") != npos &&
              tasks::failure_hint(mig, "ModuleNotFoundError: No module named 'psycopg'", dc).find("psycopg[binary]") != npos &&
              tasks::failure_hint(mig, "ModuleNotFoundError: No module named 'agensio_settings'", dc).find("django_settings") != npos &&
              tasks::failure_hint(mig, "KeyError: 'DJANGO_SECRET_KEY'", dc).find("generate") != npos &&
              tasks::failure_hint(mig, "ModuleNotFoundError: No module named 'taggit'", dc).find("pip_install_requirements") != npos);
        // An interpreter that cannot make virtualenvs is known before venv_create runs.
        const fs::path vd = fs::temp_directory_path() / ("agensio-venvsupport-" + std::to_string(::getpid()));
        fs::create_directories(vd / "bin");
        fs::create_directories(vd / "lib" / "python3.13");
        std::string cmd;
        CHECK(tasks::venv_support((vd / "bin" / "python3.13").string(), cmd).find("ensurepip") != npos);
        fs::create_directories(vd / "lib" / "python3.13" / "ensurepip");
        std::ofstream(vd / "lib" / "python3.13" / "ensurepip" / "__init__.py") << "";
        CHECK(tasks::venv_support((vd / "bin" / "python3.13").string(), cmd).empty() && tasks::venv_support("/opt/custom/python", cmd).empty() && cmd.empty());
        fs::remove_all(vd);
    }
    // Node (2026-09-28): npm as the site's account from runtimes.node, the account's own npm cache
    // and configuration, npm ci from the lockfile, npm run by a checked script name.
    {
        const std::size_t npos = std::string::npos;
        tasks::Context nc;
        nc.runtime_dir = "/usr/bin";
        nc.root = "/var/www/n.test/app";
        nc.home = "/var/lib/agensio/n1";
        nc.app = "node";
        nc.site = "n.test";
        const tasks::Row& ci = *tasks::find("node", "npm_ci");
        const tasks::Plan cp = tasks::build(ci, json::Value::object(), nc, "/usr/share/nodejs/npm/bin/npm-cli.js");
        CHECK(cp.argv == (std::vector<std::string>{"/usr/share/nodejs/npm/bin/npm-cli.js", "ci", "--omit=dev", "--no-audit", "--no-fund"}) && ci.network &&
              !ci.user_confirm && std::string_view(ci.runtime) == "node");
        auto has = [&](const tasks::Plan& p, const std::string& e) { return std::find(p.env.begin(), p.env.end(), e) != p.env.end(); };
        CHECK(has(cp, "NODE_ENV=production") && has(cp, "NPM_CONFIG_CACHE=/var/lib/agensio/n1/.npm") && has(cp, "NPM_CONFIG_USERCONFIG=/var/lib/agensio/n1/.npmrc") &&
              has(cp, "NPM_CONFIG_UPDATE_NOTIFIER=false") && cp.env.front().starts_with("PATH=/usr/bin:"));
        const tasks::Row& run = *tasks::find("node", "npm_run");
        CHECK(tasks::build(run, js(R"({"script":"download-dist"})"), nc, "/x").argv == (std::vector<std::string>{"/x", "run", "download-dist"}));
        for (const char* ok : {"download-dist", "build", "build:prod", "start.server", "a_b"}) CHECK(tasks::check_params(run, json::Value::object().set("script", ok)).empty());
        for (const char* bad : {"", "-e", "--prefix=/", "Build", "a b", "a;b", "a/b", "$(x)"})
            CHECK(!tasks::check_params(run, json::Value::object().set("script", bad)).empty());
        CHECK(!tasks::find("rails", "npm_ci") && !tasks::find("proxy", "npm_ci") && tasks::names("node").size() == 2);
        // engines.node against the runtime's version, and the entry package.json names.
        auto m = [](const char* range, const char* v) {
            bool known = false;
            const bool ok = install::node_range_matches(range, v, known);
            return !known ? 2 : ok ? 1 : 0;
        };
        CHECK(m(">= 20.4.0", "20.19.2") == 1 && m(">= 20.4.0", "v18.19.0") == 0 && m(">=18 <21", "20.19.2") == 1 && m(">=18 <20", "20.19.2") == 0 &&
              m("^20.4", "20.19.2") == 1 && m("^20.4", "22.1.0") == 0 && m("^18 || ^20", "20.19.2") == 1 && m("^18 || ^22", "20.19.2") == 0 &&
              m("20.x", "20.19.2") == 1 && m("20", "21.0.0") == 0 && m("~20.19", "20.19.9") == 1 && m("~20.18", "20.19.2") == 0 && m("*", "20.1.0") == 1 &&
              m(">20", "20.19.2") == 0 && m(">20", "21.0.0") == 1 && m("<=20", "20.19.2") == 1 && m("=20.19.2", "20.19.2") == 1 && m("^0.2.3", "0.2.9") == 1 &&
              m("^0.2.3", "0.3.0") == 0 && m("18 - 20", "20.1.0") == 2 && m(">= 20.0.0-rc.1", "20.1.0") == 2 && m(">=20", "20.1") == 2);
        json::Value pj;
        std::string perr;
        CHECK(json::parse(R"({"name":"uptime-kuma","scripts":{"start":"npm run start-server","start-server":"node server/server.js"}})", pj, perr) &&
              install::guess_node_entry(pj) == "server/server.js");
        // An .htaccess that denies its whole directory (2026-10-01): Kanboard's two forms inside
        // <IfVersion>, not one inside <Files>, not the root's rewrite rules.
        CHECK(install::htaccess_denies_all("<IfVersion >= 2.3>\n    Require all denied\n</IfVersion>\n<IfVersion < 2.3>\n    Order allow,deny\n    Deny from all\n</IfVersion>\n") &&
              install::htaccess_denies_all("deny from all\n") && install::htaccess_denies_all("  REQUIRE   ALL   DENIED  \r\n") &&
              install::htaccess_denies_all("<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n") &&
              !install::htaccess_denies_all("<Files \"*.log\">\nRequire all denied\n</Files>\n") &&
              !install::htaccess_denies_all("<FilesMatch \"\\.(ini|log)$\">\n  Deny from all\n</FilesMatch>\nOptions -Indexes\n") &&
              !install::htaccess_denies_all("RewriteEngine On\nRewriteRule ^ index.php [QSA,L]\n") && !install::htaccess_denies_all("# Require all denied\n") &&
              !install::htaccess_denies_all("Require all granted\n") && !install::htaccess_denies_all(""));
        // app_facts walks the installed tree for them: a parent covers its children, dot directories
        // and <Files> blocks are skipped, the root's own .htaccess is not a directory denial.
        {
            const std::filesystem::path ft = std::filesystem::temp_directory_path() / ("agensio-facts-" + std::to_string(::getpid()));
            std::filesystem::remove_all(ft);
            for (const char* d : {"app/Core", "assets", "data", "vendor/sub", ".hidden", "plain"}) std::filesystem::create_directories(ft / d);
            const char* deny = "<IfVersion >= 2.3>\n    Require all denied\n</IfVersion>\n<IfVersion < 2.3>\n    Order allow,deny\n    Deny from all\n</IfVersion>\n";
            std::ofstream(ft / ".htaccess") << "RewriteEngine On\nRewriteRule ^ index.php [QSA,L]\n";
            std::ofstream(ft / "app" / ".htaccess") << deny;
            std::ofstream(ft / "app" / "Core" / ".htaccess") << deny;
            std::ofstream(ft / "data" / ".htaccess") << deny;
            std::ofstream(ft / "vendor" / "sub" / ".htaccess") << "Deny from all\n";
            std::ofstream(ft / ".hidden" / ".htaccess") << deny;
            std::ofstream(ft / "assets" / ".htaccess") << "<Files \"*.log\">\nRequire all denied\n</Files>\n";
            std::ofstream(ft / "index.php") << "<?php\n";
            const int ffd = ::open(ft.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            CHECK(ffd >= 0);
            const json::Value facts = install::app_facts(ffd, "", "");
            ::close(ffd);
            std::string got;
            for (const auto& x : facts["htaccess_denied"].items()) got += std::string(x.str()) + " ";
            CHECK(got == "app data vendor/sub ");
            std::filesystem::remove_all(ft);
        }
        CHECK(json::parse(R"({"scripts":{"start":"node ./index.mjs --port 3"}})", pj, perr) && install::guess_node_entry(pj) == "index.mjs");
        CHECK(json::parse(R"({"main":"lib/app.js","scripts":{"start":"next start"}})", pj, perr) && install::guess_node_entry(pj) == "lib/app.js");
        CHECK(json::parse(R"({"main":"../x.js","scripts":{"start":"node /etc/x.js"}})", pj, perr) && install::guess_node_entry(pj).empty());
        CHECK(tasks::summarize(ci, "npm WARN deprecated x\nadded 512 packages in 45s\n", -1) == "added 512 packages in 45s" &&
              tasks::summarize(ci, "up to date in 2s\n", -1) == "up to date in 2s");
        CHECK(tasks::failure_hint(ci, "npm ERR! The `npm ci` command can only install with an existing package-lock.json", nc).find("lockfile") != npos &&
              tasks::failure_hint(run, "npm ERR! Missing script: \"dist\"\n", nc).find("no script \"dist\"") != npos &&
              tasks::failure_hint(ci, "npm ERR! notsup Unsupported engine for x", nc).find("runtimes.node") != npos &&
              tasks::failure_hint(ci, "gyp ERR! stack Error", nc).find("build-essential") != npos);
    }
    const tasks::Row& gem = *tasks::find("rails", "gem_install_rails");
    const tasks::Row& fresh = *tasks::find("rails", "rails_new");
    const tasks::Row& prep = *tasks::find("rails", "db_prepare");
    // Parameters: typed, never options.
    CHECK(tasks::check_params(fresh, js(R"({"name":"blog"})")).empty() && tasks::check_params(fresh, js(R"({"name":"Blog_2"})")).empty());
    CHECK(tasks::check_params(fresh, js("{}")).find("needs the parameter name") != std::string::npos);
    CHECK(tasks::check_params(fresh, json::Value()).find("needs the parameter name") != std::string::npos);
    for (const char* bad : {R"({"name":"2blog"})", R"({"name":"-m"})", R"({"name":"a b"})", R"({"name":"a;b"})", R"({"name":"a/b"})", R"({"name":""})", R"({"name":5})"})
        CHECK(!tasks::check_params(fresh, js(bad)).empty());
    CHECK(!tasks::check_params(fresh, json::Value::object().set("name", std::string(65, 'a'))).empty());
    CHECK(tasks::check_params(fresh, js(R"({"name":"blog","template":"https://x"})")).find("takes no parameter 'template'") != std::string::npos);
    CHECK(tasks::check_params(prep, js(R"({"x":"y"})")).find("it takes none") != std::string::npos);
    CHECK(tasks::check_params(fresh, js("[1]")).find("must be an object") != std::string::npos);
    CHECK(tasks::check_params(gem, json::Value()).empty() && tasks::check_params(gem, js(R"({"version":"8.1.4"})")).empty() && tasks::check_params(gem, js(R"({"version":"8.0"})")).empty());
    for (const char* bad : {"7.1.0", "8", "8.", "8..1", "8.1.4.5.6", "8.1a", "-v", "8.1.99999", "80.1", "8.1 ", " 8.1"})
        CHECK(!tasks::check_params(gem, json::Value::object().set("version", bad)).empty());
    // The plan: argv and the whole environment, exactly.
    tasks::Context ctx;
    ctx.runtime_dir = "/usr/bin";
    ctx.root = "/var/www/r.test/app";
    ctx.home = "/var/lib/agensio/r1";
    tasks::Plan pl = tasks::build(gem, json::Value(), ctx, "/usr/bin/gem");
    CHECK(pl.argv == (std::vector<std::string>{"/usr/bin/gem", "install", "rails", "--no-document", "--version", "~> 8.0"}));
    pl = tasks::build(gem, js(R"({"version":"8.1.4"})"), ctx, "/usr/bin/gem3.3");
    CHECK(pl.argv == (std::vector<std::string>{"/usr/bin/gem3.3", "install", "rails", "--no-document", "--version", "8.1.4"}));
    pl = tasks::build(fresh, js(R"({"name":"blog"})"), ctx, "/usr/bin/ruby3.3");
    CHECK(pl.argv == (std::vector<std::string>{"/usr/bin/ruby3.3", "/var/lib/agensio/r1/gems/bin/rails", "new", ".", "--name=blog", "--database=sqlite3", "--skip-git",
                                               "--skip-docker", "--skip-thruster", "--skip-ci"}));
    CHECK(pl.env == (std::vector<std::string>{"PATH=/usr/bin:/usr/local/bin:/bin", "HOME=/var/lib/agensio/r1", "TMPDIR=/var/lib/agensio/r1/tmp", "LANG=C.UTF-8",
                                              "RAILS_ENV=production", "GEM_HOME=/var/lib/agensio/r1/gems", "GEM_PATH=/var/lib/agensio/r1/gems",
                                              "BUNDLE_PATH=vendor/bundle", "BUNDLE_WITHOUT=development:test"}));
    CHECK(pl.cwd == "/var/www/r.test/app" && pl.timeout == 1200 && pl.processes == 512 && pl.open_files == 4096);
    ctx.runtime_dir = "/opt/ruby/bin";
    ctx.timeout = 300;
    pl = tasks::build(*tasks::find("rails", "assets_precompile"), json::Value(), ctx, "/opt/ruby/bin/bundle");
    CHECK(pl.argv == (std::vector<std::string>{"/opt/ruby/bin/bundle", "exec", "rails", "assets:precompile"}) &&
          pl.env.front() == "PATH=/opt/ruby/bin:/usr/local/bin:/usr/bin:/bin" && pl.env.back() == "SECRET_KEY_BASE_DUMMY=1" && pl.timeout == 300);
    // The site's environment comes last and never replaces a variable agensio set.
    ctx.app_env = {{"SECRET_KEY_BASE", "abc"}, {"RAILS_ENV", "development"}, {"DATABASE_URL", "sqlite3:x"}};
    pl = tasks::build(prep, json::Value(), ctx, "/opt/ruby/bin/bundle");
    CHECK(pl.env.size() == 11 && pl.env[9] == "SECRET_KEY_BASE=abc" && pl.env[10] == "DATABASE_URL=sqlite3:x" &&
          std::count(pl.env.begin(), pl.env.end(), std::string("RAILS_ENV=production")) == 1 &&
          std::none_of(pl.env.begin(), pl.env.end(), [](const std::string& e) { return e == "RAILS_ENV=development"; }));
    ctx.app_env.clear();
    // Known causes of a failure get a hint naming the fix (2026-09-27 Writebook report).
    CHECK(tasks::failure_hint(prep, "ArgumentError: Missing `secret_key_base` for 'production' environment", ctx).find("generate: [\"SECRET_KEY_BASE\"]") != std::string::npos);
    CHECK(tasks::failure_hint(gem, "Your Ruby version is 3.3.8, but your Gemfile specified 3.4.7", ctx).find("ruby = \"/opt/ruby/bin\"") != std::string::npos);
    CHECK(tasks::failure_hint(prep, "Could not find gem 'pg'", ctx).empty() && tasks::failure_hint(prep, "Your Ruby version is 3.3.8", ctx).empty());
    const json::Value cat = tasks::catalog("rails");
    CHECK(cat.items().size() == 7 && cat.items()[1].get("task") == "rails_new" && cat.items()[1]["needs_empty"].boolean() &&
          cat.items()[6].get("writes") == "config/database.yml" && cat.items()[6].get("mode") == "0600" &&
          cat.items()[1]["params"].items()[0].get("name") == "name" && tasks::catalog("static").items().empty());
    // Output: head and tail, the cut named.
    {
        tasks::Capture c(8, 8);
        c.add("hello", 5);
        CHECK(c.text() == "hello" && !c.truncated());
        c.add(" world, and more", 16);
        CHECK(c.total() == 21 && c.truncated() && c.text() == "hello wo\n[... 5 bytes not shown ...]\nand more");
        tasks::Capture big;
        const std::string chunk(1000, 'x');
        for (int i = 0; i < 300; ++i) big.add(chunk.data(), chunk.size());
        CHECK(big.total() == 300000 && big.truncated() && big.text().size() < 16 * 1024 + 48 * 1024 + 64);
    }
    CHECK(tasks::clean_text("ok\n") == "ok\n" && tasks::clean_text("\x1b[32mgreen\x1b[0m") == "green" && tasks::clean_text("caf\xc3\xa9") == "caf\xc3\xa9");
    CHECK(tasks::clean_text("a\xff" "b") == "a\xEF\xBF\xBD" "b" && tasks::clean_text("\xe2\x82") == "\xEF\xBF\xBD\xEF\xBF\xBD" && tasks::clean_text("\xc0\xaf") == "\xEF\xBF\xBD\xEF\xBF\xBD");
    CHECK(tasks::clean_text("\xed\xa0\x80") == "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD");
    // The interpreter rule: /bin/sh is root's wherever this runs.
    std::string canonical;
    bool missing = false;
    CHECK(tasks::trusted_program("/bin/sh", "/var/www", canonical, missing).empty() && !canonical.empty() && canonical[0] == '/');
    CHECK(tasks::trusted_program("/bin/sh", "/", canonical, missing).find("below sites_root") != std::string::npos);
    CHECK(tasks::trusted_program("/usr/bin/agensio-no-such-ruby", "/var/www", canonical, missing).find("No such file") != std::string::npos && missing);
    CHECK(!tasks::trusted_program("bin/sh", "/var/www", canonical, missing).empty());
    const fs::path dir = fs::temp_directory_path() / ("agensio-tasks-" + std::to_string(::getpid()));
    fs::create_directories(dir / "site");
    fs::create_directories(dir / "empty");
    const bool root = ::geteuid() == 0;
    if (!root) {
        std::ofstream(dir / "ruby") << "#!/bin/sh\n";
        fs::permissions(dir / "ruby", fs::perms::owner_all);
        // Refused at the first component root alone does not control (/tmp is world-writable).
        const std::string why = tasks::trusted_program((dir / "ruby").string(), "/var/www", canonical, missing);
        CHECK((why.find("not root") != std::string::npos || why.find("writable by its group or by others") != std::string::npos) && !missing);
        fs::create_symlink("/bin/sh", dir / "sh-link");  // a name someone else controls: refused, whatever it points at
        CHECK(!tasks::trusted_program((dir / "sh-link").string(), "/var/www", canonical, missing).empty());
    }
    // The runner on real processes.
    const int site_fd = ::open((dir / "site").c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    tasks::Plan sh;
    sh.argv = {"/bin/sh", "-c", "echo out; echo err >&2; pwd; echo \"HOME=$HOME X=${X:-unset}\"; umask; exit 3"};
    sh.env = {"PATH=/usr/bin:/bin", "HOME=/nowhere"};
    sh.cwd = (dir / "site").string();
    sh.timeout = 20;
    sh.processes = 1 << 20;  // RLIMIT_NPROC counts every thread of this account, and a desktop has thousands
    ::setenv("X", "leaked", 1);
    json::Value res = tasks::run(sh, site_fd);
    ::unsetenv("X");
    std::string out(res.get("output"));
    CHECK(res["exit"].num() == 3 && !res["timed_out"].boolean() && out.find("out\n") != std::string::npos && out.find("err\n") != std::string::npos);
    CHECK(out.find(fs::canonical(dir / "site").string() + "\n") != std::string::npos && out.find("HOME=/nowhere X=unset") != std::string::npos && out.find("0027") != std::string::npos);
    sh.argv = {"/bin/sh", "-c", "trap '' TERM; echo started; sleep 30; echo never"};
    sh.timeout = 1;
    sh.term_grace = 1;
    auto t0 = std::chrono::steady_clock::now();
    res = tasks::run(sh, site_fd);
    auto took = std::chrono::steady_clock::now() - t0;
    CHECK(res["timed_out"].boolean() && res["signal"].num() == SIGKILL && std::string(res.get("output")) == "started\n" && took < std::chrono::seconds(8));
    sh.argv = {"/bin/sh", "-c", "(sleep 30; echo late) & echo done"};
    sh.timeout = 20;
    sh.drain = 1;
    t0 = std::chrono::steady_clock::now();
    res = tasks::run(sh, site_fd);
    took = std::chrono::steady_clock::now() - t0;
    CHECK(res["exit"].num() == 0 && std::string(res.get("output")) == "done\n" && took < std::chrono::seconds(5));
    sh.argv = {"/bin/sh", "-c", "i=0; while [ $i -lt 2000 ]; do echo 0123456789012345678901234567890123456789012345678901234567890123456789; i=$((i+1)); done"};
    res = tasks::run(sh, site_fd);
    // Up to 1 MB is kept whole (the handler trims the answer and keeps this for site_task_output);
    // beyond it the first 256 KB and the last 768 KB.
    CHECK(res["output_bytes"].num() == 142000 && !res["truncated"].boolean() && std::string(res.get("output")).size() == 142000);
    sh.argv = {"/bin/sh", "-c", "i=0; while [ $i -lt 16000 ]; do echo 0123456789012345678901234567890123456789012345678901234567890123456789; i=$((i+1)); done"};
    res = tasks::run(sh, site_fd);
    CHECK(res["output_bytes"].num() == 1136000 && res["truncated"].boolean() && std::string(res.get("output")).find("bytes not shown") != std::string::npos &&
          std::string(res.get("output")).size() < 1024 * 1024 + 200);
    sh.argv = {"/nonexistent/program"};
    res = tasks::run(sh, site_fd);
    CHECK(res["exit"].num() == 127 && std::string(res.get("output")).find("could not be executed") != std::string::npos);
    // The sweep: the rule's list and the preset's patterns; files 0600, directories without
    // their group's read; never through a symlink.
    fs::create_directories(dir / "site/config/credentials");
    fs::create_directories(dir / "site/storage");
    fs::create_directories(dir / "site/db");
    fs::create_directories(dir / "site/.kamal");
    for (const char* f : {"config/master.key", "config/database.yml", "config/credentials/production.key", ".env.production", "db/dev.sqlite3",
                          "storage/production.sqlite3", "storage/production.sqlite3-wal", ".kamal/secrets", "Gemfile"}) {
        std::ofstream(dir / "site" / f) << "x";
        ::chmod((dir / "site" / f).c_str(), 0644);
    }
    ::chmod((dir / "site/storage").c_str(), 02750);
    ::chmod((dir / "site/config/credentials").c_str(), 0755);
    fs::create_symlink("/etc/hostname", dir / "site/.env");
    const std::vector<std::string> rule{"config/master.key", "config/credentials", "config/database.yml", "storage", ".env", ".git"};
    const json::Value sw = tasks::sweep(site_fd, (dir / "site").string(), rule, tasks::family("rails")->secret_patterns);
    auto mode = [&](const char* f) {
        struct stat st {};
        ::lstat((dir / "site" / f).c_str(), &st);
        return st.st_mode & 07777;
    };
    CHECK(mode("config/master.key") == 0600 && mode("config/database.yml") == 0600 && mode("config/credentials/production.key") == 0600 && mode(".env.production") == 0600);
    CHECK(mode("db/dev.sqlite3") == 0600 && mode("storage/production.sqlite3") == 0600 && mode("storage/production.sqlite3-wal") == 0600 && mode("Gemfile") == 0644);
    CHECK(mode("storage") == 02710 && mode("config/credentials") == 0710 && mode(".kamal/secrets") == 0600 && fs::is_symlink(dir / "site/.env"));
    CHECK(sw["exposed"].items().empty() && sw["secured"].items().size() == 10);
    CHECK(tasks::sweep(site_fd, (dir / "site").string(), rule, tasks::family("rails")->secret_patterns)["secured"].items().empty());
    CHECK(secret_dir_mode(02750) == 02710 && secret_dir_mode(0755) == 0710 && secret_dir_mode(0700) == 0700 && !secret_exposed(02710, 33, 1001));
    ::close(site_fd);
    // Needs and produces (2026-09-27 report): rails_new needs the rails command the earlier
    // task installs, the bundle tasks need the application, gem_install_rails must leave the
    // command behind; each named with what to do.
    {
        tasks::Context nc;
        nc.root = (dir / "empty").string();
        nc.home = (dir / "needs-home").string();
        const int empty_fd = ::open(nc.root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        const std::string no_rails = tasks::check_needs(fresh, js(R"({"name":"blog"})"), nc, empty_fd);
        CHECK(no_rails.find("task rails_new needs " + nc.home + "/gems/bin/rails, which does not exist; run gem_install_rails first") == 0);
        CHECK(tasks::check_needs(gem, json::Value(), nc, empty_fd, true).find("task gem_install_rails exited 0, but " + nc.home + "/gems/bin/rails does not exist") == 0);
        CHECK(tasks::check_needs(prep, json::Value(), nc, empty_fd).find("task db_prepare needs " + nc.root + "/Gemfile, which does not exist; the site's directory holds no application yet") == 0);
        CHECK(tasks::check_needs(gem, json::Value(), nc, empty_fd).empty());  // it needs nothing
        fs::create_directories(dir / "needs-home/gems/bin");
        std::ofstream(dir / "needs-home/gems/bin/rails") << "#!/usr/bin/env ruby\n";
        CHECK(tasks::check_needs(fresh, js(R"({"name":"blog"})"), nc, empty_fd).empty() && tasks::check_needs(gem, json::Value(), nc, empty_fd, true).empty());
        ::close(empty_fd);
        nc.root = (dir / "site").string();  // holds a Gemfile (the sweep section made one)
        const int app_fd = ::open(nc.root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK(tasks::check_needs(prep, json::Value(), nc, app_fd).empty() && tasks::check_needs(*tasks::find("rails", "assets_precompile"), json::Value(), nc, app_fd).empty());
        ::close(app_fd);
    }
    // The listing a site's tasks answer with: the effective time limit (the row's, capped by
    // root's ceiling) and each interpreter's state.
    {
        tasks::CatalogContext cc;
        cc.timeout_cap = 1200;
        cc.runtime_dir = [](std::string_view) { return std::string("/nonexistent-agensio-runtime"); };
        cc.sites_root = "/var/www";
        const json::Value listed = tasks::catalog("rails", &cc);
        CHECK(listed.items().size() == 7 && listed.items()[1].get("task") == "rails_new" && listed.items()[1]["timeout"].num() == 1200 &&
              listed.items()[6]["interpreter"].is_null() &&  // a template row runs no interpreter
              listed.items()[3]["timeout"].num() == 1200);  // db_prepare's own 1800 is capped too
        const json::Value& in = listed.items()[0]["interpreter"];
        CHECK(in.get("program") == "/nonexistent-agensio-runtime/gem" && !in["ok"].boolean() && !in.get("error").empty());
        cc.timeout_cap = 7200;
        CHECK(tasks::catalog("rails", &cc).items()[1]["timeout"].num() == 3600);  // a higher ceiling never raises a row
        CHECK(tasks::catalog("rails").items()[1]["interpreter"].is_null());
    }
    // execute's refusals, each before anything runs.
    tasks::Request tr;
    tr.row = &fresh;
    tr.params = js(R"({"name":"blog"})");
    tr.ctx.runtime_dir = "/bin";
    tr.ctx.root = (dir / "site").string();
    tr.ctx.home = (dir / "home").string();
    tr.sites_root = "/var/www";
    tr.dry_run = true;
    if (!root) {
        CHECK(std::string(tasks::execute(tr).get("error")).find("creates the application in an empty directory") != std::string::npos);
        tr.ctx.root = (dir / "empty").string();
        // A runtime directory that exists nowhere: GitHub's Ubuntu runners have a root-owned
        // /bin/ruby (Ruby preinstalled, /bin merged into /usr/bin), so /bin cannot stand for
        // "no interpreter here" (the alpha.24 release job, 2026-09-27).
        tr.ctx.runtime_dir = "/nonexistent-agensio-runtime";
        const json::Value e = tasks::execute(tr);
        CHECK(!e["ok"].boolean() && std::string(e.get("error")).find("the ruby runtime: /nonexistent-agensio-runtime") != std::string::npos && !e.get("hint").empty());
        tr.ctx.runtime_dir = "/bin";
        tr.ctx.root = "/";
        CHECK(std::string(tasks::execute(tr).get("error")).find("belongs to root, not to the account running the task") != std::string::npos);
        tr.ctx.root = (dir / "empty").string();
        tr.params = js(R"({"name":"-m"})");
        CHECK(std::string(tasks::execute(tr).get("error")).find("does not match") != std::string::npos);
        tr.row = &gem;
        tr.params = json::Value();
        tr.network_allowed = false;
        CHECK(std::string(tasks::execute(tr).get("error")).find("task_network = false") != std::string::npos);
        CHECK(!fs::exists(dir / "home"));  // a dry run creates nothing
    }
    // The helper's validation: names and short string parameters only.
    CHECK(provision::validate(js(R"({"op":"task_run","site":"r.test","task":"rails_new","params":{"name":"blog"},"dry_run":true})"), Config{}).empty());
    CHECK(provision::validate(js(R"({"op":"task_run","site":"r.test","task":"db_prepare"})"), Config{}).empty());
    for (const char* bad : {R"({"op":"task_run","site":"../etc","task":"db_prepare"})", R"({"op":"task_run","site":"r.test","task":"Rails-New"})",
                            R"({"op":"task_run","site":"r.test","task":""})", R"({"op":"task_run","site":"r.test","task":"db_prepare","params":"name=x"})",
                            R"({"op":"task_run","site":"r.test","task":"db_prepare","params":{"name":5}})", R"({"op":"task_run","site":"r.test","task":"db_prepare","dry_run":"yes"})"})
        CHECK(!provision::validate(js(bad), Config{}).empty());
    // [control] runtimes, task_limits, task_network; app = "rails".
    fs::create_directories(dir / "app");
    auto write = [&](const char* name, const std::string& text) { std::ofstream(dir / name) << text; };
    const std::string rails = "[[site]]\nserver_name = [\"r.test\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"app\"\nuser = \"r1\"\napp = \"rails\"\nupstream = \"http://127.0.0.1:3000\"\n";
    write("t.toml", "[control]\nruntimes = { ruby = \"/opt/ruby/bin/\" }\ntask_limits = { timeout = 60, processes = 100 }\ntask_network = false\n" + rails);
    const Config cfg = load_config(dir / "t.toml");
    CHECK(cfg.control.runtimes.ruby == "/opt/ruby/bin" && cfg.control.runtimes.node == "/usr/bin" && cfg.control.task_timeout == 60 && cfg.control.task_processes == 100 &&
          !cfg.control.task_network);
    CHECK(runtime_dir(cfg.control, "ruby") == "/opt/ruby/bin" && runtime_dir(cfg.control, "perl").empty());
    const SiteConfig& rs = cfg.sites[0];
    CHECK(rs.app == "rails" && !rs.pool.generated && proxy_app("rails") && proxy_app("proxy") && !proxy_app("laravel") && php_app("laravel") && !php_app("rails"));
    const auto rl = std::find_if(rs.locations.begin(), rs.locations.end(), [](const LocationConfig& l) { return l.path == "/"; });
    CHECK(rl != rs.locations.end() && rl->kind == HandlerKind::proxy && rl->origin == "preset:rails");
    // The paths scanners probe are answered 404 at the edge, never proxied to Puma.
    auto refused_at = [&](const char* path, bool exact) {
        const auto it = std::find_if(rs.locations.begin(), rs.locations.end(), [&](const LocationConfig& l) { return l.path == path && l.exact == exact; });
        return it != rs.locations.end() && it->handler == "deny" && it->kind == HandlerKind::static_ && it->origin == "preset:rails";
    };
    CHECK(refused_at("/config/master.key", true) && refused_at("/.env", true) && refused_at("/Gemfile.lock", true) && refused_at("/config/credentials/", false) &&
          refused_at("/.kamal/", false));
    CHECK(Router::location(rs, "/config/master.key").handler == "deny" && Router::location(rs, "/config/credentials/production.key").handler == "deny" &&
          Router::location(rs, "/config").kind == HandlerKind::proxy && Router::location(rs, "/storage/db/production.sqlite3").handler == "deny" &&
          Router::location(rs, "/storage/files/ab/cd/abcdef").handler == "deny");
    // Databases, logs and keys by their ending wherever an application keeps them: the proxy
    // location carries the endings and the dispatcher answers 404 (2026-09-27 report).
    const LocationConfig& up = Router::location(rs, "/db/production.sqlite3");
    CHECK(up.kind == HandlerKind::proxy && refused_suffix("/db/production.sqlite3", up.deny_suffixes) && refused_suffix("/log/development.log", up.deny_suffixes) &&
          refused_suffix("/db/x.SQLITE3-WAL", up.deny_suffixes) && refused_suffix("/config/credentials/production.key", up.deny_suffixes) &&
          refused_suffix("/backup.sql", up.deny_suffixes) && !refused_suffix("/books/1-logs", up.deny_suffixes) && !refused_suffix("/rails/active_storage/disk/x/cover.png", up.deny_suffixes));
    // A refused body names the site, the sizes and the fix in the error log.
    CHECK(body_refused_text(&rs, "192.0.2.7", 2883584, 1048576) ==
          "site r.test: a request body of 2.8 MB from 192.0.2.7 refused with 413: its max_body_size is 1 MB (the server's default); site_update with settings {max_body_size} raises it, up to [control] site_limits");
    CHECK(body_refused_text(nullptr, "-", 5000, 1024) == "a request body of 4.9 KB from - refused with 413: above the server's max_body_size of 1 KB");
    // The Puma unit rendered for root (2026-09-27 Redmine report): the Ruby of [control]
    // runtimes on PATH and in ExecStart, the site's account, directory, loopback port and
    // environment file; refused for a site without its own account or a non-loopback upstream,
    // and for any value that could add a line to the unit.
    {
        const json::Value u = control::service_unit(rs, cfg);
        const std::string text(u.get("unit"));
        CHECK(u["ok"].boolean() && u.get("unit_name") == "agensio-app-r1.service" && text.find("User=r1\nGroup=r1\n") != std::string::npos &&
              text.find("Environment=PATH=/opt/ruby/bin:/usr/local/bin:/usr/bin:/bin\n") != std::string::npos &&
              text.find("ExecStart=/opt/ruby/bin/bundle exec puma -e production -b tcp://127.0.0.1:3000\n") != std::string::npos &&
              text.find("WorkingDirectory=" + rs.root + "\n") != std::string::npos && text.find("EnvironmentFile=-" + (dir / "env").string() + "/r.test.env\n") != std::string::npos &&
              u["run_as_root"].items()[0].str() == "agensio ctl site-unit r.test --raw > /etc/systemd/system/agensio-app-r1.service");
        SiteConfig nouser = rs;
        nouser.user.clear();
        CHECK(control::service_unit(nouser, cfg).get("error").find("no account of its own") != std::string_view::npos);
        SiteConfig remote = rs;
        remote.proxy.address.host = "10.0.0.5";
        CHECK(control::service_unit(remote, cfg).get("error").find("loopback") != std::string_view::npos);
        SiteConfig odd = rs;
        odd.root = rs.root + "\nExecStartPre=/bin/sh -c id";
        if (!odd.project_root.empty()) odd.project_root = odd.root;
        CHECK(!control::service_unit(odd, cfg)["ok"].boolean() && control::service_unit(odd, cfg).get("unit").empty());
        SiteConfig php = rs;
        php.app = "wordpress";
        CHECK(!control::service_unit(php, cfg)["ok"].boolean());
    }
    const auto rsec = secret_paths(rs);
    CHECK(std::find(rsec.begin(), rsec.end(), rs.root + "/config/master.key") != rsec.end() && std::find(rsec.begin(), rsec.end(), rs.root + "/storage") != rsec.end());
    write("d.toml", rails);
    const Config def = load_config(dir / "d.toml");
    CHECK(def.control.runtimes.ruby == "/usr/bin" && def.control.task_timeout == 1200 && def.control.task_processes == 512 && def.control.task_network);
    auto refused = [&](const std::string& text, const char* needle) {
        write("bad.toml", text);
        try {
            load_config(dir / "bad.toml");
            return false;
        } catch (const std::exception& e) {
            const bool hit = std::string(e.what()).find(needle) != std::string::npos;
            if (!hit) std::printf("tasks config: expected '%s', got '%s'\n", needle, e.what());
            return hit;
        }
    };
    CHECK(version_mismatch_note("0.1.0-alpha.26", "0.1.0-alpha.26").empty() && version_mismatch_note("0.1.0-alpha.26", "").empty());
    const std::string note = version_mismatch_note("0.1.0-alpha.23", "0.1.0-alpha.26");
    CHECK(note.find("bridge is agensio 0.1.0-alpha.23 and the server runs 0.1.0-alpha.26") != std::string::npos && note.find("reconnect this MCP server") != std::string::npos &&
          note.find("systemctl restart agensio") != std::string::npos);
    CHECK(refused("[control]\nruntimes = { ruby = \"usr/bin\" }\n" + rails, "must be an absolute directory"));
    CHECK(refused("[control]\nruntimes = { perl = \"/usr/bin\" }\n" + rails, "unknown runtime \"perl\""));
    CHECK(refused("[control]\nruntimes = { ruby = \"/var/www/x/bin\" }\n" + rails, "below sites_root"));
    CHECK(refused("[control]\nruntimes = \"/usr/bin\"\n" + rails, "control.runtimes must be a table"));
    CHECK(refused("[control]\ntask_limits = { timeout = 1 }\n" + rails, "5 to 86400"));
    CHECK(refused("[control]\ntask_limits = { processes = 8 }\n" + rails, "16 to 65536"));
    CHECK(refused("[control]\ntask_limits = { timeout = 60, memory = 5 }\n" + rails, "unknown key \"memory\""));
    CHECK(refused("[[site]]\nlisten = [\"127.0.0.1:1\"]\napp = \"rails\"\nupstream = \"http://127.0.0.1:3000\"\n", "'root' is required"));
    CHECK(refused("[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"app\"\napp = \"rails\"\n", "app = \"rails\" needs upstream"));
    CHECK(refused(rails + "php = { children = 4 }\n", "need a PHP handler"));
    // Django and Wagtail (2026-09-28): /static/ and /media/ from the project directory, the
    // rest to Gunicorn; project required and checked; what the settings are told; the unit.
    {
        const std::size_t npos = std::string::npos;
        const std::string wag = "[[site]]\nserver_name = [\"w.test\", \"*.w.test\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"app\"\nuser = \"w1\"\napp = \"wagtail\"\n"
                                "project = \"mysite\"\nupstream = \"http://127.0.0.1:3008\"\n";
        write("w.toml", "[control]\nruntimes = { python3 = \"/opt/py/bin\" }\n" + wag);
        const Config wc = load_config(dir / "w.toml");
        const SiteConfig& ws = wc.sites[0];
        CHECK(ws.project == "mysite" && proxy_app("wagtail") && python_app("django") && !python_app("rails") && service_app("wagtail") && service_app("redmine") &&
              !service_app("proxy"));
        const LocationConfig& st = Router::location(ws, "/static/css/app.1a2b.css");
        const LocationConfig& me = Router::location(ws, "/media/original_images/x.png");
        CHECK(st.kind == HandlerKind::static_ && st.handler == "static" && st.root == ws.root && st.add_headers.size() == 1 &&
              st.add_headers[0].second == "public, max-age=300" && st.hashed_headers.size() == 1 &&
              st.hashed_headers[0].second == "public, max-age=31536000, immutable" && st.origin == "preset:wagtail");
        // Immutable only for a name that carries its content's hash (alpha.35 report, P3 a).
        CHECK(content_hashed("/static/css/welcome_page.85e6f9d19e42.css") && content_hashed("/static/x.0123abcd.js") &&
              !content_hashed("/static/admin/css/base.css") && !content_hashed("/static/jquery.min.js") && !content_hashed("/static/a.0123ABCD.js") &&
              !content_hashed("/static/a.0123abc.js") && !content_hashed("/static/.0123abcd.js") && !content_hashed("/static/a.0123abcd.") &&
              !content_hashed("/static/0123abcd.js") && !content_hashed(""));
        CHECK(me.kind == HandlerKind::static_ && me.add_headers.size() == 2 && me.add_headers[0].second == "nosniff" &&
              me.add_headers[1].second.find("script-src 'none'") != npos && me.add_headers[1].second.find("sandbox") == npos && me.symlinks_deny);
        CHECK(Router::location(ws, "/media/documents/report.pdf").handler == "deny" && Router::location(ws, "/manage.py").handler == "deny" &&
              Router::location(ws, "/agensio_settings.py").handler == "deny" && Router::location(ws, "/admin/login/").kind == HandlerKind::proxy &&
              Router::location(ws, "/documents/1/report.pdf").kind == HandlerKind::proxy);
        CHECK(refused_suffix("/media/x.py", me.deny_suffixes) && refused_suffix("/static/db.sqlite3", st.deny_suffixes) &&
              refused_suffix("/whatever/settings.py", Router::location(ws, "/whatever/settings.py").deny_suffixes) &&
              !refused_suffix("/media/images/x.png", me.deny_suffixes));
        const AppContext ac = app_context(wc, ws);
        CHECK(ac.hosts == "w.test,.w.test" && ac.origins == "http://w.test,http://*.w.test" && ac.base_url == "http://w.test");
        const json::Value u = control::service_unit(ws, wc);
        const std::string text(u.get("unit"));
        const std::string venv = wc.state_dir + "/w1/venvs/w.test";
        CHECK(u["ok"].boolean() && text.find("ExecStart=@/opt/py/bin/python3 " + venv + "/bin/python -m gunicorn mysite.wsgi:application --bind 127.0.0.1:3008 ") != npos &&
              text.find("UnsetEnvironment=DJANGO_SUPERUSER_PASSWORD DJANGO_SUPERUSER_USERNAME DJANGO_SUPERUSER_EMAIL\n") != npos &&
              text.find("Environment=DJANGO_SETTINGS_MODULE=agensio_settings AGENSIO_DJANGO_PROJECT=mysite\n") != npos &&
              text.find("AGENSIO_HOSTS=w.test,.w.test AGENSIO_ORIGINS=http://w.test,http://*.w.test AGENSIO_BASE_URL=http://w.test\n") != npos &&
              text.find("VIRTUAL_ENV=" + venv + "\n") != npos && text.find("(Gunicorn)") != npos && text.find("puma") == npos);
        write("dj.toml", "[[site]]\nserver_name = [\"d.test\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"app\"\napp = \"django\"\nproject = \"blog\"\n"
                         "upstream = \"http://127.0.0.1:3009\"\n");
        const Config dc = load_config(dir / "dj.toml");
        CHECK(Router::location(dc.sites[0], "/static/x.css").add_headers[0].second == "public, max-age=300" &&
              !Router::location(dc.sites[0], "/static/x.css").hashed_headers.empty() &&
              Router::location(dc.sites[0], "/media/documents/x.pdf").handler == "static");
        const std::string django_site = "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"app\"\napp = \"django\"\nupstream = \"http://127.0.0.1:3000\"\n";
        CHECK(refused(django_site, "needs project = \"NAME\""));
        CHECK(refused(rails + "project = \"blog\"\n", "goes with app = \"django\""));
        CHECK(refused(django_site + "project = \"site\"\n", "would shadow"));
        CHECK(refused(django_site + "project = \"My-Site\"\n", "not a Python package name"));
        CHECK(check_project_name("mysite").empty() && check_project_name("my_site2").empty() && check_project_name("_x").empty() && !check_project_name("2site").empty() &&
              !check_project_name("django").empty() && !check_project_name("a.b").empty() && !check_project_name("").empty());
        // A managed site file's HSTS "/" location (only add_headers) joins the preset's "/":
        // before 2026-09-28 it replaced it, so a proxy preset's site served its project
        // directory from disk (source included) and a PHP preset lost its front controller.
        const std::string hsts_loc = "\n[[site.location]]\npath = \"/\"\nadd_headers = { \"Strict-Transport-Security\" = \"max-age=31536000\" }\n";
        write("h.toml", "[[site]]\nserver_name = [\"h.test\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"app\"\napp = \"django\"\nproject = \"blog\"\n"
                        "upstream = \"http://127.0.0.1:3009\"\n" + hsts_loc);
        const Config hc = load_config(dir / "h.toml");
        const LocationConfig& hr = Router::location(hc.sites[0], "/blog/settings.py");
        CHECK(hr.kind == HandlerKind::proxy && hr.origin == "preset:django" && refused_suffix("/blog/settings.py", hr.deny_suffixes) &&
              hr.add_headers.size() == 1 && hr.add_headers[0].first == "Strict-Transport-Security");
        CHECK(app_context(hc, hc.sites[0]).hsts && !app_context(hc, hc.sites[0]).https_redirect);
        write("hr.toml", rails + hsts_loc);
        CHECK(Router::location(load_config(dir / "hr.toml").sites[0], "/app/models/user.rb").kind == HandlerKind::proxy);
        fs::create_directories(dir / "wp");
        write("hw.toml", "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"wp\"\napp = \"wordpress\"\nphp = { socket = \"unix:/tmp/x.sock\" }\n" + hsts_loc);
        const Config hw = load_config(dir / "hw.toml");
        const LocationConfig& wr = Router::location(hw.sites[0], "/hello-world/");
        CHECK(wr.try_files.size() == 3 && wr.try_files[2].target == "/index.php" && wr.add_headers.size() == 1);
        // A "/" that names a handler, a root or an upstream is still the user's own, and wins.
        write("hs.toml", "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"app\"\napp = \"django\"\nproject = \"blog\"\nupstream = \"http://127.0.0.1:3009\"\n"
                         "\n[[site.location]]\npath = \"/\"\nhandler = \"static\"\nadd_headers = { \"X-A\" = \"1\" }\n");
        CHECK(Router::location(load_config(dir / "hs.toml").sites[0], "/x").kind == HandlerKind::static_);
        // A site written by site-create with https, the redirect and hsts: all three reach the settings.
        {
            control::SiteSpec hs;
            hs.domain = "h.test";
            hs.https = "manual";
            fs::create_directories(dir / "c");
            std::ofstream(dir / "c" / "c.pem") << "x";
            std::ofstream(dir / "c" / "k.pem") << "x";
            hs.cert = (dir / "c" / "c.pem").string();
            hs.key = (dir / "c" / "k.pem").string();
            hs.redirect_http = true;
            hs.hsts = true;
            hs.user_decided = true;
            hs.app = "django";
            hs.project = "blog";
            hs.root = (dir / "app").string();
            hs.upstream = "http://127.0.0.1:3009";
            hs.listen_plain = "127.0.0.1:1";
            hs.listen_tls = "127.0.0.1:2";
            const std::string file = control::render_site(hs, "x");
            CHECK(file.find("Strict-Transport-Security") != npos);
        }
        // The unit: PATH names each directory once (alpha.35 report, P4 d).
        write("p.toml", wag);
        const Config pc = load_config(dir / "p.toml");
        CHECK(std::string(control::service_unit(pc.sites[0], pc).get("unit")).find("Environment=PATH=/usr/bin:/usr/local/bin:/bin\n") != npos);
        // Node (2026-09-28): everything to the upstream, the project's manifests and databases
        // refused at the edge, an entry checked, the unit running root's node bound to loopback.
        const std::string nd = "[[site]]\nserver_name = [\"n.test\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"app\"\nuser = \"n1\"\napp = \"node\"\n"
                               "upstream = \"http://127.0.0.1:3009\"\n";
        write("n.toml", "[control]\nruntimes = { node = \"/opt/node/bin\" }\n" + nd);
        const Config nc = load_config(dir / "n.toml");
        const SiteConfig& ns = nc.sites[0];
        CHECK(proxy_app("node") && service_app("node") && node_app("node") && !node_app("proxy") && ns.entry.empty());
        CHECK(Router::location(ns, "/api/status").kind == HandlerKind::proxy && Router::location(ns, "/socket.io/").kind == HandlerKind::proxy &&
              Router::location(ns, "/node_modules/x/package.json").handler == "deny" && Router::location(ns, "/package-lock.json").handler == "deny" &&
              Router::location(ns, "/.npmrc").handler == "deny" &&
              refused_suffix("/data/kuma.db", Router::location(ns, "/data/kuma.db").deny_suffixes) &&
              !refused_suffix("/assets/index.js", Router::location(ns, "/assets/index.js").deny_suffixes));
        CHECK(control::service_unit(ns, nc).get("error").find("names no entry") != npos);
        write("n2.toml", "[control]\nruntimes = { node = \"/opt/node/bin\" }\n" + nd + "entry = \"server/server.js\"\n");
        const Config nc2 = load_config(dir / "n2.toml");
        const std::string nu(control::service_unit(nc2.sites[0], nc2).get("unit"));
        CHECK(nu.find("ExecStart=/opt/node/bin/node " + nc2.sites[0].root + "/server/server.js\n") != npos &&
              nu.find("Environment=HOST=127.0.0.1 PORT=3009\n") != npos && nu.find("NODE_ENV=production") != npos &&
              nu.find("Environment=PATH=/opt/node/bin:/usr/local/bin:/usr/bin:/bin\n") != npos && nu.find("(node)") != npos);
        CHECK(refused(nd + "entry = \"../x.js\"\n", "must be a path relative") && refused(nd + "entry = \"server/run.sh\"\n", ".js, .mjs or .cjs") &&
              refused(nd + "entry = \"a/.hidden/x.js\"\n", "plain path") && refused(rails + "entry = \"x.js\"\n", "goes with app = \"node\""));
        CHECK(check_entry("server/server.js").empty() && check_entry("index.mjs").empty() && !check_entry("/abs.js").empty() && !check_entry("a b.js").empty() &&
              !check_entry("x.ts").empty() && !check_entry("-x.js").empty());
        // The trash (F12b): what a files-delete moves, and [control] trash_keep.
        {
            fs::create_directories(dir / "www" / "a.test" / "app");
            fs::create_directories(dir / "www" / "a.test" / "other");
            fs::create_directories(dir / "www" / "b.test" / "web");
            fs::create_directories(dir / "elsewhere");
            const std::string www = fs::canonical(dir / "www").string();
            write("tr.toml", "[control]\nsites_root = \"" + www + "\"\ntrash_keep = 30\n"
                             "[[site]]\nserver_name = [\"a.test\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www/a.test/app\"\nuser = \"t1\"\napp = \"rails\"\nupstream = \"http://127.0.0.1:3000\"\n"
                             "[[site]]\nserver_name = [\"b.test\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www/b.test/web\"\n"
                             "[[site]]\nserver_name = [\"c.test\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"elsewhere\"\n");
            const Config tc = load_config(dir / "tr.toml");
            CHECK(tc.control.trash_keep == 30 && provision::trash_dir(tc) == www + "/.trash");
            std::string why;
            // The whole domain directory when the site alone lives under it, the root alone when another site does.
            CHECK(provision::site_tree(tc, tc.sites[0], why) == www + "/a.test" && provision::site_tree(tc, tc.sites[1], why) == www + "/b.test");
            CHECK(provision::site_tree(tc, tc.sites[2], why).empty() && why.find("not below sites_root") != npos);
            write("tr2.toml", "[control]\nsites_root = \"" + www + "\"\n"
                              "[[site]]\nserver_name = [\"a.test\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www/a.test/app\"\n"
                              "[[site]]\nserver_name = [\"d.test\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www/a.test/other\"\n");
            const Config tc2 = load_config(dir / "tr2.toml");
            CHECK(provision::site_tree(tc2, tc2.sites[0], why) == www + "/a.test/app" && tc2.control.trash_keep == 60);
            CHECK(refused("[control]\ntrash_keep = 5000\n" + rails, "0 to 3650") && refused("[control]\ntrash_keep = \"a month\"\n" + rails, "number of days"));
        }
    }
    fs::remove_all(dir);
}

// A site's application environment (services/appenv.*; 2026-09-27 Writebook report).
static void test_appenv() {
    namespace fs = std::filesystem;
    using namespace appenv;
    // Names: upper-case, and never one agensio sets or one that chooses a program.
    CHECK(check_name("SECRET_KEY_BASE").empty() && check_name("DATABASE_URL").empty() && check_name("_X1").empty() && check_name("RACK_ENV").empty());
    for (const char* bad : {"PATH", "HOME", "RAILS_ENV", "GEM_HOME", "GEM_PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "RUBYOPT", "BUNDLE_PATH", "BUNDLE_GEMFILE",
                            "BUNDLE_BUILD__NOKOGIRI", "GIT_SSH_COMMAND", "PYTHONPATH", "NODE_OPTIONS", "SECRET_KEY_BASE_DUMMY", "BASH_ENV", "LISTEN_FDS"})
        CHECK(check_name(bad).find("cannot set it") != std::string::npos);
    CHECK(check_name("BUNDLE_GEMS__CONTRIBSYS__COM").empty());  // a private gem source's credentials
    // Django (2026-09-28): the virtualenv, the settings module, pip's sources and agensio's own
    // AGENSIO_* are agensio's; the secret key and the admin's password are the site's.
    CHECK(!check_name("PIP_INDEX_URL").empty() && !check_name("PIP_EXTRA_INDEX_URL").empty() && !check_name("VIRTUAL_ENV").empty() &&
          !check_name("DJANGO_SETTINGS_MODULE").empty() && !check_name("AGENSIO_HOSTS").empty() && !check_name("PYTHONPATH").empty() &&
          check_name("DJANGO_SECRET_KEY").empty() && check_name("DJANGO_SUPERUSER_PASSWORD").empty());
    // Node (2026-09-28): npm's settings everywhere; HOST, PORT and NODE_ENV on a Node site, whose
    // unit sets them (an EnvironmentFile would override the unit's own lines).
    CHECK(!check_name("NPM_CONFIG_REGISTRY").empty() && check_name("HOST").empty() && check_name("DATA_DIR").empty());
    {
        Change nch;
        nch.set.push_back({"HOST", "0.0.0.0"});
        Change ok;
        ok.set.push_back({"DATA_DIR", "/var/lib/agensio/n1/data/"});
        Change gen;
        gen.generate.push_back("PORT");
        CHECK(!check_change_for_app("node", nch).empty() && check_change_for_app("proxy", nch).empty() && check_change_for_app("node", ok).empty() &&
              !check_change_for_app("node", gen).empty());
    }
    for (const char* bad : {"", "secret", "1ABC", "A-B", "A B", "A=B"}) CHECK(!check_name(bad).empty());
    CHECK(!check_name(std::string(65, 'A')).empty() && check_name(std::string(64, 'A')).empty());
    // Values: one line of UTF-8.
    CHECK(check_value("").empty() && check_value("postgres://u:p@h/db?x=1&y=$z").empty() && check_value("caf\xc3\xa9 \xe2\x82\xac").empty());
    for (const char* bad : {"a\nb", "a\tb", "a\rb", "\xff", "\xc3", "\xc0\xaf"}) CHECK(!check_value(bad).empty());
    CHECK(!check_value(std::string(kMaxValue + 1, 'x')).empty() && check_value(std::string(kMaxValue, 'x')).empty());
    CHECK(valid_site("ag6.edoc.gr") && valid_site("localhost") && !valid_site("*") && !valid_site("../x") && !valid_site("a/b") && !valid_site(".x") && !valid_site("A.test"));
    // Render and parse are each other's inverse, in systemd's syntax.
    const std::vector<Var> vars = {{"A", "plain"}, {"B", "with \"quotes\" and \\ and $HOME and `id`"}, {"C", ""}, {"D", "  spaced  "}, {"E", "caf\xc3\xa9'"}};
    const std::string text = render(vars, "ag6.edoc.gr");
    CHECK(text.find("# The application environment of site ag6.edoc.gr") == 0 && text.find("B=\"with \\\"quotes\\\" and \\\\ and \\$HOME and \\`id\\`\"\n") != std::string::npos);
    std::vector<Var> back;
    std::string why;
    CHECK(parse(text, back, why) && back.size() == vars.size());
    for (std::size_t i = 0; i < vars.size() && i < back.size(); ++i) CHECK(back[i].name == vars[i].name && back[i].value == vars[i].value);
    // What root may write by hand, read the way systemd reads it.
    back.clear();
    CHECK(parse("# comment\n; another\n\n  X = unquoted a\\ b  \nY='single $x \\n'\nZ=\"d \\q \\\"\"\nnot a line\nX=later\n", back, why));
    CHECK(back.size() == 3 && back[0].name == "X" && back[0].value == "later" && back[1].value == "single $x \\n" && back[2].value == "d \\q \"");
    for (const char* bad : {"A=\"open\n", "A='open\n", "A=trailing\\\n", "A=\"x\" y\n", "1A=x\n", "A-B=x\n"}) {
        back.clear();
        CHECK(!parse(bad, back, why) && why.find("line 1") == 0);
    }
    // The change request.
    json::Value body;
    std::string err;
    Change c;
    CHECK(json::parse(R"({"set":{"DATABASE_URL":"x"},"unset":["OLD"],"generate":["SECRET_KEY_BASE"]})", body, err) && parse_change(body, c).empty() &&
          c.set.size() == 1 && c.unset.size() == 1 && c.generate.size() == 1);
    CHECK(json::parse(R"({"unset":["SECRET_KEY_BASE"],"generate":["SECRET_KEY_BASE"]})", body, err) && parse_change(body, c).empty());  // a rotation
    for (const char* bad : {R"({})", R"({"set":{"A":"x"},"unset":["A"]})", R"({"set":{"A":"x"},"generate":["A"]})", R"({"set":{"PATH":"/tmp"}})",
                            R"({"generate":["LD_PRELOAD"]})", R"({"set":{"A":5}})", R"({"set":["A"]})", R"({"unset":"A"})", R"({"unset":["a b"]})",
                            R"({"generate":["A","A"]})", R"({"set":{"A":"x\ny"}})"})
        CHECK(json::parse(bad, body, err) && !parse_change(body, c).empty());
    CHECK(json::parse(R"({"unset":["PATH"]})", body, err) && parse_change(body, c).empty());  // a hand-written reserved line can be removed
    const std::string a = random_secret(), b = random_secret();
    CHECK(a.size() == 128 && a.find_first_not_of("0123456789abcdef") == std::string::npos && a != b);
    CHECK(dir_of("/etc/agensio/agensio.toml") == "/etc/agensio/env");
    // The files, as this account (the helper does the same as root).
    const fs::path dir = fs::temp_directory_path() / ("agensio-env-" + std::to_string(::getpid()));
    fs::create_directories(dir);
    const std::string envdir = (dir / "env").string();
    const unsigned me = ::geteuid();
    std::vector<Var> got;
    auto rd = [&](const char* site, unsigned owner, Status& st) { st = Status{}; return read(envdir, site, owner, got, st); };
    Status st;
    CHECK(rd("a.test", me, st) && got.empty() && !st.exists);  // nothing yet: none, and ok
    Change ch;
    ch.set = {{"DATABASE_URL", "sqlite3:storage/db.sqlite3"}};
    ch.generate = {"SECRET_KEY_BASE"};
    json::Value r = apply(envdir, "a.test", me, ch);
    CHECK(r["ok"].boolean() && r["generated"].items().size() == 1 && r["set"].items().size() == 1 && r.dump().find("sqlite3:storage") == std::string::npos);
    struct stat sb {};
    CHECK(::stat(envdir.c_str(), &sb) == 0 && (sb.st_mode & 0777) == 0700 && ::stat((envdir + "/a.test.env").c_str(), &sb) == 0 && (sb.st_mode & 0777) == 0600);
    CHECK(rd("a.test", me, st) && st.exists && got.size() == 2 && got[1].name == "SECRET_KEY_BASE" && got[1].value.size() == 128);
    const std::string first = got[1].value;
    // What site_env answers: names, lengths, fingerprints; a value only when revealed.
    json::Value d = describe(envdir, "a.test", me, {});
    CHECK(d["ok"].boolean() && d["exists"].boolean() && d["variables"].items().size() == 2 && d.dump().find(first) == std::string::npos &&
          d.dump().find("sqlite3:storage") == std::string::npos && d["variables"].items()[1]["length"].num() == 128 &&
          d["variables"].items()[1]["value"].is_null() && d["revealed"].items().empty());
#ifdef AGENSIO_HAS_TLS
    const std::string fp = std::string(d["variables"].items()[1].get("fingerprint"));
    CHECK(fp.size() == 16 && fp.find_first_not_of("0123456789abcdef") == std::string::npos && fs::exists(envdir + "/.fingerprint.key") &&
          describe(envdir, "a.test", me, {})["variables"].items()[1].get("fingerprint") == fp);  // stable: the key is kept
    CHECK(fingerprint("k1", "v") != fingerprint("k2", "v") && fingerprint("k1", "v") != fingerprint("k1", "w") && fingerprint("k1", "v") == fingerprint("k1", "v"));
#endif
    d = describe(envdir, "a.test", me, {"SECRET_KEY_BASE", "NOPE"});
    CHECK(d["variables"].items()[1].get("value") == first && d["variables"].items()[0]["value"].is_null() && d["revealed"].items().size() == 1 &&
          d["not_found"].items().size() == 1 && d.dump().find("sqlite3:storage") == std::string::npos);
    CHECK(!describe(envdir, "z.test", me, {})["exists"].boolean() && describe(envdir, "z.test", me, {})["ok"].boolean());
    ch = Change{};
    ch.generate = {"SECRET_KEY_BASE"};
    r = apply(envdir, "a.test", me, ch);
    CHECK(r["ok"].boolean() && r["kept"].items().size() == 1 && r["generated"].items().empty() && rd("a.test", me, st) && got[1].value == first);
    ch.unset = {"SECRET_KEY_BASE"};
    r = apply(envdir, "a.test", me, ch);
    CHECK(r["ok"].boolean() && r["generated"].items().size() == 1 && rd("a.test", me, st) && got.size() == 2 && got[1].value != first);
    ch = Change{};
    ch.unset = {"DATABASE_URL", "SECRET_KEY_BASE", "NOT_THERE"};
    r = apply(envdir, "a.test", me, ch);
    CHECK(r["ok"].boolean() && r["unset"].items().size() == 2 && r["absent"].items().size() == 1 && !fs::exists(envdir + "/a.test.env"));
    // A file others could only read is tightened by its owner; one they could write is never read.
    std::ofstream(envdir + "/b.test.env") << "A=1\n";
    fs::permissions(envdir + "/b.test.env", fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read);
    CHECK(rd("b.test", me, st) && got.size() == 1 && st.notes.size() == 1 && ::stat((envdir + "/b.test.env").c_str(), &sb) == 0 && (sb.st_mode & 0777) == 0600);
    fs::permissions(envdir + "/b.test.env", fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_write);
    CHECK(!rd("b.test", me, st) && st.error.find("mode 0600") != std::string::npos && st.fix.find("chmod 0600") != std::string::npos);
    fs::permissions(envdir + "/b.test.env", fs::perms::owner_read | fs::perms::owner_write);
    CHECK(!rd("b.test", me + 1, st) && st.error.find("0700") != std::string::npos && st.fix.find("chmod 0700") != std::string::npos);  // not that owner's
    CHECK(::link((envdir + "/b.test.env").c_str(), (envdir + "/e.test.env").c_str()) == 0);  // a second link: never read
    CHECK(!rd("e.test", me, st) && st.error.find("one link") != std::string::npos);
    ::unlink((envdir + "/e.test.env").c_str());
    std::ofstream(envdir + "/c.test.env") << "PATH=/tmp\n";
    fs::permissions(envdir + "/c.test.env", fs::perms::owner_read | fs::perms::owner_write);
    CHECK(!rd("c.test", me, st) && st.error.find("PATH") != std::string::npos);
    fs::create_symlink(envdir + "/b.test.env", envdir + "/d.test.env");
    CHECK(!rd("d.test", me, st) && st.error.find("symlink") != std::string::npos && st.fix == "rm " + envdir + "/d.test.env");
    // A directory open to its group (a mkdir under a lax umask): its owner tightens it and says so.
    fs::permissions(envdir, fs::perms::owner_all | fs::perms::group_all);
    CHECK(rd("b.test", me, st) && st.notes.size() == 1 && st.notes[0].find("made 0700") != std::string::npos && ::stat(envdir.c_str(), &sb) == 0 && (sb.st_mode & 0777) == 0700);
    fs::permissions(envdir, fs::perms::owner_all | fs::perms::group_all);
    r = apply(envdir, "b.test", me, ch);
    CHECK(r["ok"].boolean() && r["tightened"].items().size() == 1);
    CHECK(!rd("../x", me, st) && !apply(envdir, "../x", me, ch)["ok"].boolean());
    // Rotation is advised only when others could reach the file (2026-09-27 report).
    fs::permissions(envdir + "/b.test.env", fs::perms::owner_read | fs::perms::owner_write | fs::perms::others_read);
    CHECK(rd("b.test", me, st) && st.notes.size() == 1 && st.notes[0].find("nothing to rotate") != std::string::npos);
    fs::permissions(envdir, fs::perms::owner_all | fs::perms::others_exec);
    fs::permissions(envdir + "/b.test.env", fs::perms::owner_read | fs::perms::owner_write | fs::perms::others_read);
    CHECK(rd("b.test", me, st) && st.notes.size() == 2 && st.notes[1].find("rotate what it holds") != std::string::npos);
    // The last variable unset: the file goes, and the answer says so.
    ch = Change{};
    ch.unset = {"A"};
    r = apply(envdir, "b.test", me, ch);
    CHECK(r["ok"].boolean() && r.get("removed") == envdir + "/b.test.env" && !fs::exists(envdir + "/b.test.env"));
    // Health's read-only view: nothing tightened, a finding per file a task would meet, orphans.
    auto write_env = [&](const char* site, const char* text, fs::perms mode) {
        std::ofstream(envdir + "/" + site + ".env") << text;
        fs::permissions(envdir + "/" + site + ".env", mode);
    };
    const auto rw = fs::perms::owner_read | fs::perms::owner_write;
    write_env("ok.test", "A=\"1\"\n", rw);
    write_env("open.test", "A=1\n", rw | fs::perms::others_read | fs::perms::others_write);
    write_env("read.test", "A=1\n", rw | fs::perms::group_read);
    write_env("path.test", "PATH=/tmp\n", rw);
    write_env("gone.test", "A=1\n", rw);
    json::Value in = inspect(envdir, me, {"ok.test", "open.test", "read.test", "path.test", "none.test", "c.test", "d.test"});
    auto finding = [&](const char* site) {
        for (const auto& f : in["sites"].items())
            if (f.get("site") == site) return std::string(f.get("severity")) + " " + std::string(f.get("problem")).substr(0, 0) + (f.get("fix").empty() ? "nofix" : "fix");
        return std::string("none");
    };
    // c.test (PATH) and d.test (a symlink) are left from above: five in all.
    CHECK(in["ok"].boolean() && finding("ok.test") == "none" && finding("none.test") == "none" && finding("open.test") == "warn fix" &&
          finding("read.test") == "info fix" && finding("path.test") == "warn fix" && finding("d.test") == "warn fix");
    CHECK(::stat((envdir + "/read.test.env").c_str(), &sb) == 0 && (sb.st_mode & 0777) == 0640);  // read-only: nothing tightened
    bool orphan = false;
    for (const auto& o : in["orphans"].items()) orphan = orphan || o.get("file") == envdir + "/gone.test.env";
    CHECK(orphan && in["orphans"].items().size() == 1);
    const auto hf = control::env_findings(in);
    CHECK(std::count_if(hf.begin(), hf.end(), [](const control::Finding& f) { return f.code == "site_env_unsafe"; }) == 5 &&
          std::count_if(hf.begin(), hf.end(), [](const control::Finding& f) { return f.code == "site_env_orphan" && f.fix.find("rm -f") != std::string::npos; }) == 1);
    const auto busy = control::env_findings(json::Value::object().set("ok", false).set("busy", true));
    CHECK(busy.size() == 1 && busy[0].code == "site_env_unchecked" && busy[0].severity == "info");
    // The application services health reads through the helper's app_check (alpha.33 report).
    {
        auto svc = [](const char* site, const char* load, const char* active, const char* sub) {
            return json::Value::object().set("site", site).set("unit", std::string("agensio-app-") + site + ".service")
                .set("state", json::Value::object().set("LoadState", load).set("ActiveState", active).set("SubState", sub).set("Result", "exit-code")
                                  .set("ExecMainStatus", "1").set("NRestarts", "5"));
        };
        const auto sf = control::service_findings(json::Value::object().set("ok", true).set("services", json::Value::array()
            .push(svc("a", "loaded", "active", "running")).push(svc("b", "not-found", "inactive", "dead")).push(svc("c", "loaded", "failed", "failed"))
            .push(svc("d", "loaded", "inactive", "dead")).push(svc("e", "loaded", "activating", "auto-restart"))));
        auto code_of = [&](const char* site) {
            for (const auto& f : sf)
                if (f.site == site) return f.severity + " " + f.code;
            return std::string();
        };
        CHECK(sf.size() == 4 && code_of("a").empty() && code_of("b") == "info site_service_missing" && code_of("c") == "warn site_service_failed" &&
              code_of("d") == "warn site_service_down" && code_of("e") == "warn site_service_failed");
        for (const auto& f : sf)
            if (f.site == "c") CHECK(f.fix.find("site_service_logs c") != std::string::npos && f.fix.find("systemctl restart agensio-app-c.service") != std::string::npos);
        CHECK(control::service_findings(json::Value::object().set("ok", false).set("busy", true)).empty());
    }
    CHECK(inspect(envdir + "-none", me, {"ok.test"})["sites"].items().empty());
    // Which sites have a file (site_delete names the file only then).
    std::vector<std::string> present;
    for (const auto& p : in["present"].items()) present.emplace_back(p.str());
    CHECK(std::find(present.begin(), present.end(), "ok.test") != present.end() && std::find(present.begin(), present.end(), "none.test") == present.end());
    // A file others can read under a directory open to others may have leaked: a warning with
    // the rotation advice, not info (2026-09-27 report).
    fs::permissions(envdir, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read | fs::perms::others_exec);
    in = inspect(envdir, me, {"read.test"});
    CHECK(in["sites"].items().size() == 1 && in["sites"].items()[0].get("severity") == "warn" &&
          std::string(in["sites"].items()[0].get("problem")).find("rotate what it holds") != std::string::npos);
#ifdef AGENSIO_HAS_TLS
    // The report's sequence (2026-09-27, against alpha.30): the directory open, a file others
    // could read, then a call on ANOTHER site closes the directory. The file is tightened in
    // that same pass and recorded; health keeps warning until the values change.
    {
        const std::string xdir = (dir / "xenv").string();
        fs::create_directories(xdir);
        auto put_file = [&](const char* site, const char* text, fs::perms mode) {
            std::ofstream(xdir + "/" + site + ".env") << text;
            fs::permissions(xdir + "/" + site + ".env", mode);
        };
        put_file("wb7.test", "A=\"1\"\nB=\"2\"\n", rw | fs::perms::group_read | fs::perms::others_read);
        put_file("ag6.test", "S=\"x\"\n", rw);
        fs::permissions(xdir, fs::perms::owner_all | fs::perms::group_all | fs::perms::others_read | fs::perms::others_exec);
        Status xs;
        std::vector<Var> xv;
        CHECK(read(xdir, "ag6.test", me, xv, xs));  // step 2: site_env or a task on another site
        bool rotate_note = false;
        for (const auto& n : xs.notes) rotate_note = rotate_note || (n.find("wb7.test.env") != std::string::npos && n.find("rotate what it holds") != std::string::npos);
        CHECK(rotate_note && ::stat((xdir + "/wb7.test.env").c_str(), &sb) == 0 && (sb.st_mode & 0777) == 0600 && ::stat(xdir.c_str(), &sb) == 0 && (sb.st_mode & 0777) == 0700);
        auto wb7 = [&] {
            json::Value r = inspect(xdir, me, {"wb7.test", "ag6.test"});
            std::string out;
            for (const auto& f : r["sites"].items()) out += std::string(f.get("site")) + ":" + std::string(f.get("severity")) + ":" + std::string(f.get("problem")) + "|";
            return out;
        };
        const std::string after = wb7();  // step 3: health, the directory now closed
        CHECK(after.find("wb7.test:warn:") != std::string::npos && after.find("A, B were readable by others") != std::string::npos &&
              after.find("rotate them") != std::string::npos && after.find("ag6.test") == std::string::npos && after.find("nothing to rotate") == std::string::npos);
        Change rot;
        rot.set = {{"A", "new"}};
        CHECK(apply(xdir, "wb7.test", me, rot)["ok"].boolean() && wb7().find("B was readable by others") != std::string::npos && wb7().find("A, B") == std::string::npos);
        // The tool says what is still to rotate (2026-09-27 report, c): B was left alone above.
        rot = Change{};
        rot.set = {{"B", "2"}};  // the same value again: still the one others could read
        json::Value same = apply(xdir, "wb7.test", me, rot);
        CHECK(same["ok"].boolean() && same["still_exposed"].items().size() == 1 && same["still_exposed"].items()[0].str() == "B");
        rot = Change{};
        rot.unset = {"B"};
        json::Value gone = apply(xdir, "wb7.test", me, rot);
        CHECK(gone["ok"].boolean() && gone["still_exposed"].is_null() && wb7().empty());  // every exposed value changed or gone: no warning
        // a) the rotation fix is a tool call, never "as root"; the chmod fix stays root's.
        put_file("wb9.test", "K=\"k\"\n", rw | fs::perms::others_read);
        fs::permissions(xdir, fs::perms::owner_all | fs::perms::others_exec);
        inspect(xdir, me, {"wb9.test"});  // seen open: recorded
        fs::permissions(xdir, fs::perms::owner_all);
        fs::permissions(xdir + "/wb9.test.env", rw);
        auto fs9 = control::env_findings(inspect(xdir, me, {"wb9.test"}));
        std::erase_if(fs9, [](const control::Finding& f) { return f.code != "site_env_unsafe"; });  // the other files here are orphans
        CHECK(fs9.size() == 1 && fs9[0].site == "wb9.test" && fs9[0].severity == "warn" && fs9[0].fix.starts_with("site_env_set wb9.test") &&
              fs9[0].fix.find("as root") == std::string::npos);
        // b) the site deleted, its file kept, unrotated: the orphan is a warning naming K.
        json::Value orph = inspect(xdir, me, {});
        bool named = false;
        for (const auto& o : orph["orphans"].items()) named = named || (o.get("site") == "wb9.test" && o["exposed"].items().size() == 1);
        const auto fo = control::env_findings(orph);
        CHECK(named && std::any_of(fo.begin(), fo.end(), [](const control::Finding& f) {
                  return f.code == "site_env_orphan" && f.severity == "warn" && f.message.find("K in it was readable by others and never rotated") != std::string::npos &&
                         f.message.find("brings that value back") != std::string::npos && f.fix.starts_with("rotate it ");
              }));
        // One name reads singular, several plural (2026-09-27 report against alpha.32).
        json::Value two = json::Value::object().set("ok", true).set("sites", json::Value::array())
                              .set("orphans", json::Value::array().push(json::Value::object().set("file", "/e/x.test.env").set("exposed", json::Value::array().push("A").push("B"))));
        const auto f2 = control::env_findings(two);
        CHECK(f2.size() == 1 && f2[0].message.find("A, B in it were readable") != std::string::npos && f2[0].message.find("brings those values back") != std::string::npos &&
              f2[0].fix.starts_with("rotate them "));
        // d) with neither the site nor its file, the ledger entry goes.
        fs::remove(xdir + "/wb9.test.env");
        inspect(xdir, me, {});
        std::ifstream ledger(xdir + "/.exposed");
        const std::string led((std::istreambuf_iterator<char>(ledger)), std::istreambuf_iterator<char>());
        CHECK(led.find("wb9.test") == std::string::npos);
        // health itself records what it sees open, so closing the directory by hand keeps the warning too
        put_file("wb8.test", "C=\"3\"\n", rw | fs::perms::others_read);
        fs::permissions(xdir, fs::perms::owner_all | fs::perms::others_exec);
        CHECK(inspect(xdir, me, {"wb8.test"})["sites"].items()[0].get("severity") == "warn");
        fs::permissions(xdir, fs::perms::owner_all);
        const std::string later = std::string(inspect(xdir, me, {"wb8.test"}).dump());
        CHECK(later.find("C was readable by others") != std::string::npos && later.find("\"warn\"") != std::string::npos);
    }
#endif
    fs::remove_all(dir);
}

// C3b-2: the ownership rules over a described machine.
static void test_hosting_rules() {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("agensio-hosting-" + std::to_string(::getpid()));
    fs::create_directories(dir / "app" / "public");
    fs::create_directories(dir / "blog");
    auto write = [&](const char* name, const std::string& text) { std::ofstream(dir / name) << text; };
    const std::string server = "[server]\nworkers = 1\ngroup = \"agensio\"\npools_run = \"/run/php\"\nstate_dir = \"/var/lib/agensio\"\n[log]\naccess = \"/var/log/agensio/access.log\"\n";
    write("h.toml", server +
          "[[site]]\nserver_name = [\"shop\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"app\"\nuser = \"web1\"\napp = \"laravel\"\naccess_log = \"/var/log/agensio/shop.log\"\n"
          "[[site]]\nserver_name = [\"blog\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"blog\"\nuser = \"web2\"\napp = \"wordpress\"\naccess_log = \"/var/log/agensio/blog.log\"\n"
          "[[site]]\nserver_name = [\"docs\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"docs\"\nuser = \"web2\"\napp = \"drupal\"\naccess_log = \"/var/log/agensio/blog.log\"\n");
    fs::create_directories(dir / "docs");
    Config cfg = load_config(dir / "h.toml");
    const std::string app = fs::canonical(dir / "app").string();
    const std::string blog = fs::canonical(dir / "blog").string();
    const std::string docs = fs::canonical(dir / "docs").string();
    // The machine: users web1 (1001:1001) and web2 (1002:1002), agensio group 33.
    std::map<std::string, FileFacts> files;
    HostFacts facts;
    facts.user = [](const std::string& n, unsigned& uid, unsigned& gid) {
        if (n == "web1") { uid = 1001; gid = 1001; return true; }
        if (n == "web2") { uid = 1002; gid = 1002; return true; }
        return false;
    };
    facts.group = [](const std::string& n, unsigned& gid) {
        if (n == "agensio") { gid = 33; return true; }
        if (n == "web1") { gid = 1001; return true; }
        return false;
    };
    facts.stat = [&](const std::string& path, FileFacts& out) {
        auto it = files.find(path);
        if (it == files.end()) return false;
        out = it->second;
        return true;
    };
    auto count_with = [&](const char* needle) {
        int n = 0;
        for (const auto& e : check_hosting(cfg, facts)) n += e.find(needle) != std::string::npos;
        return n;
    };
    auto file = [](unsigned uid, unsigned gid, unsigned mode, bool d = false) { return FileFacts{d, uid, gid, mode}; };
    // A correct layout passes.
    files[app] = file(1001, 1001, 0750, true);
    files[app + "/public"] = file(1001, 1001, 0750, true);
    files[app + "/.env"] = file(1001, 1001, 0640);
    files[blog] = file(1002, 1002, 0755, true);
    files[blog + "/wp-config.php"] = file(1002, 1002, 0640);
    files[docs] = file(1002, 1002, 0755, true);
    files[docs + "/sites/default/settings.php"] = file(1002, 1002, 0600);
    files["/run/php/agensio-web1.sock"] = file(1001, 33, 0660);
    files["/run/php"] = file(0, 0, 0755, true);
    files["/var/log/agensio"] = file(33, 33, 0750, true);
    files["/var/log/agensio/shop.log"] = file(33, 1001, 0640);
    CHECK(check_hosting(cfg, facts).empty());
    // Each rule, one failure at a time.
    files[app + "/public"] = file(1003, 1001, 0750, true);
    CHECK(count_with("expected owner web1") == 1);
    files[app + "/public"] = file(1001, 1001, 0757, true);
    CHECK(count_with("writable by other users") == 1);
    files[app + "/public"] = file(1001, 1001, 0750, true);
    files[app + "/.env"] = file(1001, 1001, 0644);
    CHECK(count_with(".env is readable by other users") == 1);
    files[app + "/.env"] = file(1001, 1001, 0640);
    files[blog + "/wp-config.php"] = file(1002, 33, 0640);  // readable by a group that is not web2's
    CHECK(count_with("wp-config.php is readable") == 1);
    files[blog + "/wp-config.php"] = file(1002, 1002, 0640);
    // The same rule reads the preset table: Drupal's settings.php and services.yml are covered too.
    files[docs + "/sites/default/settings.php"] = file(1002, 33, 0640);
    files[docs + "/sites/default/services.yml"] = file(1002, 1002, 0644);
    CHECK(count_with("settings.php is readable") == 1 && count_with("services.yml is readable") == 1);
    files[docs + "/sites/default/settings.php"] = file(1002, 1002, 0600);
    files.erase(docs + "/sites/default/services.yml");
    CHECK(secret_exposed(0644, 1002, 1002) && secret_exposed(0640, 33, 1002) && !secret_exposed(0640, 1002, 1002) && !secret_exposed(0600, 33, 1002));
    {
        // secret_paths: one list for the rule and for the writers, from the preset table.
        const auto wp = secret_paths(cfg.sites[1]);
        const auto dr = secret_paths(cfg.sites[2]);
        CHECK(std::find(wp.begin(), wp.end(), blog + "/wp-config.php") != wp.end() && std::find(wp.begin(), wp.end(), blog + "/.git") != wp.end());
        CHECK(std::find(dr.begin(), dr.end(), docs + "/sites/default/settings.php") != dr.end() && std::find(dr.begin(), dr.end(), docs + "/sites/default/services.yml") != dr.end());
        const auto lv = secret_paths(cfg.sites[0]);
        CHECK(std::find(lv.begin(), lv.end(), app + "/.env") != lv.end() && std::find(lv.begin(), lv.end(), app + "/storage") != lv.end());
        // Every preset's secrets are among what it never serves (a secret that is served is a contradiction).
        const json::Value catalog = preset_catalog();
        for (const auto& pr : catalog["presets"].items()) {
            if (proxy_app(pr.get("app"))) continue;  // serves nothing from its directory: every request goes to the upstream
            const auto& never = pr["never_served"].items();
            for (const auto& sec : pr["secrets"].items())
                CHECK(std::find_if(never.begin(), never.end(), [&](const json::Value& n) { return n.str() == sec.str(); }) != never.end());
            CHECK(preset_secrets(std::string(pr.get("app"))).size() == pr["secrets"].items().size());
        }
        CHECK(preset_secrets("wordpress") == std::vector<std::string>{"/wp-config.php"} && preset_secrets("drupal").size() == 3 && preset_secrets("static").empty());
    }
    files["/run/php/agensio-web1.sock"] = file(1001, 1001, 0666);
    CHECK(count_with("expected group agensio") == 1 && count_with("any user could connect") == 1);
    files["/run/php/agensio-web1.sock"] = file(1002, 33, 0660);
    CHECK(count_with("socket /run/php/agensio-web1.sock is owned") == 1);
    files["/run/php/agensio-web1.sock"] = file(1001, 33, 0660);
    files["/var/log/agensio/shop.log"] = file(33, 33, 0644);
    CHECK(count_with("access log /var/log/agensio/shop.log is readable") == 1);
    files["/var/log/agensio/shop.log"] = file(33, 1001, 0640);
    files["/var/log/agensio"] = file(33, 1001, 0770, true);
    CHECK(count_with("log directory /var/log/agensio is writable") == 3);  // all three sites log there
    files["/var/log/agensio"] = file(33, 33, 0750, true);
    CHECK(check_hosting(cfg, facts).empty());
    // Accounts and sharing.
    facts.group = [](const std::string& n, unsigned& gid) { if (n == "agensio") { gid = 33; return true; } return false; };
    cfg.sites[1].user = "nobody-here";
    CHECK(count_with("user 'nobody-here' does not exist") == 1);
    cfg.sites[1].user = "web2";
    cfg.sites[1].access_log = "/var/log/agensio/shop.log";
    CHECK(count_with("same access log") == 1);
    cfg.sites[1].access_log = "/var/log/agensio/blog.log";
    cfg.sites[1].root = app + "/public";
    CHECK(count_with("nested or equal roots") == 1);
    cfg.group = "missing";
    CHECK(count_with("server.group") == 1);
    fs::remove_all(dir);
}

// D1: the HTTP response-head parser and the proxy location.
static void test_proxy() {
    namespace fs = std::filesystem;
    using http::HeadStatus;
    http::ResponseHead h;
    CHECK(http::parse_response_head("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-A: b\r\n\r\nabc", h) == HeadStatus::complete);
    CHECK(h.status == 200 && h.version_minor == 1 && h.length == 46 && h.headers.get("x-a") == "b");
    CHECK(http::parse_response_head("HTTP/1.0 404\r\n\r\n", h) == HeadStatus::complete && h.version_minor == 0 && h.status == 404);
    CHECK(http::parse_response_head("HTTP/1.1 200 OK\r\nContent-Len", h) == HeadStatus::incomplete);
    CHECK(http::parse_response_head("HTTP/2 200\r\n\r\n", h) == HeadStatus::error);
    CHECK(http::parse_response_head("HTTP/1.1 99 x\r\n\r\n", h) == HeadStatus::error);
    CHECK(http::parse_response_head("HTTP/1.1 200 OK\r\nBad Name: 1\r\n\r\n", h) == HeadStatus::error);
    CHECK(http::parse_response_head("HTTP/1.1 200 OK\r\nX: a\nb\r\n\r\n", h) == HeadStatus::error);  // bare LF
    CHECK(http::parse_response_head("HTTP/1.1 200 OK\r\nX: a\x01\r\n\r\n", h) == HeadStatus::error);
    CHECK(http::connection_lists("close", "close") && http::connection_lists("keep-alive, X-Custom", "x-custom") &&
          !http::connection_lists("keep-alive", "close"));
    CHECK(http::is_hop_by_hop("Transfer-Encoding") && http::is_hop_by_hop("connection") && !http::is_hop_by_hop("Host"));

    const fs::path dir = fs::temp_directory_path() / ("agensio-proxy-" + std::to_string(::getpid()));
    fs::create_directories(dir / "www");
    auto write = [&](const char* name, const std::string& text) { std::ofstream(dir / name) << text; };
    write("p.toml", "[[site]]\nlisten = [\"127.0.0.1:18097\"]\nroot = \"www\"\n"
                    "[[site.location]]\npath = \"/api/\"\nupstream = \"http://127.0.0.1:9100\"\nproxy = { buffering = false, read_timeout = 2 }\n"
                    "[[site.location]]\npath = \"/sock/\"\nupstream = \"unix:/run/app.sock\"\n");
    Config cfg = load_config(dir / "p.toml");
    const LocationConfig& api = Router::location(cfg.sites[0], "/api/x");
    CHECK(api.kind == HandlerKind::proxy && api.handler == "proxy" && api.proxy.address.key == "127.0.0.1:9100");
    CHECK(api.proxy.options.keep_conn && !api.proxy.options.buffering && api.proxy.options.read_timeout.count() == 2000);
    CHECK((api.methods & method_bit(Method::post)) != 0);
    CHECK(Router::location(cfg.sites[0], "/sock/").proxy.address.unix);
    CHECK(Router::location(cfg.sites[0], "/").kind == HandlerKind::static_);
    auto refused = [&](const char* name, const std::string& text, const char* needle) {
        write(name, text);
        try { load_config(dir / name); return false; } catch (const std::exception& e) { return std::string(e.what()).find(needle) != std::string::npos; }
    };
    // TLS to the origin (D4b): https:// sets the flag and keeps the pool apart; the tls table.
    std::ofstream(dir / "ca.pem") << "-----BEGIN CERTIFICATE-----\n";
    write("tls.toml", "[[site]]\nlisten = [\"127.0.0.1:18097\"]\nroot = \"www\"\n[[site.location]]\npath = \"/\"\nupstream = \"https://127.0.0.1:9100\"\n"
                      "proxy = { tls = { verify = false, server_name = \"origin.internal\", ca = \"ca.pem\" } }\n");
    const Config tcfg = load_config(dir / "tls.toml");
    const LocationConfig& tl = Router::location(tcfg.sites[0], "/");
    CHECK(tl.proxy.address.tls && tl.proxy.address.key == "https://127.0.0.1:9100" && tl.proxy.address.port == 9100);
    CHECK(!tl.proxy.tls.verify && tl.proxy.tls.server_name == "origin.internal" && tl.proxy.tls.ca_file == fs::canonical(dir / "ca.pem").string());
    CHECK(refused("tlsunix.toml", "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n[[site.location]]\npath = \"/\"\nupstream = \"https://unix:/run/x.sock\"\n", "unix socket"));
    CHECK(refused("tlsca.toml", "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n[[site.location]]\npath = \"/\"\nupstream = \"https://127.0.0.1:9100\"\nproxy = { tls = { ca = \"missing.pem\" } }\n", "file not found"));
    CHECK(refused("noup.toml", "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n[[site.location]]\npath = \"/\"\nhandler = \"proxy\"\n", "needs upstream"));
    CHECK(refused("name.toml", "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n[[site.location]]\npath = \"/\"\nupstream = \"http://origin:3000\"\n", "IP literal"));
    CHECK(api.proxy.rewrite.empty() && api.proxy.options.max_connections == 256 && api.proxy.options.max_idle == 64);
    write("rw.toml", "[[site]]\nlisten = [\"127.0.0.1:18097\"]\nroot = \"www\"\n[[site.location]]\npath = \"/api/\"\nupstream = \"http://127.0.0.1:9100/v1\"\n");
    const Config rwcfg = load_config(dir / "rw.toml");
    CHECK(Router::location(rwcfg.sites[0], "/api/x").proxy.rewrite == "/v1/");
    CHECK(refused("rwexact.toml", "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n[[site.location]]\npath = \"/x\"\nmatch = \"exact\"\nupstream = \"http://127.0.0.1:9100/\"\n", "prefix location"));

    // The forwarded head: hop-by-hop dropped, Host kept, X-Forwarded-* set.
    Stream st;
    st.request.method = Method::post;
    st.request.method_name = "POST";
    st.request.target = "/api/x?y=1";
    st.request.host = "app.example.com";
    st.request.headers.add("Host", "app.example.com");
    st.request.headers.add("Connection", "keep-alive, X-Drop");
    st.request.headers.add("X-Drop", "1");
    st.request.headers.add("Transfer-Encoding", "chunked");
    st.request.headers.add("Content-Length", "5");
    st.request.headers.add("X-Forwarded-For", "10.0.0.1");
    st.request.headers.add("Accept", "*/*");
    st.conn.remote_address = "192.0.2.7";
    st.conn.local_port = 443;
    st.conn.tls = true;
    UpstreamConfig policy;  // defaults: host pass, x-forwarded, rewrite redirects
    std::string head;
    {
        // Two Cookie lines (an HTTP/1.1 client should send one): one line for the origin,
        // the crumbs in order, at the first one's place (2026-09-27 report).
        Stream ck;
        ck.request.method_name = "GET";
        ck.request.headers.add("Host", "app.example.com");
        ck.request.headers.add("Cookie", "_app_session=S");
        ck.request.headers.add("Accept", "*/*");
        ck.request.headers.add("cookie", "session_token=T");
        ck.conn.remote_address = "192.0.2.7";
        ProxyHandler::build_head(head, ck, "/", policy);
        CHECK(head.find("Cookie: _app_session=S; session_token=T\r\nAccept: */*\r\n") != std::string::npos && head.find("session_token=T\r\n") == head.rfind("session_token=T\r\n") &&
              head.find("cookie: ") == std::string::npos);
        head.clear();
    }
    ProxyHandler::build_head(head, st, st.request.target, policy);
    CHECK(head.starts_with("POST /api/x?y=1 HTTP/1.1\r\n"));
    CHECK(head.find("Host: app.example.com\r\n") != std::string::npos && head.find("Accept: */*\r\n") != std::string::npos);
    CHECK(head.find("X-Drop") == std::string::npos && head.find("Transfer-Encoding") == std::string::npos &&
          head.find("Content-Length") == std::string::npos && head.find("Connection:") == std::string::npos);
    // An untrusted peer: its X-Forwarded-For is replaced, not appended to.
    CHECK(head.find("X-Forwarded-For: 192.0.2.7\r\n") != std::string::npos && head.find("10.0.0.1") == std::string::npos);
    CHECK(head.find("X-Forwarded-Proto: https\r\n") != std::string::npos);
    CHECK(head.find("X-Forwarded-Host:") == std::string::npos);  // Host passes through: the field would only repeat it
    CHECK(head.find("Forwarded:") == std::string::npos);
    // A trusted proxy in front: appended; both conventions; Host rewritten; configured fields.
    st.conn.trusted_peer = true;
    policy.forwarded = "both";
    policy.host = "app.internal";
    policy.set_headers = {{"X-Real-IP", "$remote_addr"}, {"X-Site", "$scheme://$host:$server_port"}, {"Accept", ""}};
    head.clear();
    ProxyHandler::build_head(head, st, st.request.target, policy);
    CHECK(head.find("X-Forwarded-For: 10.0.0.1, 192.0.2.7\r\n") != std::string::npos);
    CHECK(head.find("Forwarded: for=192.0.2.7;proto=https;host=app.example.com\r\n") != std::string::npos);
    CHECK(head.find("\r\nHost: app.internal\r\n") != std::string::npos && head.find("\r\nHost: app.example.com") == std::string::npos);
    CHECK(head.find("X-Forwarded-Host: app.example.com\r\n") != std::string::npos);  // Host rewritten: the original goes along
    CHECK(head.find("X-Real-IP: 192.0.2.7\r\n") != std::string::npos && head.find("X-Site: https://app.example.com:443\r\n") != std::string::npos);
    CHECK(head.find("Accept:") == std::string::npos);  // "" removes
    policy.host = "upstream";
    policy.forwarded = "off";
    policy.address.key = "127.0.0.1:9100";
    head.clear();
    ProxyHandler::build_head(head, st, st.request.target, policy);
    CHECK(head.find("Host: 127.0.0.1:9100\r\n") != std::string::npos && head.find("X-Forwarded") == std::string::npos);
    // An Upgrade request is recognised and its Upgrade field forwarded; not with a body.
    Stream ws;
    ws.request.method = Method::get;
    ws.request.method_name = "GET";
    ws.request.target = "/socket";
    ws.request.host = "app.example.com";
    ws.request.headers.add("Connection", "Upgrade");
    ws.request.headers.add("Upgrade", "websocket");
    ws.request.headers.add("Sec-WebSocket-Key", "x");
    ws.conn.remote_address = "192.0.2.7";
    UpstreamConfig p2;
    head.clear();
    CHECK(ProxyHandler::build_head(head, ws, ws.request.target, p2));
    CHECK(head.find("Upgrade: websocket\r\n") != std::string::npos && head.find("Sec-WebSocket-Key: x\r\n") != std::string::npos);
    p2.upgrade = false;
    head.clear();
    CHECK(!ProxyHandler::build_head(head, ws, ws.request.target, p2) && head.find("Upgrade:") == std::string::npos);
    // The policy keys through the loader, site defaults refined by the location.
    write("policy.toml", "[[site]]\nlisten = [\"127.0.0.1:18097\"]\nroot = \"www\"\nproxy = { forwarded = \"both\", hide = [\"X-Powered-By\"], headers = { \"X-A\" = \"1\" } }\n"
                         "[[site.location]]\npath = \"/\"\nupstream = \"http://127.0.0.1:9100\"\nproxy = { host = \"app.internal\", headers = { \"X-A\" = \"2\", \"X-B\" = \"$host\" }, redirects = \"pass\" }\n");
    const Config pcfg = load_config(dir / "policy.toml");  // keep the Config alive behind the reference
    const LocationConfig& pl = Router::location(pcfg.sites[0], "/");
    CHECK(pl.proxy.forwarded == "both" && pl.proxy.host == "app.internal" && !pl.proxy.rewrite_redirects);
    CHECK(pl.proxy.hide.size() == 1 && pl.proxy.set_headers.size() == 2 && pl.proxy.set_headers[0].second == "2");
    CHECK(pl.proxy.options.keep_conn && pl.proxy.options.max_connections == 256);
    // Groups (D4): a list of origins, round-robin per worker, failures skipped for fail_timeout.
    write("group.toml", "[[site]]\nlisten = [\"127.0.0.1:18097\"]\nroot = \"www\"\n[[site.location]]\npath = \"/g/\"\n"
                        "upstream = [\"http://127.0.0.1:9107/\", \"http://127.0.0.1:9108/\", \"http://127.0.0.1:9109/\"]\nproxy = { max_fails = 2, fail_timeout = 0.2 }\n");
    const Config gcfg = load_config(dir / "group.toml");
    const LocationConfig& g = Router::location(gcfg.sites[0], "/g/x");
    CHECK(g.proxy.addresses.size() == 3 && g.proxy.address.key == "127.0.0.1:9107" && g.proxy.rewrite == "/" &&
          g.proxy.options.max_fails == 2 && g.proxy.options.fail_timeout.count() == 200);
    CHECK(refused("gmix.toml", "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n[[site.location]]\npath = \"/\"\nupstream = [\"http://127.0.0.1:9107/\", \"http://127.0.0.1:9108\"]\n", "same URI part"));
    CHECK(refused("gdup.toml", "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n[[site.location]]\npath = \"/\"\nupstream = [\"http://127.0.0.1:9107\", \"http://127.0.0.1:9107\"]\n", "listed twice"));
    {
        asio::io_context ctx;
        UpstreamPool pool(ctx);
        const auto& grp = g.proxy.addresses;
        const UpstreamOptions& o = g.proxy.options;
        // Round-robin over the group, then the next member after a given one, skipping tried ones.
        CHECK(pool.pick(grp, o, SIZE_MAX, 0) == 0 && pool.pick(grp, o, SIZE_MAX, 0) == 1 && pool.pick(grp, o, SIZE_MAX, 0) == 2 &&
              pool.pick(grp, o, SIZE_MAX, 0) == 0);
        CHECK(pool.pick(grp, o, 1, 0b010) == 2 && pool.pick(grp, o, 2, 0b111) == SIZE_MAX);
        // Two failures mark a member down: it is skipped until fail_timeout passes, unless all are down.
        std::string note;
        pool.mark_failure(grp[1], o, note);
        CHECK(note.empty());
        pool.mark_failure(grp[1], o, note);
        CHECK(note.find("127.0.0.1:9108 marked down") != std::string::npos);
        CHECK(pool.pick(grp, o, 0, 0b001) == 2);  // 1 is down: the next after 0 is 2
        pool.mark_failure(grp[0], o, note); pool.mark_failure(grp[0], o, note);
        pool.mark_failure(grp[2], o, note); pool.mark_failure(grp[2], o, note);
        CHECK(pool.pick(grp, o, SIZE_MAX, 0) == 1);  // everything down: the one marked longest ago
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        CHECK(pool.pick(grp, o, 0, 0b001) == 1);  // the timeout passed: 1 is available again
        note.clear();
        pool.mark_success(grp[1], note);
        CHECK(note == "127.0.0.1:9108 is back");
        pool.mark_success(grp[1], note);  // a healthy member says nothing
    }
    // The proxy preset (D6): a site with `upstream` and no root; other locations coexist.
    write("preset.toml", "[[site]]\nlisten = [\"127.0.0.1:18097\"]\napp = \"proxy\"\nupstream = \"http://127.0.0.1:3000\"\nproxy = { read_timeout = 120 }\n"
                         "[[site.location]]\npath = \"/assets/\"\nalias = \"" + dir.string() + "/www\"\n");
    const Config prcfg = load_config(dir / "preset.toml");
    const LocationConfig& pr = Router::location(prcfg.sites[0], "/anything");
    CHECK(pr.kind == HandlerKind::proxy && pr.origin == "preset:proxy" && pr.proxy.address.key == "127.0.0.1:3000" &&
          pr.proxy.options.read_timeout.count() == 120000 && pr.proxy.options.keep_conn);
    CHECK(Router::location(prcfg.sites[0], "/assets/x.js").kind == HandlerKind::static_);
    CHECK(refused("noup.toml", "[[site]]\nlisten = [\"127.0.0.1:1\"]\napp = \"proxy\"\n", "needs upstream"));
    CHECK(refused("badfwd.toml", "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n[[site.location]]\npath = \"/\"\nupstream = \"http://127.0.0.1:9100\"\nproxy = { forwarded = \"maybe\" }\n", "forwarded must be"));
    fs::remove_all(dir);
}

// E1: the Range header parser and If-Range.
static void test_range() {
    std::uint64_t f = 0, l = 0;
    CHECK(parse_range("bytes=0-99", 1000, f, l) == RangeStatus::single && f == 0 && l == 99);
    CHECK(parse_range("bytes=500-", 1000, f, l) == RangeStatus::single && f == 500 && l == 999);
    CHECK(parse_range("bytes=-100", 1000, f, l) == RangeStatus::single && f == 900 && l == 999);
    CHECK(parse_range("bytes=-5000", 1000, f, l) == RangeStatus::single && f == 0 && l == 999);  // suffix longer than the file
    CHECK(parse_range("bytes=990-2000", 1000, f, l) == RangeStatus::single && f == 990 && l == 999);  // clipped
    CHECK(parse_range(" bytes = 1 - 2 ", 1000, f, l) == RangeStatus::none);  // "bytes=" must be exact
    CHECK(parse_range("bytes= 1-2", 1000, f, l) == RangeStatus::single && f == 1 && l == 2);
    CHECK(parse_range("bytes=1000-", 1000, f, l) == RangeStatus::unsatisfiable);
    CHECK(parse_range("bytes=2000-3000", 1000, f, l) == RangeStatus::unsatisfiable);
    CHECK(parse_range("bytes=-0", 1000, f, l) == RangeStatus::none);
    CHECK(parse_range("bytes=5-2", 1000, f, l) == RangeStatus::none);
    CHECK(parse_range("bytes=0-99,200-299", 1000, f, l) == RangeStatus::none);  // several ranges: the whole body
    CHECK(parse_range("items=0-1", 1000, f, l) == RangeStatus::none);
    CHECK(parse_range("bytes=abc", 1000, f, l) == RangeStatus::none);
    CHECK(parse_range("bytes=-1", 0, f, l) == RangeStatus::unsatisfiable);
    CHECK(parse_range("bytes=0-", 0, f, l) == RangeStatus::unsatisfiable);
    CHECK(if_range_matches("", "\"abc\"", "Thu, 01 Jan 2026 00:00:00 GMT"));
    CHECK(if_range_matches("\"abc\"", "\"abc\"", "x") && !if_range_matches("\"abd\"", "\"abc\"", "x"));
    CHECK(!if_range_matches("W/\"abc\"", "W/\"abc\"", "x"));  // weak validators never permit a range
    CHECK(if_range_matches("Thu, 01 Jan 2026 00:00:00 GMT", "\"abc\"", "Thu, 01 Jan 2026 00:00:00 GMT"));
    CHECK(!if_range_matches("Fri, 02 Jan 2026 00:00:00 GMT", "\"abc\"", "Thu, 01 Jan 2026 00:00:00 GMT"));
    Request rq;
    CHECK(parse_request("GET / HTTP/1.1\r\nHost: h\r\nRange: bytes=1-2\r\nIf-Range: \"e\"\r\n\r\n", rq) == ParseStatus::complete &&
          rq.range == "bytes=1-2" && rq.if_range == "\"e\"");
}

static void test_json() {
    json::Value v;
    std::string err;
    CHECK(json::parse(R"({"a":1,"b":[true,null,"x\u00e9\n"],"c":{"d":-2.5e1},"e":""})", v, err));
    CHECK(v.is_object() && v["a"].num() == 1 && v["b"].items().size() == 3 && v["b"].items()[0].boolean());
    CHECK(v["b"].items()[1].is_null() && v["b"].items()[2].str() == "x\xc3\xa9\n");
    CHECK(v["c"]["d"].num() == -25 && v.get("e").empty() && v.get("missing").empty() && v["zz"]["yy"].is_null());
    CHECK(v.dump() == "{\"a\":1,\"b\":[true,null,\"x\xc3\xa9\\n\"],\"c\":{\"d\":-25},\"e\":\"\"}");
    CHECK(json::Value::object().set("k", "v").set("n", 3).set("k", "w").dump() == R"({"k":"w","n":3})");
    CHECK(json::Value("a\"b\\c\x01").dump() == R"("a\"b\\c\u0001")");
    CHECK(!json::parse("{\"a\":}", v, err) && !err.empty());
    CHECK(!json::parse("[1,2", v, err));
    CHECK(!json::parse("{\"a\":1} x", v, err));
    CHECK(!json::parse("\"\\q\"", v, err));
    std::string deep(100, '[');
    CHECK(!json::parse(deep, v, err));
    CHECK(json::parse(" [ ] ", v, err) && v.is_array() && v.items().empty());
    CHECK(json::parse("{\"s\":\"\\ud83d\\ude00\"}", v, err) && v.get("s") == "\xf0\x9f\x98\x80");
}

#ifdef AGENSIO_HAS_TLS
static void test_acme() {
    using namespace std::chrono;
    // base64url, RFC 4648 section 5 test vectors and no padding.
    CHECK(acme::base64url("") == "");
    CHECK(acme::base64url("f") == "Zg" && acme::base64url("fo") == "Zm8" && acme::base64url("foo") == "Zm9v");
    CHECK(acme::base64url("foob") == "Zm9vYg" && acme::base64url("fooba") == "Zm9vYmE" && acme::base64url("foobar") == "Zm9vYmFy");
    CHECK(acme::base64url("\xfb\xff\xbf") == "-_-_");
    // JWS ES256 over a P-256 key round-trips; the JWK thumbprint is stable and URL-safe.
    const std::string key =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n"
        "OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n"
        "1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n"
        "-----END PRIVATE KEY-----\n";
    std::string jwk, thumb, err;
    CHECK(acme::jwk_of(key, jwk, thumb, err));
    CHECK(jwk.starts_with("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"") && thumb.size() == 43);
    CHECK(thumb.find_first_of("+/=") == std::string::npos);
    const std::string jws = acme::jws_sign(key, R"({"alg":"ES256","nonce":"n","url":"https://ca/x","kid":"k"})", R"({"a":1})", err);
    CHECK(!jws.empty() && err.empty());
    CHECK(acme::jws_verify(key, jws, err));
    std::string tampered = jws;
    tampered.replace(tampered.find("\"payload\":\"") + 11, 1, "A");
    CHECK(!acme::jws_verify(key, tampered, err));
    CHECK(acme::jws_sign("not a key", "{}", "", err).empty() && !err.empty());
    // Renewal: at a third of the lifetime left (90-day certificate: 30 days), never before.
    const auto t0 = system_clock::time_point{};
    const auto ninety = t0 + hours(24 * 90);
    CHECK(!acme::renewal_due(t0, ninety, t0 + hours(24 * 59)));
    CHECK(acme::renewal_due(t0, ninety, t0 + hours(24 * 61)));
    CHECK(acme::renewal_due(t0, ninety, ninety + hours(1)));
    CHECK(!acme::renewal_due(t0, t0 + hours(24 * 6), t0 + hours(24 * 3)));  // 6-day certificate renews after day 4
    CHECK(acme::renewal_due(t0, t0 + hours(24 * 6), t0 + hours(24 * 4) + hours(1)));
    std::string why;
    CHECK(acme::needs_renewal("/nonexistent/fullchain.pem", {"a.test"}, system_clock::now(), why) && why == "no certificate yet");
    // Configuration: tls = "auto" resolves the storage paths; the rules for it.
    const auto dir = std::filesystem::temp_directory_path() / "agensio-acme-test";
    std::filesystem::create_directories(dir);
    {
        std::ofstream(dir / "a.toml") << "[server]\nacme = { email = \"me@x.test\" }\n[[site]]\nserver_name = [\"a.test\", \"www.a.test\"]\nlisten = [\"127.0.0.1:8443\"]\nroot = \"" << dir.string() << "\"\ntls = \"auto\"\n";
        const Config cfg = load_config(dir / "a.toml");
        CHECK(cfg.acme.enabled && cfg.acme.storage == "/var/lib/agensio/acme" && cfg.acme.directory.find("letsencrypt") != std::string::npos);
        CHECK(cfg.sites[0].tls && cfg.sites[0].tls->automatic && cfg.sites[0].tls->cert == "/var/lib/agensio/acme/a.test/fullchain.pem");
        const auto sites = acme::sites_of(cfg);
        CHECK(sites.size() == 1 && sites[0].names.size() == 2 && sites[0].key == "/var/lib/agensio/acme/a.test/key.pem");
    }
    auto refused = [&](const std::string& body, const std::string& what) {
        std::ofstream(dir / "b.toml") << body;
        try {
            load_config(dir / "b.toml");
            return false;
        } catch (const std::exception& e) {
            return std::string(e.what()).find(what) != std::string::npos;
        }
    };
    const std::string site = "[[site]]\nserver_name = [\"a.test\"]\nlisten = [\"127.0.0.1:8443\"]\nroot = \"" + dir.string() + "\"\n";
    CHECK(refused(site + "tls = \"auto\"\n", "needs [server] acme"));
    CHECK(refused("[server]\nacme = { email = \"me@x.test\" }\n" + site + "tls = \"manual\"\n", "\"auto\" or a table"));
    CHECK(refused("[server]\nacme = { email = \"me@x.test\", directory = \"http://ca\" }\n" + site, "must be an https:// URL"));
    CHECK(refused("[server]\nacme = { email = \"nope\" }\n" + site, "server.acme.email"));
    CHECK(refused("[server]\nacme = \"yes\"\n" + site, "server.acme must be a table"));
    // redirect = "https": no root needed, only on plain sites, "https" or an https://host[:port] prefix.
    {
        std::ofstream(dir / "r.toml") << "[[site]]\nserver_name = [\"a.test\"]\nlisten = [\"127.0.0.1:80\"]\nredirect = \"https\"\n[[site]]\nserver_name = [\"b.test\"]\nlisten = [\"127.0.0.1:80\"]\nredirect = \"https://b.test:8443\"\n";
        const Config cfg = load_config(dir / "r.toml");
        CHECK(cfg.sites.size() == 2 && cfg.sites[0].redirect == "https" && cfg.sites[1].redirect == "https://b.test:8443");
    }
    const std::string plain = "[[site]]\nserver_name = [\"a.test\"]\nlisten = [\"127.0.0.1:80\"]\n";
    CHECK(refused(plain + "redirect = \"http://a.test\"\n", "redirect must be"));
    CHECK(refused(plain + "redirect = \"https://a.test/path\"\n", "redirect must be"));
    CHECK(refused(plain + "redirect = true\n", "redirect must be a string"));
    CHECK(refused("[server]\nacme = { email = \"me@x.test\" }\n" + plain + "redirect = \"https\"\ntls = \"auto\"\n", "would loop"));
    {   // the bare name on 443 redirecting to www: allowed, with its own automatic certificate
        std::ofstream(dir / "c.toml") << "[server]\nacme = { email = \"me@x.test\" }\n" + plain + "redirect = \"https://www.a.test\"\ntls = \"auto\"\n";
        const Config cfg = load_config(dir / "c.toml");
        CHECK(cfg.sites.size() == 1 && cfg.sites[0].redirect == "https://www.a.test" && cfg.sites[0].tls && cfg.sites[0].tls->automatic);
    }
    std::filesystem::remove_all(dir);
}
#endif

static void test_control() {
    RoleGroups g;
    g.admins = 100;
    g.operators = 200;
    g.viewers = 300;
    CHECK(role_of(0, 0, {}, 33, g) == Role::admin);          // root
    CHECK(role_of(33, 33, {}, 33, g) == Role::admin);        // the server's own user
    CHECK(role_of(1000, 100, {}, 33, g) == Role::admin);     // primary group
    CHECK(role_of(1000, 1000, {5, 200}, 33, g) == Role::operator_);
    CHECK(role_of(1000, 1000, {300}, 33, g) == Role::viewer);
    CHECK(role_of(1000, 1000, {100, 300}, 33, g) == Role::admin);  // the highest membership wins
    CHECK(role_of(1000, 1000, {7}, 33, g) == Role::none);
    CHECK(role_of(1000, 1000, {}, 33, RoleGroups{}) == Role::none);  // no groups configured: root and server only
    CHECK(role_name(Role::operator_) == "operator" && role_name(Role::none) == "none");
    CHECK(static_cast<std::uint8_t>(Role::admin) > static_cast<std::uint8_t>(Role::viewer));
    // The synthetic control site routes everything to the control handler.
    const SiteConfig site = control_site();
    CHECK(site.locations.size() == 1 && site.locations[0].kind == HandlerKind::control && site.is_default);
    CHECK(Router::location(site, "/v1/status").kind == HandlerKind::control);
    // [control] parsing: defaults and the audit path next to the error log.
    const auto dir = std::filesystem::temp_directory_path() / "agensio-control-test";
    std::filesystem::create_directories(dir);
    std::ofstream(dir / "a.toml") << "[log]\nerror = \"" << dir.string() << "/logs/error.log\"\n[control]\nadmins = \"wheel\"\n[[site]]\nserver_name = [\"a.test\"]\nlisten = [\"127.0.0.1:80\"]\nroot = \"" << dir.string() << "\"\n";
    const Config cfg = load_config(dir / "a.toml");
    CHECK(cfg.control.enabled && cfg.control.admins == "wheel" && cfg.control.operators.empty());
    CHECK(cfg.control.socket.ends_with("/agensio/control.sock") && cfg.control.audit == dir.string() + "/logs/audit.log");
    std::ofstream(dir / "b.toml") << "[[site]]\nserver_name = [\"a.test\"]\nlisten = [\"127.0.0.1:80\"]\nroot = \"" << dir.string() << "\"\n";
    CHECK(!load_config(dir / "b.toml").control.enabled);
    std::ofstream(dir / "c.toml") << "control = 1\n[[site]]\nserver_name = [\"a.test\"]\nlisten = [\"127.0.0.1:80\"]\nroot = \"" << dir.string() << "\"\n";
    bool refused = false;
    try { load_config(dir / "c.toml"); } catch (const std::exception& e) { refused = std::string(e.what()).find("control must be a table") != std::string::npos; }
    CHECK(refused);
    std::filesystem::remove_all(dir);
}

static void test_control_commands() {
    using namespace control;
    LogLine l;
    CHECK(parse_log_line("2026/09/18 21:44:39 [warn] reloaded x\n", l) && l.source == "error" && l.level == "warn" && l.time > 0);
    CHECK(parse_log_line("127.0.0.1 - - [18/Sep/2026:21:44:39 +0300] \"GET /x?y HTTP/1.1\" 404 150 \"-\" \"curl\"", l));
    CHECK(l.status == 404 && l.level.empty());
    const std::time_t combined = l.time;
    CHECK(parse_log_line(R"({"time":"2026-09-18T21:44:39+03:00","remote":"127.0.0.1","status":502,"bytes":1})", l));
    CHECK(l.status == 502 && l.time == combined);  // the same instant in both formats
    CHECK(parse_log_line(R"({"time":"2026-09-18T18:44:39+00:00","status":200})", l) && l.time == combined);  // zone applied
    CHECK(!parse_log_line("garbage", l) && !parse_log_line("", l) && !parse_log_line("{\"time\":\"x\"}", l));
    std::time_t t = 0;
    const std::time_t now = 1000000;
    CHECK(parse_since("3h", now, t) && t == now - 3 * 3600);
    CHECK(parse_since("45m", now, t) && t == now - 2700 && parse_since("2d", now, t) && t == now - 2 * 86400);
    CHECK(parse_since("90", now, t) && t == now - 90 && !parse_since("3x", now, t) && !parse_since("", now, t));
    CHECK(parse_since("2026-09-18T10:00:00", now, t) && t > 1700000000);
    CHECK(query_value("/v1/logs?site=a.test&since=3h&x=a%20b+c", "since") == "3h");
    CHECK(query_value("/v1/logs?site=a.test&since=3h&x=a%20b+c", "x") == "a b c");
    CHECK(query_value("/v1/logs?site=a.test", "nope").empty() && query_value("/v1/logs", "site").empty());
    // Backward scan: newest lines first, then chronological; trailing newline; since bound; byte cap.
    const auto dir = std::filesystem::temp_directory_path() / "agensio-ctl-test";
    std::filesystem::create_directories(dir);
    {
        std::ofstream f(dir / "error.log");
        f << "2026/09/18 10:00:00 [info] one\n2026/09/18 11:00:00 [error] two\n2026/09/18 12:00:00 [warn] three\n\n2026/09/18 13:00:00 [error] four\n";
    }
    LogQuery q;
    std::vector<LogLine> out;
    bool truncated = false;
    scan_log(dir / "error.log", "error", q, out, truncated);
    CHECK(out.size() == 3 && out[0].text.ends_with("two") && out[2].text.ends_with("four") && !truncated);
    out.clear();
    q.level = "error";
    q.limit = 1;
    scan_log(dir / "error.log", "error", q, out, truncated);
    CHECK(out.size() == 1 && out[0].text.ends_with("four"));
    out.clear();
    q.limit = 100;
    q.level = "info";
    q.max_bytes = 60;  // only the tail: the partial first line is dropped
    scan_log(dir / "error.log", "error", q, out, truncated);
    CHECK(truncated && !out.empty() && out.size() < 4);
    out.clear();
    q.max_bytes = 1 << 20;
    parse_log_line("2026/09/18 12:30:00 [info] x", l);
    q.since = l.time;
    scan_log(dir / "error.log", "error", q, out, truncated);
    CHECK(out.size() == 1 && out[0].text.ends_with("four"));
    // The sources of logs(): the server-wide access log is "access" whoever shares it, a site's
    // own file carries its name, a site on the shared file is answered with the note; JSON lines
    // are filtered to the site's names (2026-10-02 report against alpha.42).
    {
        const std::string shared = (dir / "shared.log").string(), own = (dir / "a.log").string();
        std::ofstream(shared) << "203.0.113.5 - - [02/Oct/2026:10:00:01 +0000] \"GET /wp-login.php HTTP/1.1\" 404 150 \"-\" \"scan\"\n"
                                 "203.0.113.5 - - [02/Oct/2026:10:00:02 +0000] \"GET /.env HTTP/1.1\" 404 150 \"-\" \"scan\"\n"
                                 "198.51.100.2 - - [02/Oct/2026:10:00:03 +0000] \"GET / HTTP/1.1\" 301 0 \"-\" \"x\"\n";
        std::ofstream(own) << "192.0.2.9 - - [02/Oct/2026:10:00:04 +0000] \"POST /login HTTP/1.1\" 401 0 \"-\" \"x\"\n";
        std::ofstream(dir / "l.toml") << "[log]\naccess = \"" << shared << "\"\n[[site]]\nserver_name = [\"a.test\"]\nlisten = [\"127.0.0.1:8080\"]\nroot = \"" << dir.string()
                                      << "\"\naccess_log = \"" << own << "\"\n[[site]]\nserver_name = [\"b.test\"]\nlisten = [\"127.0.0.1:8080\"]\nroot = \"" << dir.string()
                                      << "\"\n[[site]]\nserver_name = [\"*\"]\nlisten = [\"127.0.0.1:8080\"]\nroot = \"" << dir.string() << "\"\n";
        const Config cfg = load_config(dir / "l.toml");
        LogQuery all;
        all.status_min = 300;
        all.since = 0;
        json::Value r = logs(cfg, all);
        std::string by_source;
        for (const auto& l : r["lines"].items()) by_source += std::string(l.get("source")) + " ";
        CHECK(by_source == "access access access a.test " && r["sources"].items().size() == 2);
        CHECK(r["sources"].items()[0].get("file") == shared && r["sources"].items()[0].get("source") == "access" && r["sources"].items()[0]["sites"].items().size() == 2 &&
              r["sources"].items()[1].get("source") == "a.test" && r["sources"].items()[1]["sites"].items().size() == 1);
        LogQuery one = all;
        one.site = "a.test";
        r = logs(cfg, one);
        CHECK(r["count"].num() == 1 && r["lines"].items()[0].get("source") == "a.test" && r["shared"].is_null());
        one.site = "b.test";
        r = logs(cfg, one);
        CHECK(r["count"].num() == 3 && r["lines"].items()[0].get("source") == "access" && r["shared"].boolean() && r["shared_with"].items().size() == 1 &&
              r["shared_with"].items()[0].str() == "*" && r.get("note").find("combined format carries no host name") != std::string_view::npos);
        // JSON lines carry the host: b.test gets its own, the catch-all gets what no other site claims.
        std::ofstream(shared) << "{\"time\":\"2026-10-02T10:00:01+00:00\",\"remote\":\"203.0.113.5\",\"host\":\"b.test\",\"method\":\"GET\",\"target\":\"/x\",\"proto\":\"HTTP/1.1\",\"status\":404,\"bytes\":1}\n"
                                 "{\"time\":\"2026-10-02T10:00:02+00:00\",\"remote\":\"203.0.113.5\",\"host\":\"203.0.113.9:80\",\"method\":\"GET\",\"target\":\"/\",\"proto\":\"HTTP/1.1\",\"status\":404,\"bytes\":1}\n"
                                 "{\"time\":\"2026-10-02T10:00:03+00:00\",\"remote\":\"203.0.113.5\",\"host\":\"B.test:8080\",\"method\":\"GET\",\"target\":\"/y\",\"proto\":\"HTTP/1.1\",\"status\":500,\"bytes\":1}\n";
        r = logs(cfg, one);
        CHECK(r["count"].num() == 2 && r["lines"].items()[0].get("text").find("/x") != std::string_view::npos && r["lines"].items()[1].get("text").find("/y") != std::string_view::npos &&
              r.get("note").find("JSON lines carry the host") != std::string_view::npos);
        one.site = "*";
        CHECK(find_site(cfg, "*") != nullptr);
        r = logs(cfg, one);
        CHECK(r["count"].num() == 1 && r["lines"].items()[0].get("text").find("203.0.113.9") != std::string_view::npos);
        r = logs(cfg, all);
        CHECK(r["count"].num() == 4);
        // A client's raw bytes in an older file are answered as valid text; well-formed UTF-8 stays.
        CHECK(utf8_escaped("caf\xC3\xA9 \xE9-\xEE\xFF ok") == "caf\xC3\xA9 \\xE9-\\xEE\\xFF ok" && utf8_escaped("plain") == "plain" &&
              utf8_escaped("\xE2\x82\xAC \xF0\x9F\x98\x80 \xED\xA0\x80 \xC0\xAF \xF4\x90\x80\x80") == "\xE2\x82\xAC \xF0\x9F\x98\x80 \\xED\\xA0\\x80 \\xC0\\xAF \\xF4\\x90\\x80\\x80");
        CHECK(utf8_sequence("a", 0) == 1 && utf8_sequence("\xC3\xA9", 0) == 2 && utf8_sequence("\xC3", 0) == 0 && utf8_sequence("\x80", 0) == 0 && utf8_sequence("\xE0\x9F\xBF", 0) == 0 &&
              utf8_sequence("\xE0\xA0\x80", 0) == 3 && utf8_sequence("\xF0\x90\x80\x80", 0) == 4 && utf8_sequence("\xF0\x8F\xBF\xBF", 0) == 0 && utf8_sequence("\xF5\x80\x80\x80", 0) == 0);
        std::ofstream(own) << "192.0.2.9 - - [02/Oct/2026:10:00:04 +0000] \"GET /caf\xE9-\xEE\xFF HTTP/1.1\" 404 0 \"-\" \"x\"\n";
        one.site = "a.test";
        r = logs(cfg, one);
        CHECK(r["count"].num() == 1 && r["lines"].items()[0].get("text").find("/caf\\xE9-\\xEE\\xFF HTTP") != std::string_view::npos);
    }
    // Health: a manual TLS site with a missing certificate, no redirect, two application sites without users.
    {
        std::ofstream(dir / "www.html") << "x";
        std::ofstream(dir / "h.toml") << "[log]\nerror = \"" << (dir / "error.log").string() << "\"\n"
            << "[[site]]\nserver_name = [\"a.test\"]\nlisten = [\"127.0.0.1:8443\"]\nroot = \"" << dir.string() << "\"\ntls = { cert = \"" << (dir / "www.html").string() << "\", key = \"" << (dir / "www.html").string() << "\" }\n"
            << "[[site]]\nserver_name = [\"b.test\"]\nlisten = [\"127.0.0.1:8080\"]\nroot = \"" << dir.string() << "\"\nphp = { socket = \"127.0.0.1:9000\" }\n"
            << "[[site]]\nserver_name = [\"c.test\"]\nlisten = [\"127.0.0.1:8080\"]\nroot = \"" << dir.string() << "\"\nphp = { socket = \"127.0.0.1:9000\" }\n";
        const Config cfg = load_config(dir / "h.toml");
        const auto f = health_findings(cfg, cfg, true, std::time(nullptr));
        auto has = [&](std::string_view code) { return std::any_of(f.begin(), f.end(), [&](const Finding& x) { return x.code == code; }); };
        CHECK(has("running_as_root") && has("certificate_unreadable") && has("no_http_redirect") && has("shared_account"));
        CHECK(!has("config_invalid") && !has("restart_needed") && !has("acme_needs_port_80"));
        // The recent-errors rule reads the error log written above (dates in 2026: within 24 h only if today).
        Config changed = cfg;
        changed.workers = cfg.workers + 3;
        CHECK(restart_needed(changed, cfg) == std::vector<std::string>{"workers"});
        // The task keys apply on reload: the helper reads them from root's file for every task.
        Config tasks_changed = cfg;
        tasks_changed.control.runtimes.ruby = "/opt/ruby-3.4.7/bin";
        tasks_changed.control.task_timeout = 60;
        tasks_changed.control.task_processes = 64;
        tasks_changed.control.task_network = false;
        CHECK(restart_needed(tasks_changed, cfg).empty());
        const json::Value h = health(cfg, cfg, false, std::time(nullptr));
        CHECK(!h["ok"].boolean() && h["findings"].items().size() == h["count"].num());
        const json::Value s = sites(cfg, std::time(nullptr));
        CHECK(s["count"].num() == 3 && s["sites"].items()[0]["tls"].get("mode") == "manual" && !s["sites"].items()[0]["tls"]["present"].boolean());
        CHECK(find_site(cfg, "B.TEST") == &cfg.sites[1] && find_site(cfg, "z.test") == nullptr);
        const json::Value v = validate(dir / "h.toml", cfg);
        CHECK(v["ok"].boolean() && v["sites"].num() == 3);
        std::ofstream(dir / "bad.toml") << "[[site]\n";
        CHECK(!validate(dir / "bad.toml", cfg)["ok"].boolean());
    }
    std::filesystem::remove_all(dir);
}

static void test_control_sites() {
    using namespace control;
    CHECK(valid_domain("example.com") && valid_domain("www.shop-1.example.co.uk") && valid_domain("xn--80ak6aa92e.com"));
    CHECK(!valid_domain("Example.com") && !valid_domain("example") && !valid_domain("-a.com") && !valid_domain("a-.com"));
    CHECK(!valid_domain("a..com") && !valid_domain(".a.com") && !valid_domain("a.com/x") && !valid_domain("a b.com"));
    CHECK(!valid_domain(std::string(64, 'a') + ".com") && !valid_domain("../etc.com"));
    CHECK(suggest_user("www.example.com") == "example" && suggest_user("shop.example.com") == "shop" && suggest_user("123.com") == "web123");
    const auto dir = std::filesystem::temp_directory_path() / "agensio-sites-test";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir / "www");
    CHECK(detect_app(dir / "www") == "static");
    std::ofstream(dir / "www" / "index.php") << "<?php";
    CHECK(detect_app(dir / "www") == "php");
    std::ofstream(dir / "www" / "wp-config.php") << "<?php";
    CHECK(detect_app(dir / "www") == "wordpress");
    std::filesystem::create_directories(dir / "www" / "bin");
    std::filesystem::create_directories(dir / "www" / "system");
    std::ofstream(dir / "www" / "bin" / "grav") << "#!";
    CHECK(detect_app(dir / "www") == "wordpress");  // bin/grav alone is not Grav
    std::ofstream(dir / "www" / "system" / "defines.php") << "<?php";
    CHECK(detect_app(dir / "www") == "grav" && detect_app_marker("grav") == "bin/grav and system/defines.php");
    std::ofstream(dir / "artisan") << "#!";
    CHECK(detect_app(dir / "www") == "laravel");
    CHECK(detect_app(dir / "nope").empty());
    // A Django project by its manage.py, Wagtail's by its requirements (2026-09-28).
    std::filesystem::create_directories(dir / "dj");
    std::ofstream(dir / "dj" / "manage.py") << "#!/usr/bin/env python";
    CHECK(detect_app(dir / "dj") == "django");
    std::ofstream(dir / "dj" / "requirements.txt") << "Django>=6.1,<6.2\nwagtail>=8.0,<8.1\n";
    CHECK(detect_app(dir / "dj") == "wagtail" && detect_app_marker("wagtail").find("manage.py") != std::string::npos);
    CHECK(suggest_project("www.example.com") == "example" && suggest_project("my-blog.example.com") == "my_blog" && suggest_project("123.com") == "site123" &&
          suggest_project("django.example.com") == "django_site" && check_project_name(suggest_project("test.example.com")).empty());
    // Decisions: everything open, then closed one by one; explicit null user counts as decided.
    Config cfg;
    cfg.config_path = dir / "agensio.toml";
    cfg.includes = {"sites.d/*.toml"};
    SiteSpec spec;
    std::string err;
    json::Value body;
    CHECK(json::parse(R"({"domain":"shop.test"})", body, err));
    auto needs = apply_request(body, cfg, spec, err);
    CHECK(err.empty() && needs.size() == 4);
    CHECK(needs[0].field == "https" && needs[1].field == "root" && needs[2].field == "app" && needs[3].field == "user" && needs[3].suggestion == "shop");
    CHECK(json::parse(R"({"https":"auto"})", body, err) && (apply_request(body, cfg, spec, err), err.find("acme") != std::string::npos));
    err.clear();
    cfg.acme.enabled = true;
    CHECK(json::parse(R"({"https":"auto","root":")" + (dir / "www").string() + R"(","user":null})", body, err));
    needs = apply_request(body, cfg, spec, err);
    CHECK(err.empty() && needs.size() == 1 && needs[0].field == "app" && needs[0].suggestion.starts_with("laravel"));
    CHECK(json::parse(R"({"app":"php"})", body, err));
    needs = apply_request(body, cfg, spec, err);
    CHECK(needs.size() == 1 && needs[0].field == "php_socket");  // no user, so no generated pool
    CHECK(json::parse(R"({"user":"shop","app":"laravel","aliases":["www.shop.test"]})", body, err));
    needs = apply_request(body, cfg, spec, err);
    CHECK(err.empty() && needs.empty() && spec.user == "shop" && spec.app == "laravel");
    CHECK(json::parse(R"({"app":"weird"})", body, err) && (apply_request(body, cfg, spec, err), err.find("app must be one of: static, php, laravel, drupal, wordpress, grav, proxy") != std::string::npos));
    CHECK(app_presets().size() == 12 && app_presets().front() == "static" && app_presets()[5] == "grav" && app_presets()[6] == "proxy" && app_presets()[7] == "rails" &&
          app_presets()[8] == "redmine" && app_presets()[9] == "django" && app_presets()[10] == "wagtail" && app_presets().back() == "node");
    const json::Value catalog = preset_catalog();
    CHECK(catalog["presets"].items().size() == 12 && catalog["presets"].items()[8].get("app") == "redmine" && catalog["presets"].items()[8]["tasks"].items().size() == 8 &&
          catalog["presets"].items()[11].get("app") == "node" && catalog["presets"].items()[11]["tasks"].items().size() == 2 &&
          catalog["presets"].items()[9].get("app") == "django" && catalog["presets"].items()[9]["tasks"].items().size() == 9 &&
          catalog["presets"].items()[10].get("app") == "wagtail" && catalog["presets"].items()[10]["tasks"].items().size() == 9 &&
          catalog["presets"].items()[0].get("app") == "static" && catalog["presets"].items()[5].get("app") == "grav" &&
          catalog["presets"].items()[6].get("app") == "proxy" && catalog["presets"].items()[7].get("app") == "rails" &&
          catalog["presets"].items()[7]["tasks"].items().size() == 7 && catalog["presets"].items()[7]["secrets"].items()[0].str() == "/config/master.key");
    // A Django or Wagtail site asks for its project, checks it, writes it, and names the tasks
    // still open by what its directory holds (2026-09-28).
    {
        const std::size_t npos = std::string::npos;
        SiteSpec ds;
        json::Value b;
        std::string e;
        CHECK(json::parse(R"({"domain":"blog.example.com","https":"none","user":"bl","app":"wagtail","upstream":"http://127.0.0.1:3008"})", b, e));
        auto nd = apply_request(b, cfg, ds, e);
        std::string project_suggestion, root_question;
        for (const auto& d : nd) {
            if (d.field == "project") project_suggestion = d.suggestion;
            if (d.field == "root") root_question = d.question;
        }
        CHECK(e.empty() && project_suggestion == "blog" && root_question.find("Django project") != npos);
        const std::string proot = (dir / "wagapp").string();
        CHECK(json::parse(("{\"project\":\"blog\",\"root\":\"" + proot + "\"}").c_str(), b, e));
        nd = apply_request(b, cfg, ds, e);
        CHECK(e.empty() && nd.empty() && ds.project == "blog");
        const std::string file = render_site(ds, "x");
        SiteSpec back;
        CHECK(file.find("project = \"blog\"\n") != npos && file.find("app = \"wagtail\"\n") != npos && SiteSpec::from_json(ds.to_json(), back) && back.project == "blog");
        SiteSpec bad = ds;
        CHECK(json::parse(R"({"project":"Bad-Name"})", b, e) && (apply_request(b, cfg, bad, e), e.find("not a Python package name") != npos));
        SiteSpec plain;
        e.clear();
        CHECK(json::parse(R"({"domain":"p.example.com","https":"none","no_user":true,"app":"static","root":"/var/www/p","project":"blog"})", b, e) &&
              (apply_request(b, cfg, plain, e), e.find("goes with app") != npos));
        auto step = [&] {
            for (const auto& st : next_steps(ds, cfg))
                if (st.find("site-task") != npos) return st;
            return std::string();
        };
        std::filesystem::create_directories(proot);
        CHECK(step().find("a new Wagtail site: site-task blog.example.com venv_create, pip_install --param \"packages=wagtail gunicorn\" (you confirm it), startproject (it creates the project blog)") != npos);
        std::ofstream(proot + "/manage.py") << "#!";
        CHECK(step().find("the project is in place: site-task blog.example.com venv_create, pip_install_requirements") != npos &&
              step().find("--generate DJANGO_SECRET_KEY") != npos && step().find("startproject") == npos && step().find("packages=gunicorn") != npos);
        std::ofstream(proot + "/agensio_settings.py") << "#";
        CHECK(step().find("settings are in place: site-task blog.example.com migrate, collectstatic") != npos);
        std::filesystem::create_directories(proot + "/static");
        CHECK(step().find("migrate after an upgrade") != npos);
        ds.app = "django";
        std::filesystem::remove_all(proot);
        std::filesystem::create_directories(proot);
        CHECK(step().find("packages=django gunicorn") != npos);
    }
    // A Node site's open steps follow its directory too (2026-09-28).
    {
        const std::size_t npos = std::string::npos;
        const std::string nroot = (dir / "nodeapp").string();
        SiteSpec ns;
        ns.domain = "kuma.example.com";
        ns.https = "none";
        ns.app = "node";
        ns.root = nroot;
        ns.upstream = "http://127.0.0.1:3009";
        auto first = [&] {
            for (const auto& st : next_steps(ns, cfg))
                if (st.find("site-task") != npos || st.find("site-update") != npos || st.find("site-install") != npos) return st;
            return std::string();
        };
        std::filesystem::create_directories(nroot);
        CHECK(first().find("a Node application: site-install kuma.example.com") != npos && first().find("--entry FILE") != npos);
        std::ofstream(nroot + "/package.json") << "{}";
        CHECK(first().find("the application is in place: site-task kuma.example.com npm_ci") != npos);
        std::filesystem::create_directories(nroot + "/node_modules");
        CHECK(first().find("its dependencies are installed: site-update kuma.example.com --entry FILE") != npos);
        ns.entry = "server/server.js";
        CHECK(first().find("npm_ci after its lockfile changed") != npos && first().find("--entry") == npos);
        std::string e;
        SiteSpec bad = ns;
        json::Value b;
        CHECK(json::parse(R"({"entry":"../evil.js"})", b, e) && (apply_request(b, cfg, bad, e), e.find("relative") != npos));
        std::filesystem::remove_all(nroot);
    }
    CHECK(catalog["presets"].items()[5]["never_served_directories"].items().size() == 9 && catalog["presets"].items()[5]["never_served_directories"].items()[0].str() == "/logs/" &&
          catalog["presets"].items()[3]["never_served_directories"].items().empty() && catalog["presets"].items()[5].get("source").starts_with("https://getgrav.org/"));
    const json::Value& laravel_row = catalog["presets"].items()[2];
    CHECK(laravel_row.get("app") == "laravel" && !laravel_row.get("summary").empty() && laravel_row.get("php").starts_with("only /index.php"));
    // The php preset refuses SQLite files and web.config (2026-10-01, the Kanboard proposal: data/db.sqlite was downloadable).
    {
        const json::Value& php_row = catalog["presets"].items()[1];
        std::string refused, never;
        for (const auto& r : php_row["refused_suffixes"].items()) refused += std::string(r.str()) + " ";
        for (const auto& r : php_row["never_served"].items()) never += std::string(r.str()) + " ";
        CHECK(php_row.get("app") == "php" && refused.find(".sqlite ") != std::string::npos && refused.find(".sqlite3 ") != std::string::npos &&
              refused.find(".db ") != std::string::npos && never == "/web.config ");
    }
    CHECK(catalog["presets"].items()[3]["never_served"].items().size() == 9 && catalog["presets"].items()[3]["no_php_under"].items().size() == 5);
    err.clear();
    CHECK(json::parse(R"({"aliases":["bad host"]})", body, err) && (apply_request(body, cfg, spec, err), err.find("alias") != std::string::npos));
    err.clear();
    // Values that reach root commands are validated first; hostile or sentinel values are refused.
    spec.app = "laravel";               // the probes above left "weird" and a bad alias behind
    spec.aliases = {"www.shop.test"};
    err.clear();
    std::string why;
    for (const char* bad : {"null", "none", "nil", "undefined", "false", "true", "~", "", "root", "nobody", "www-data",
                            "Shop", "a b", "a;b", "$(id)", "../x", "web1;rm -rf /", "a\nb", "toolongtoolongtoolongtoolongtoolong"})
        CHECK(!valid_account(bad, why));
    CHECK(valid_account("web1", why) && valid_account("_svc", why) && valid_account("t1-shop", why));
    CHECK(!valid_account("null", why) && why.find("no_user: true") != std::string::npos);
    for (const char* bad : {"relative/x", "/a/../b", "/a b", "/a;b", "/a$(x)", "/a//b", "/a/", "/tmp/x\n", "/a/`id`"})
        CHECK(!safe_path(bad, why));
    CHECK(safe_path("/var/www/shop.test/web", why) && safe_path("/", why));
    for (const char* payload : {R"({"user":"null"})", R"({"user":"a;b"})", R"({"group":"none"})", R"({"root":"/var/www/x;rm -rf /"})",
                                R"({"https":{"cert":"/etc/x y.pem","key":"/etc/k.pem"}})"}) {
        SiteSpec probe = spec;
        std::string e;
        CHECK(json::parse(payload, body, err) && (apply_request(body, cfg, probe, e), !e.empty()));
        const auto cmds = prerequisites(probe, cfg);  // never a command built from a refused value
        CHECK(cmds.empty() || cmds[0].starts_with("# refused"));
    }
    {
        SiteSpec probe = spec;
        std::string e;
        CHECK(json::parse(R"({"user":"web1","no_user":true})", body, err) && (apply_request(body, cfg, probe, e), e.find("no_user is true but user") != std::string::npos));
    }
    // The two ways to say "no account" agree; the decision text names the boolean.
    SiteSpec none_a = spec, none_b = spec;
    none_a.php_socket = none_b.php_socket = "127.0.0.1:9000";  // a PHP site without an account needs an existing pool
    CHECK(json::parse(R"({"no_user":true})", body, err) && apply_request(body, cfg, none_a, err).empty() && none_a.user.empty() && none_a.no_user);
    CHECK(json::parse(R"({"user":null})", body, err) && apply_request(body, cfg, none_b, err).empty() && none_b.user.empty() && none_b.no_user);
    SiteSpec undecided;
    undecided.domain = "shop.test";
    CHECK(json::parse(R"({"domain":"shop.test","https":"none","app":"static","root":"/var/www/x"})", body, err));
    const auto asks = apply_request(body, cfg, undecided, err);
    CHECK(asks.size() == 1 && asks[0].field == "user" && asks[0].question.find("no_user: true") != std::string::npos);
    spec.aliases = {"www.shop.test"};
    spec.app = "laravel";  // the "weird" probe left its value behind
    // Rendering: HTTPS-only with the redirect site, the managed header round-trips.
    spec.hsts = true;
    const std::string text = render_site(spec, "2026-09-18");
    CHECK(text.starts_with(kManagedMarker));
    CHECK(text.find("listen = [\"0.0.0.0:80\"]\nredirect = \"https\"") != std::string::npos);
    CHECK(text.find("listen = [\"0.0.0.0:443\"]\nroot = ") != std::string::npos && text.find("app = \"laravel\"") != std::string::npos);
    CHECK(text.find("user = \"shop\"") != std::string::npos && text.find("tls = \"auto\"") != std::string::npos);
    CHECK(text.find("Strict-Transport-Security") != std::string::npos && text.find("server_name = [\"shop.test\", \"www.shop.test\"]") != std::string::npos);
    std::filesystem::create_directories(dir / "sites.d");
    err.clear();
    CHECK(write_site_file(site_file(cfg, "shop.test"), text, err) && err.empty());
    SiteSpec back;
    CHECK(read_managed(site_file(cfg, "shop.test"), back) && back.domain == "shop.test" && back.user == "shop" && back.user_decided && back.hsts && back.aliases.size() == 1);
    CHECK(write_site_file(site_file(cfg, "shop.test"), text + "\n", err) && std::filesystem::exists(dir / "sites.d" / "shop.test.toml.bak"));
    std::ofstream(dir / "sites.d" / "hand.toml") << "[[site]]\n";
    CHECK(!read_managed(dir / "sites.d" / "hand.toml", back));
    CHECK(sites_dir_included(cfg));
    cfg.includes = {"conf.d/*.toml"};
    CHECK(!sites_dir_included(cfg));
    // A plain-only site renders one block; proxy renders app and upstream.
    SiteSpec plain;
    plain.domain = "a.test";
    plain.https = "none";
    plain.app = "proxy";
    plain.upstream = "http://127.0.0.1:3000";
    const std::string whole = render_site(plain, "x");
    const std::string p = whole.substr(whole.find("\n[[site]]"));  // past the managed header
    CHECK(p.find("redirect") == std::string::npos && p.find("app = \"proxy\"\nupstream = \"http://127.0.0.1:3000\"") != std::string::npos);
    CHECK(std::count(p.begin(), p.end(), '[') == 2 + 1 + 1);  // one [[site]] block: server_name and listen lists
    // The managed file the loader accepts.
    {
        std::ofstream(dir / "agensio.toml") << "include = [\"sites.d/*.toml\"]\n[server]\nacme = { email = \"a@b.test\" }\n";
        std::filesystem::remove(dir / "sites.d" / "hand.toml");
        std::filesystem::create_directories(dir / "www" / "public");
        SiteSpec ok = spec;
        ok.app = "laravel";  // the "weird" probe above left its value in spec
        ok.root = (dir / "www").string();
        ok.user.clear();
        ok.php_socket = "127.0.0.1:9000";
        CHECK(write_site_file(site_file(cfg, "shop.test"), render_site(ok, "x"), err));
        const Config loaded = load_config(dir / "agensio.toml");
        CHECK(loaded.sites.size() == 2 && loaded.sites[0].redirect == "https" && loaded.sites[1].tls && loaded.sites[1].tls->automatic && loaded.sites[1].app == "laravel");
        // Per-site settings (F10): the allowlist, the ceilings, the refusals, the rendering.
        {
            json::Value out, given;
            std::string e2;
            json::parse(R"({"max_body_size":"200MB","memory_limit":"512M","max_execution_time":120,"children":"4","pm":"Dynamic","max_requests":0})", given, e2);
            CHECK(apply_settings(given, loaded, true, out).empty());
            CHECK(out.get("max_body_size") == "200MB" && out.get("memory_limit") == "512MB" && out["max_execution_time"].num() == 120 && out["children"].num() == 4 && out.get("pm") == "dynamic" && out["max_requests"].num() == 0);
            auto refused = [&](const char* text, bool user, const char* fragment) {
                json::Value g, o;
                json::parse(text, g, e2);
                const std::string r = apply_settings(g, loaded, user, o);
                const bool hit = r.find(fragment) != std::string::npos;
                if (!hit) std::printf("settings: expected '%s', got '%s'\n", fragment, r.c_str());
                return hit;
            };
            // Ceilings: root's; above them refused naming the key, the value and the ceiling.
            CHECK(refused(R"({"max_body_size":"10GB"})", true, "max_body_size: 10GB is above the ceiling 512MB"));
            CHECK(refused(R"({"memory_limit":"8G"})", true, "memory_limit: 8GB is above the ceiling 512MB"));
            CHECK(refused(R"({"children":1000})", true, "children: 1000 is above the ceiling 32"));
            CHECK(refused(R"({"max_execution_time":301})", true, "above the ceiling 300") && refused(R"({"children":0})", true, "below the minimum 1"));
            CHECK(refused(R"({"pm":"forever"})", true, "not one of static, dynamic, ondemand") && refused(R"({"children":"many"})", true, "whole number") && refused(R"({"max_body_size":"big"})", true, "not a size"));
            // Nothing outside the allowlist, whatever it is called: the ini keys that mean code
            // execution or the end of the sandbox are refused by name, as unknown.
            for (const char* key : {"sendmail_path", "auto_prepend_file", "extension", "zend_extension", "disable_functions", "open_basedir", "extra", "error_log", "session.save_path", "php_admin_value[x]"})
                CHECK(refused((std::string("{\"") + key + "\":\"/bin/sh\"}").c_str(), true, "unknown setting"));
            // Pool keys need a site with its own user; max_body_size does not.
            CHECK(refused(R"({"memory_limit":"64M"})", false, "needs a PHP site with its own user"));
            json::Value o2, g2;
            json::parse(R"({"max_body_size":"4MB"})", g2, e2);
            CHECK(apply_settings(g2, loaded, false, o2).empty() && o2.get("max_body_size") == "4MB");
            // The catalogue and the table agree, and the site file round-trips through the loader.
            const json::Value cat = settings_catalog(loaded, nullptr);
            CHECK(cat["settings"].items().size() == setting_defs().size());
            for (std::size_t i = 0; i < setting_defs().size(); ++i) {
                const json::Value& row = cat["settings"].items()[i];
                CHECK(row.get("key") == setting_defs()[i].key && !row.get("applies").empty() && !row["default"].is_null());
            }
            SiteSpec tuned = ok;
            tuned.user = "shop";
            tuned.php_socket.clear();
            tuned.settings = out;
            const std::string rendered = render_site(tuned, "x");
            CHECK(rendered.find("max_body_size = \"200MB\"") != std::string::npos && rendered.find("memory_limit = \"512MB\"") != std::string::npos && rendered.find("children = 4") != std::string::npos && rendered.find("pm = \"dynamic\"") != std::string::npos);
            SiteSpec back;
            CHECK(SiteSpec::from_json(tuned.to_json(), back) && back.settings.get("max_body_size") == "200MB" && back.php_children == 4);
            std::ofstream(dir / "sites.d" / "tuned.toml") << rendered;
            Config tcfg;
            bool loads = true;
            try { tcfg = load_config(dir / "agensio.toml"); } catch (const std::exception& ex) { loads = false; std::printf("tuned: %s\n", ex.what()); }
            CHECK(loads);
            if (loads) {
                const SiteConfig* tsite = nullptr;
                for (const auto& st : tcfg.sites) if (st.user == "shop" && !st.redirect.empty() == false && st.tls) tsite = &st;
                CHECK(tsite && tsite->max_body_size == 200u * 1024 * 1024 && tsite->pool.memory_limit == "512MB" && tsite->pool.children == 4 && tsite->pool.pm == "dynamic" && tsite->pool.max_execution_time == 120);
                if (tsite) {
                    const json::Value eff = effective_settings(*tsite, tcfg);
                    CHECK(eff["max_body_size"].get("value") == "200MB" && eff["max_body_size"].get("source") == "site" && eff["max_input_time"].get("source") == "default" && eff["children"]["value"].num() == 4);
                    CHECK(body_limit_of(*tsite, tcfg) == 200u * 1024 * 1024 && body_limit_of(loaded.sites[1], loaded) == loaded.max_body_size);
                    const std::string pool = render_pool(tcfg, *tsite, "agensio");
                    CHECK(pool.find("php_admin_value[upload_max_filesize] = 200M") != std::string::npos && pool.find("php_admin_value[post_max_size] = 200M") != std::string::npos && pool.find("php_admin_value[max_input_time] = 60") != std::string::npos && pool.find("memory_limit] = 512MB") != std::string::npos);
                }
            }
            std::filesystem::remove(dir / "sites.d" / "tuned.toml");
            // [control] site_limits from the file, and a site-level max_body_size.
            std::ofstream(dir / "lim.toml") << "[control]\nsite_limits = { max_body_size = \"64MB\", children = 4 }\n[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\nmax_body_size = \"3MB\"\n";
            const Config lim = load_config(dir / "lim.toml");
            CHECK(lim.control.site_limits.max_body_size == 64u * 1024 * 1024 && lim.control.site_limits.children == 4 && lim.control.site_limits.memory_limit == 512u * 1024 * 1024 && lim.sites[0].max_body_size == 3u * 1024 * 1024);
            json::Value o3;
            CHECK(apply_settings(g2, lim, false, o3).empty());  // 4MB is under 64MB
            json::Value g4;
            json::parse(R"({"max_body_size":"65MB"})", g4, e2);
            CHECK(!apply_settings(g4, lim, false, o3).empty());
        }
        CHECK(loaded.sites[0].root.empty());  // a redirect site has no document root, never the configuration directory
        CHECK(prerequisites(ok, loaded).empty());
        SiteSpec missing = ok;
        missing.user = "no-such-user-zz";
        missing.root = (dir / "missing").string();
        const auto pre = prerequisites(missing, loaded);
        CHECK(pre.size() == 2 && pre[0].starts_with("useradd --system --no-create-home --home-dir /var/lib/agensio/no-such-user-zz") && pre[1].starts_with("mkdir -p"));
        // Every problem in one answer, with a code each; a privileged port on a dropped server is
        // a non-blocking "needs_restart", and not a problem at all while the server is still root.
        missing.listen_tls = "0.0.0.0:444";  // privileged and not bound by `loaded` (which holds :80 and :443)
        missing.redirect_http = false;       // so only the TLS listener is used
        const auto problems = preflight(missing, loaded, false);
        CHECK(problems.size() == 3 && problems[0].code == "missing_account" && problems[1].code == "root_missing" && problems[2].code == "needs_restart");
        CHECK(problems.size() == 3 && problems[0].blocks && problems[1].blocks && !problems[2].blocks && problems[2].run_as_root == "systemctl restart agensio");
        CHECK(problems.size() == 3 && problems[2].detail.find("0.0.0.0:444") != std::string::npos && preflight(missing, loaded, true).size() == 2);
        // Each fixable problem carries the helper request that resolves it; a certificate has none.
        CHECK(problems.size() == 3 && problems[0].fix.get("op") == "account_add" && problems[0].fix.get("name") == "no-such-user-zz");
        CHECK(problems.size() == 3 && problems[1].fix.get("op") == "site_layout" && problems[1].fix.get("owner") == "no-such-user-zz" && problems[2].fix.get("op") == "service_restart");
        SiteSpec manual = ok;
        manual.https = "manual";
        manual.cert = "/etc/ssl/none.pem";
        manual.key = "/etc/ssl/none.key";
        const auto mp = preflight(manual, loaded, true);
        CHECK(mp.size() == 2 && mp[0].code == "certificate_missing" && mp[0].fix.is_null());
        // The helper's own validation: the same rules, applied to what it is asked, whoever asks.
        Config hcfg = loaded;
        hcfg.control.sites_root = "/srv/sites";
        hcfg.log.access = "/var/log/agensio/access.log";
        auto v = [&](const char* text) { json::Value r; std::string e2; json::parse(text, r, e2); return provision::validate(r, hcfg); };
        CHECK(v(R"({"op":"account_add","name":"shop"})").empty() && !v(R"({"op":"account_add","name":"root"})").empty() && !v(R"({"op":"account_add","name":"null"})").empty());
        CHECK(v(R"({"op":"site_layout","dir":"/srv/sites/a.test/web","owner":"shop"})").empty());
        CHECK(!v(R"({"op":"site_layout","dir":"/etc/agensio","owner":"shop"})").empty() && !v(R"({"op":"site_layout","dir":"/srv/sites","owner":"shop"})").empty());
        CHECK(!v(R"({"op":"site_layout","dir":"/srv/sites/../etc","owner":"shop"})").empty() && !v(R"({"op":"site_layout","dir":"/srv/sites/x","owner":"a;b"})").empty());
        CHECK(v(R"({"op":"log_own","file":"/var/log/agensio/sites/a.test.log","group":"shop"})").empty());
        CHECK(!v(R"({"op":"log_own","file":"/etc/shadow","group":"shop"})").empty() && !v(R"({"op":"log_own","file":"/var/log/agensio/x.txt","group":"shop"})").empty());
        CHECK(v(R"({"op":"pools_apply"})").empty() && v(R"({"op":"service_restart"})").empty() && !v(R"({"op":"shell","cmd":"id"})").empty());
        // A site's environment: a host name and, for a write, a change the rules accept.
        CHECK(v(R"({"op":"env_read","site":"a.test"})").empty() && v(R"({"op":"env_write","site":"a.test","generate":["SECRET_KEY_BASE"]})").empty() &&
              v(R"({"op":"env_check"})").empty() && v(R"({"op":"env_read","site":"a.test","reveal":["A_1"]})").empty() &&
              !v(R"({"op":"env_read","site":"a.test","reveal":["A;B"]})").empty() && !v(R"({"op":"env_read","site":"a.test","reveal":"A"})").empty());
        CHECK(!v(R"({"op":"env_read","site":"../etc"})").empty() && !v(R"({"op":"env_write","site":"a.test"})").empty() &&
              !v(R"({"op":"env_write","site":"a.test","set":{"LD_PRELOAD":"/tmp/x.so"}})").empty() && !v(R"({"op":"env_write","site":"a.test","set":{"A":"x\ny"}})").empty());
        // The service's state and journal: a site's name and bounded numbers, never a unit or an option.
        CHECK(v(R"({"op":"app_status","site":"a.test"})").empty() && v(R"({"op":"app_logs","site":"a.test","lines":50,"since":"3h"})").empty() &&
              v(R"({"op":"app_check"})").empty());
        // The trash (F12b): a site's name, or an entry's name of the form <domain>-<date>-<time>.
        CHECK(v(R"({"op":"site_trash","site":"a.test"})").empty() && v(R"({"op":"site_restore","entry":"a.test-20260930-101500"})").empty() &&
              v(R"({"op":"trash_delete","entry":"a.test-20260930-101500"})").empty() && v(R"({"op":"trash_list"})").empty() && v(R"({"op":"trash_expire"})").empty());
        CHECK(!v(R"({"op":"site_trash","site":"../x"})").empty() && !v(R"({"op":"site_restore","entry":"../x-20260930-101500"})").empty() &&
              !v(R"({"op":"site_restore","entry":"a.test"})").empty() && !v(R"({"op":"trash_delete","entry":"a.test-2026093-101500"})").empty() &&
              !v(R"({"op":"trash_delete","entry":"a.test-20260930-1015000"})").empty() && !v(R"({"op":"trash_delete","entry":"A.test-20260930-101500"})").empty() &&
              !v(R"({"op":"trash_delete","entry":"a.test-20260930-10150a"})").empty() && !v(R"({"op":"trash_delete","entry":""})").empty());
        CHECK(provision::valid_trash_entry("shop.example.com-20260930-235959") && !provision::valid_trash_entry("shop.example.com-20260930-235959/") &&
              !provision::valid_trash_entry(".-20260930-235959") && !provision::valid_trash_entry("-20260930-235959"));
        CHECK(!v(R"({"op":"app_status","site":"../x"})").empty() && !v(R"({"op":"app_logs","site":"a.test","lines":5000})").empty() &&
              !v(R"({"op":"app_logs","site":"a.test","lines":"50"})").empty() && !v(R"({"op":"app_logs","site":"a.test","since":"3 hours"})").empty() &&
              !v(R"({"op":"app_logs","site":"a.test","since":"h"})").empty() && !v(R"({"op":"app_logs","site":"a.test","since":"-1h"})").empty() &&
              !v(R"({"op":"app_logs","site":"a.test","since":"12345h"})").empty());
        SiteSpec high = missing;
        high.listen_tls = "0.0.0.0:8443";
        CHECK(preflight(high, loaded, false).size() == 2);  // an unprivileged port is bound by the reload
        // next steps are separate commands: `agensio pools` exits 3 when it wrote files.
        SiteSpec pooled = ok;
        pooled.user = "shop";
        pooled.php_socket.clear();
        Config pool_cfg = loaded;
        pool_cfg.pools_dir = "/etc/php-fpm.d";
        const auto steps = next_steps(pooled, pool_cfg);
        CHECK(steps.size() >= 2 && steps[0] == "agensio pools" && steps[1] == "systemctl reload php-fpm");
        for (const auto& st : steps) CHECK(st.find("&&") == std::string::npos);
        CHECK(pre[1].find("-type d -exec chown no-such-user-zz:") != std::string::npos && pre[1].find("chmod 2750") != std::string::npos && pre[0].find("/var/www") == std::string::npos);
        // The port-80 note for auto certificates, and the body limit before the first upload.
        CHECK(next_steps(ok, loaded).size() == 2 && next_steps(ok, loaded)[1].find("above 1MB, the server's default, get 413") != std::string::npos);
        {
            // A site with its own limit chose it already: no line (alpha.33 report, P4 c).
            SiteSpec big = ok;
            big.settings = json::Value::object().set("max_body_size", "100MB");
            CHECK(next_steps(big, loaded).size() == 1);
        }
        // The application's own rules (2026-10-01, the Kanboard proposal): checked against the
        // preset, rendered as locations the loader already knows, only ever narrowing the site.
        {
            const std::size_t npos = std::string::npos;
            SiteSpec kb = ok;
            kb.app = "php";
            kb.php_socket = "unix:/run/php/fpm.sock";
            json::Value n;
            auto rules = [&](const char* text, SiteSpec* sp = nullptr) {
                json::Value r;
                std::string e;
                CHECK(json::parse(text, r, e));
                return check_rules(r, sp ? *sp : kb, n);
            };
            CHECK(rules(R"({"private":["/app/","/data/","/cli","/composer.json"],"entry_points":["/index.php","/jsonrpc.php"],"cache":[{"path":"/assets/","max_age":604800}],"front_controller":"/index.php"})").empty() &&
                  n["private"].items().size() == 4 && n["entry_points"].items().size() == 2 && n["cache"].items()[0]["max_age"].num() == 604800 && n.get("front_controller") == "/index.php");
            CHECK(rules(R"({})").empty() && n.members().empty());
            CHECK(rules(R"({"private":["/app/","/app/"]})").empty() && n["private"].items().size() == 1);
            for (const char* bad : {R"({"private":["app/"]})", R"({"private":["/"]})", R"({"private":["/a//b"]})", R"({"private":["/a/../b"]})", R"({"private":["/a b/"]})",
                                    R"({"private":["/x;y"]})", R"({"rewrite":["x"]})", R"({"private":"/app/"})", R"({"entry_points":["/index.html"]})", R"({"entry_points":["/x/"]})",
                                    R"({"cache":[{"path":"/assets","max_age":10}]})", R"({"cache":[{"path":"/assets/","max_age":-1}]})", R"({"cache":[{"path":"/assets/","max_age":40000000}]})",
                                    R"({"cache":[{"path":"/assets/","max_age":1.5}]})", R"({"cache":["/assets/"]})", R"({"front_controller":"/index.php"})",
                                    R"({"entry_points":["/x.php"],"front_controller":"/index.php"})", R"({"private":["/api/"],"entry_points":["/api/x.php"]})",
                                    R"({"private":["/static/"],"cache":[{"path":"/static/js/","max_age":1}]})"})
                if (rules(bad).empty()) std::printf("rules accepted %s\n", bad);
            CHECK(!rules(R"({"private":["/"]})").empty() && !rules(R"({"entry_points":["/x.php"],"front_controller":"/index.php"})").empty());
            // Only PHP presets name entry points and a front controller; only PHP and static ones cache a directory from disk.
            SiteSpec sst = ok;
            sst.app = "static";
            SiteSpec px = ok;
            px.app = "rails";
            px.upstream = "http://127.0.0.1:3000";
            CHECK(rules(R"({"private":["/app/"],"cache":[{"path":"/assets/","max_age":60}]})", &sst).empty() && !rules(R"({"entry_points":["/index.php"]})", &sst).empty() &&
                  rules(R"({"private":["/storage/"]})", &px).empty() && !rules(R"({"cache":[{"path":"/public/","max_age":60}]})", &px).empty() &&
                  !rules(R"({"entry_points":["/index.php"],"front_controller":"/index.php"})", &px).empty());
            // Through apply_request: the whole object replaces, {} clears, and a rule that no longer fits the app refuses the change.
            json::Value b;
            std::string e;
            SiteSpec rs = ok;
            rs.app = "php";
            rs.php_socket = "unix:/run/php/fpm.sock";
            // apply_request sets the error only when it refuses, so each call starts clean, as the handler's does.
            auto apply = [&](const char* text, SiteSpec& sp) {
                e.clear();
                CHECK(json::parse(text, b, e));
                apply_request(b, loaded, sp, e);
                return e;
            };
            CHECK(apply(R"({"rules":{"private":["/data/"],"entry_points":["/index.php"],"cache":[{"path":"/assets/","max_age":3600}]}})", rs).empty() && rs.rules["private"].items().size() == 1);
            CHECK(apply(R"({"app":"proxy","upstream":"http://127.0.0.1:9000"})", rs).find("no longer fit") != npos);
            CHECK(apply(R"({"rules":{}})", rs).empty() && rs.rules.members().empty());
            // Rendered and loaded back: deny locations, the entry points, the .php refusal, the cache shield, the front controller.
            SiteSpec full = ok;
            full.domain = "kb.test";  // its own name: shop.test's managed file (no rules) is what site_show would read otherwise
            full.app = "php";
            full.php_socket = "unix:/run/php/fpm.sock";
            full.https = "none";
            full.root = (dir / "kb").string();
            std::filesystem::create_directories(dir / "kb");
            CHECK(apply(R"({"rules":{"private":["/app/","/data/","/cli","/web.config"],"entry_points":["/index.php","/jsonrpc.php"],"cache":[{"path":"/assets/","max_age":604800}],"front_controller":"/index.php"}})", full).empty());
            const std::string text = render_site(full, "x");
            CHECK(text.find("handler = \"deny\"") != npos && text.find("try_files = [\"$uri\", \"$uri/\", \"/index.php?$query_string\"]") != npos &&
                  text.find("path = \".php\"\nmatch = \"suffix\"\nhandler = \"deny\"") != npos && text.find("max-age=604800") != npos);
            std::ofstream(dir / "kb.toml") << text;
            SiteSpec back;
            CHECK(read_managed(dir / "kb.toml", back) && back.rules["entry_points"].items().size() == 2 && back.rules["cache"].items().size() == 1);
            const Config kc = load_config(dir / "kb.toml");
            const SiteConfig& ks = kc.sites[0];
            CHECK(Router::location(ks, "/app/Core/Base.php").handler == "deny" && Router::location(ks, "/data/db.sqlite").handler == "deny" &&
                  Router::location(ks, "/cli").handler == "deny" && Router::location(ks, "/web.config").handler == "deny" && Router::location(ks, "/clients").handler != "deny");
            CHECK(Router::location(ks, "/index.php").kind == HandlerKind::fastcgi && Router::location(ks, "/jsonrpc.php").kind == HandlerKind::fastcgi &&
                  Router::location(ks, "/other.php").handler == "deny" && Router::location(ks, "/libs/x.php").handler == "deny");
            const LocationConfig& ca = Router::location(ks, "/assets/css/app.css");
            CHECK(ca.kind == HandlerKind::static_ && ca.final && ca.add_headers.size() == 1 && ca.add_headers[0].second == "public, max-age=604800" &&
                  refused_suffix("/assets/x.php", ca.deny_suffixes) && refused_suffix("/assets/x.phtml", ca.deny_suffixes) && refused_suffix("/assets/x.bak", ca.deny_suffixes) &&
                  !refused_suffix("/assets/app.css", ca.deny_suffixes));
            const LocationConfig& root = Router::location(ks, "/board/1");
            CHECK(root.try_files.size() == 3 && root.try_files[2].kind == TryStep::Kind::fallback && root.try_files[2].target == "/index.php");
            std::ostringstream ex;
            explain_config(kc, ex);
            CHECK(ex.str().find("handler = \"deny\"") != npos);
            // The rule-made locations as the loader sees them, and site_show's "rules" label on
            // exactly those (2026-10-02 report), a managed file in sites.d standing for the site.
            const std::vector<RuleLocation> rl = rule_locations(full);
            CHECK(rl.size() == 8 && rl[0].kind == RuleLocation::Kind::private_ && !rl[0].exact && rl[2].path == "/cli" && rl[2].exact && rl[4].kind == RuleLocation::Kind::entry && rl[4].exact &&
                  rl[6].kind == RuleLocation::Kind::no_other_php && rl[6].suffix && rl[6].path == ".php" && rl[7].kind == RuleLocation::Kind::cache && rl[7].max_age == 604800);
            std::ofstream(dir / "sites.d" / "kb.test.toml") << text;
            const json::Value shown = control::site(kc, ks, std::time(nullptr));
            std::filesystem::remove(dir / "sites.d" / "kb.test.toml");
            std::size_t ruled = 0, unlabelled = 0;
            for (const auto& l : shown["locations"].items()) {
                if (l.get("from") == "rules") ++ruled;
                if (l["from"].is_null()) ++unlabelled;
            }
            CHECK(ruled == 8 && unlabelled == 0);  // "/" is the php preset's front controller (preset:php): every location says where it is from
            if (ruled != 8 || unlabelled != 0) {
                std::printf("rules label: ruled %zu unlabelled %zu of %zu\n", ruled, unlabelled, shown["locations"].items().size());
                for (const auto& l : shown["locations"].items()) std::printf("  %s %s from=%s\n", std::string(l.get("path")).c_str(), std::string(l.get("match")).c_str(), std::string(l.get("from")).c_str());
            }
            CHECK(rule_locations(ok).empty());
            // Root additions (2026-10-02, design section 20): root's [[location]] tables beside a
            // managed site's file, merged as hand-written locations; every refused file shape.
            {
                namespace fs = std::filesystem;
                const fs::path ra = dir / "ra";
                fs::create_directories(ra / "sites.d" / "shop");
                fs::create_directories(ra / "www");
                const auto rw_r_r = fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::others_read;
                auto put = [&](const fs::path& f, const std::string& text) {
                    std::ofstream(f) << text;
                    fs::permissions(f, rw_r_r);
                };
                put(ra / "agensio.toml", "include = [\"sites.d/*.toml\"]\n[[site]]\nserver_name = [\"*\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n");
                put(ra / "sites.d" / "shop.test.toml",
                    "[[site]]\nserver_name = [\"shop.test\"]\nlisten = [\"127.0.0.1:1\"]\napp = \"wordpress\"\nroot = \"shop\"\nphp = { socket = \"127.0.0.1:9000\" }\n"
                    "[[site.location]]\npath = \"/own/\"\nadd_headers = { \"X-Own\" = \"1\" }\n");
                const fs::path frag = ra / "sites.d" / "shop.test.root.toml";
                auto load_fails = [&](const char* needle) {
                    try {
                        load_config(ra / "agensio.toml");
                    } catch (const std::exception& e) {
                        if (std::string(e.what()).find(needle) != npos) return true;
                        std::printf("root additions: %s\n", e.what());
                    }
                    return false;
                };
                put(frag, "site = \"shop.test\"\n\n[[location]]\npath = \"/wp-content/uploads/\"\nadd_headers = { \"X-Up\" = \"1\" }\n\n[[location]]\npath = \"/wp-includes/\"\nfinal = true\n"
                          "try_files = [\"$uri\", \"=404\"]\n\n[[location]]\npath = \"/extra/\"\nalias = \"../www/\"\n\n[[location]]\npath = \"/one\"\nmatch = \"exact\"\n");
                const Config rc = load_config(ra / "agensio.toml");
                const SiteConfig& rs = rc.sites[1];
                CHECK(rs.server_names.front() == "shop.test" && rs.root_additions.size() == 1 && rs.root_additions[0] == frag.string() && rc.orphan_additions.empty());
                const LocationConfig& up = Router::location(rs, "/wp-content/uploads/x.jpg");  // headers only: joins the preset's shield
                bool xup = false;
                for (const auto& h : up.add_headers) xup = xup || h.first == "X-Up";
                CHECK(up.origin == "preset:wordpress" && xup && !up.deny_suffixes.empty());
                const LocationConfig& inc = Router::location(rs, "/wp-includes/js/x.js");  // more than headers: replaces the preset's
                CHECK(inc.origin == "root:shop.test.root.toml" && inc.deny_suffixes.empty() && inc.final);
                CHECK(Router::location(rs, "/extra/f").origin == "root:shop.test.root.toml" && Router::location(rs, "/extra/f").alias.find("www") != npos &&
                      Router::location(rs, "/one").exact && Router::location(rs, "/one").origin == "root:shop.test.root.toml" &&
                      Router::location(rs, "/own/x").origin.empty() && rc.sites[0].root_additions.empty());
                std::ostringstream rex;
                explain_config(rc, rex);
                CHECK(rex.str().find("# from root:shop.test.root.toml") != npos);
                // An orphan (its site disabled or deleted) is kept with a warning, never an error.
                put(ra / "sites.d" / "gone.test.root.toml", "site = \"gone.test\"\n[[location]]\npath = \"/x/\"\n");
                const Config oc = load_config(ra / "agensio.toml");
                CHECK(oc.sites.size() == 2 && oc.orphan_additions.size() == 1 && oc.orphan_additions[0].site == "gone.test" && oc.orphan_additions[0].file.ends_with("gone.test.root.toml"));
                fs::remove(ra / "sites.d" / "gone.test.root.toml");
                // Refused: a key that is not site or location, no site, location not a table array,
                // a duplicate of the site file's own path, a writable file, a symlink.
                put(ra / "sites.d" / "bad.root.toml", "site = \"shop.test\"\nfoo = 1\n");
                CHECK(load_fails("bad.root.toml: a root additions file holds site = \"<domain>\" and [[location]] tables only, not 'foo'"));
                put(ra / "sites.d" / "bad.root.toml", "site = \"\"\n");
                CHECK(load_fails("names the managed site"));
                put(ra / "sites.d" / "bad.root.toml", "site = \"shop.test\"\nlocation = 1\n");
                CHECK(load_fails("'location' must be an array of tables"));
                fs::remove(ra / "sites.d" / "bad.root.toml");
                put(frag, "site = \"shop.test\"\n[[location]]\npath = \"/own/\"\nfinal = true\n");
                CHECK(load_fails("shop.test.root.toml [[location]] #1: duplicate location '/own/'"));
                put(frag, "site = \"shop.test\"\n[[location]]\npath = \"/x/\"\n");
                fs::permissions(frag, fs::perms::group_write, fs::perm_options::add);
                CHECK(load_fails("must not be writable by its group or by others"));
                fs::permissions(frag, rw_r_r);
                fs::create_symlink("shop.test.root.toml", ra / "sites.d" / "link.root.toml");
                CHECK(load_fails("link.root.toml: a root additions file must be a regular file, not a symlink"));
                fs::remove(ra / "sites.d" / "link.root.toml");
                CHECK(load_config(ra / "agensio.toml").sites[1].root_additions.size() == 1);
            }
            // The connection ceiling (2026-10-02, hardening item 5): the key, its bounds, the derivation.
            {
                Config cc;
                CHECK(cc.max_connections == 0 && connection_ceiling(cc, 524288, 12) == 43520 && connection_ceiling(cc, 1024, 1) == 128 && connection_ceiling(cc, 0, 4) == 128 &&
                      connection_ceiling(cc, 65536, 0) == 63488 && connection_ceiling(cc, 2176, 1) == 128 && connection_ceiling(cc, 2177, 1) == 129);
                cc.max_connections = 10;
                CHECK(connection_ceiling(cc, 524288, 12) == 10);
                std::ofstream(dir / "mc.toml") << "[server]\nmax_connections = 7\n[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n";
                CHECK(load_config(dir / "mc.toml").max_connections == 7);
                std::ofstream(dir / "mc.toml") << "[server]\nmax_connections = -1\n[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n";
                bool refused = false;
                try {
                    load_config(dir / "mc.toml");
                } catch (const std::exception& e) {
                    refused = std::string(e.what()).find("server.max_connections must be between 0") != npos;
                }
                CHECK(refused);
            }
            SiteSpec st = ok;
            st.app = "static";
            CHECK(next_steps(st, loaded).size() == 1);
        }
        // A Rails site's chain follows what is on disk (2026-09-27 report).
        {
            namespace fs = std::filesystem;
            const fs::path rr = fs::temp_directory_path() / ("agensio-railsnext-" + std::to_string(::getpid()));
            fs::create_directories(rr);
            SiteSpec rs = ok;
            rs.app = "rails";
            rs.root = rr.string();
            rs.upstream = "http://127.0.0.1:3001";
            auto rails_step = [&] {
                for (const auto& st : next_steps(rs, loaded))
                    if (st.find("site-task") != std::string::npos) return st;
                return std::string();
            };
            CHECK(rails_step().find("gem_install_rails, then rails_new") != std::string::npos);
            std::ofstream(rr / "Gemfile") << "source 'https://rubygems.org'\n";
            // An archive without config/database.yml: the database first (2026-09-27 Redmine report).
            CHECK(rails_step().find("without config/database.yml") != std::string::npos && rails_step().find("database_config") != std::string::npos);
            fs::create_directories(rr / "config");
            std::ofstream(rr / "config" / "database.yml") << "production: {}\n";
            CHECK(rails_step().find("in place: site-task shop.test bundle_install, then db_prepare") != std::string::npos && rails_step().find("rails_new") == std::string::npos);
            fs::create_directories(rr / "vendor" / "bundle");
            CHECK(rails_step().find("db_migrate after new migrations") != std::string::npos && rails_step().find("rails_new") == std::string::npos);
            fs::remove_all(rr);
        }
        // Redmine's open steps follow what is on disk too (alpha.33 report, P4 a).
        {
            namespace fs = std::filesystem;
            const fs::path rr = fs::temp_directory_path() / ("agensio-redminenext-" + std::to_string(::getpid()));
            fs::create_directories(rr);
            SiteSpec rs = ok;
            rs.app = "redmine";
            rs.root = rr.string();
            rs.upstream = "http://127.0.0.1:3002";
            auto step = [&] {
                for (const auto& st : next_steps(rs, loaded))
                    if (st.find("Redmine") != std::string::npos) return st;
                return std::string();
            };
            CHECK(step().find("site-install shop.test --version") != std::string::npos);
            std::ofstream(rr / "Gemfile") << "source 'https://rubygems.org'\n";
            CHECK(step().find("unpacked: site-env-set shop.test --set DATABASE_URL") != std::string::npos &&
                  step().find("database_config, gemfile_local, bundle_install, db_migrate") != std::string::npos && step().find("site-install") == std::string::npos);
            fs::create_directories(rr / "config");
            std::ofstream(rr / "config" / "database.yml") << "production: {}\n";
            std::ofstream(rr / "Gemfile.local") << "gem \"puma\"\n";
            CHECK(step().find("unpacked: site-task shop.test bundle_install, db_migrate") != std::string::npos && step().find("DATABASE_URL") == std::string::npos &&
                  step().find("gemfile_local") == std::string::npos);
            fs::create_directories(rr / "vendor" / "bundle");
            CHECK(step().find("unpacked: site-task shop.test db_migrate, load_default_data") != std::string::npos);
            fs::create_directories(rr / "public" / "assets");
            CHECK(step().find("Redmine is in place: site-task shop.test db_migrate after an upgrade") != std::string::npos);
            fs::remove_all(rr);
        }
        Config php_cfg = loaded;
        php_cfg.pools_dir = "/etc/php/8.4/fpm/pool.d";
        CHECK(php_fpm_reload_command(php_cfg, "") == "systemctl reload php8.4-fpm");
        php_cfg.pools_dir = "/etc/php-fpm.d";
        CHECK(php_fpm_reload_command(php_cfg, "") == "systemctl reload php-fpm");
        // A site with a user renders its own access log; the redirect stub has no root.
        SiteSpec u = ok;
        u.user = "shop";
        u.access_log.clear();
        json::Value none;
        std::string e2;
        (void)apply_request(json::Value::object(), loaded, u, e2);
        CHECK(u.access_log.ends_with("/sites/shop.test.log"));
        const std::string rendered = render_site(u, "x");
        CHECK(rendered.find("access_log = ") != std::string::npos && rendered.find("redirect = \"https\"\n") != std::string::npos);
        CHECK(rendered.find("redirect = \"https\"\nroot") == std::string::npos);
    }
    std::filesystem::remove_all(dir);
}

// ---- site-install (F9): the archive extractor, the address fence, the validators ----

// A ustar entry: header (with a valid checksum) followed by the padded data.
static std::string tar_entry(const std::string& name, const std::string& data, char type = '0', unsigned mode = 0644,
                             const std::string& link = "", const std::string& prefix = "") {
    std::string h(512, '\0');
    auto put = [&](std::size_t at, const std::string& v, std::size_t len) { std::memcpy(&h[at], v.data(), std::min(v.size(), len)); };
    put(0, name, 100);
    char num[16];
    std::snprintf(num, sizeof num, "%07o", mode); put(100, num, 8);
    put(108, "0000000", 8); put(116, "0000000", 8);
    std::snprintf(num, sizeof num, "%011o", static_cast<unsigned>(data.size())); put(124, num, 12);
    put(136, "00000000000", 12);
    h[156] = type;
    put(157, link, 100);
    put(257, "ustar", 6); put(263, "00", 2);
    put(345, prefix, 155);
    std::memset(&h[148], ' ', 8);
    unsigned sum = 0;
    for (unsigned char c : h) sum += c;
    std::snprintf(num, sizeof num, "%06o", sum); put(148, num, 6); h[154] = '\0'; h[155] = ' ';
    std::string out = h + data;
    if (data.size() % 512) out.append(512 - data.size() % 512, '\0');
    return out;
}
static std::string tar_end() { return std::string(1024, '\0'); }

static std::string gzip_of(const std::string& in) {
#ifdef AGENSIO_HAS_ZLIB
    z_stream z{};
    deflateInit2(&z, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    std::string out(deflateBound(&z, static_cast<uLong>(in.size())), '\0');
    z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data())); z.avail_in = static_cast<uInt>(in.size());
    z.next_out = reinterpret_cast<Bytef*>(out.data()); z.avail_out = static_cast<uInt>(out.size());
    deflate(&z, Z_FINISH);
    out.resize(out.size() - z.avail_out);
    deflateEnd(&z);
    return out;
#else
    return in;
#endif
}

// A zip with stored (and, with zlib, deflated) entries and a central directory.
struct ZipBuilder {
    std::string body, cd;
    unsigned entries = 0;
    static void le16(std::string& s, unsigned v) { s.push_back(static_cast<char>(v & 0xff)); s.push_back(static_cast<char>((v >> 8) & 0xff)); }
    static void le32(std::string& s, std::uint32_t v) { le16(s, v & 0xffff); le16(s, (v >> 16) & 0xffff); }
    void add(const std::string& name, const std::string& data, bool compress = false, unsigned unix_mode = 0100644, std::uint32_t crc_override = 0, bool encrypted = false) {
        std::string stored = data;
        unsigned method = 0;
#ifdef AGENSIO_HAS_ZLIB
        std::uint32_t crc = static_cast<std::uint32_t>(crc32(0L, reinterpret_cast<const Bytef*>(data.data()), static_cast<uInt>(data.size())));
        if (compress) {
            z_stream z{};
            deflateInit2(&z, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
            std::string out(deflateBound(&z, static_cast<uLong>(data.size())) + 16, '\0');
            z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data())); z.avail_in = static_cast<uInt>(data.size());
            z.next_out = reinterpret_cast<Bytef*>(out.data()); z.avail_out = static_cast<uInt>(out.size());
            deflate(&z, Z_FINISH);
            out.resize(out.size() - z.avail_out);
            deflateEnd(&z);
            stored = out;
            method = 8;
        }
#else
        std::uint32_t crc = 0;
#endif
        if (crc_override) crc = crc_override;
        const std::uint32_t off = static_cast<std::uint32_t>(body.size());
        std::string lh = "PK\x03\x04";
        le16(lh, 20); le16(lh, encrypted ? 1 : 0); le16(lh, method); le16(lh, 0); le16(lh, 0);
        le32(lh, crc); le32(lh, static_cast<std::uint32_t>(stored.size())); le32(lh, static_cast<std::uint32_t>(data.size()));
        le16(lh, static_cast<unsigned>(name.size())); le16(lh, 0);
        body += lh + name + stored;
        std::string c = "PK\x01\x02";
        le16(c, 3 << 8 | 20); le16(c, 20); le16(c, encrypted ? 1 : 0); le16(c, method); le16(c, 0); le16(c, 0);
        le32(c, crc); le32(c, static_cast<std::uint32_t>(stored.size())); le32(c, static_cast<std::uint32_t>(data.size()));
        le16(c, static_cast<unsigned>(name.size())); le16(c, 0); le16(c, 0); le16(c, 0); le16(c, 0);
        le32(c, unix_mode << 16); le32(c, off);
        cd += c + name;
        ++entries;
    }
    std::string build(bool zip64_marker = false) const {
        std::string e = "PK\x05\x06";
        le16(e, 0); le16(e, 0); le16(e, zip64_marker ? 0xffff : entries); le16(e, zip64_marker ? 0xffff : entries);
        le32(e, static_cast<std::uint32_t>(cd.size())); le32(e, static_cast<std::uint32_t>(body.size())); le16(e, 0);
        return body + cd + e;
    }
};

static void test_install() {
    namespace fs = std::filesystem;
    using namespace archive;
    // The path rule.
    std::string out, why;
    CHECK(clean_path("./wordpress//index.php", out, why) && out == "wordpress/index.php");
    CHECK(clean_path("a/b/", out, why) && out == "a/b");
    CHECK(!clean_path("/etc/passwd", out, why) && why == "absolute path");
    CHECK(!clean_path("a/../../etc", out, why) && why == "'..' in name");
    CHECK(!clean_path("a\\b", out, why) && !clean_path("a\nb", out, why) && !clean_path("./", out, why) && !clean_path("", out, why));
    CHECK(sniff("\x1f\x8b\x08") == Format::gzip && sniff("PK\x03\x04") == Format::zip && sniff("PK\x05\x06") == Format::zip && sniff("hello") == Format::unknown);
    // A tar: one top directory, files, an executable, a GNU long name, a pax path.
    const std::string longname(150, 'n');
    std::string tar = tar_entry("wordpress/", "", '5', 0755) + tar_entry("wordpress/index.php", "<?php echo 1;", '0', 0644) +
                      tar_entry("wordpress/bin/run", "#!/bin/sh", '0', 0755) + tar_entry("././@LongLink", longname + "\0", 'L') +
                      tar_entry("ignored", "long", '0') + tar_entry("pax", "30 path=wordpress/pax/named.txt\n", 'x') +
                      tar_entry("ignored2", "paxdata", '0') + tar_entry("wordpress/sub/deep.txt", "d", '0', 0644, "", "") + tar_end();
    CHECK(sniff(tar) == Format::tar);
    {
        MemorySource src(tar);
        CountingSink sink;
        Limits limits;
        Summary sum;
        std::string err;
        const bool ok = extract(src, sink, limits, sum, err);
        CHECK(ok);
        if (!ok) std::printf("tar: %s\n", err.c_str());
        CHECK(sink.files == 5 && sink.directories == 1 && sink.executables == 1 && sink.bytes == 13 + 9 + 4 + 7 + 1);
        CHECK(sum.top == "wordpress" && !sum.single_top);  // the long-named file sits at the top level
    }
    {
        // Every entry below one directory: single_top, ready to unwrap.
        const std::string t2 = tar_entry("app/", "", '5') + tar_entry("app/a.txt", "a", '0') + tar_entry("app/b/c.txt", "cc", '0') + tar_end();
        MemorySource src(t2);
        CountingSink sink;
        Summary sum;
        std::string err;
        CHECK(extract(src, sink, Limits{}, sum, err) && sum.single_top && sum.top == "app" && sum.files == 2);
        // gzip of the same: the same result.
#ifdef AGENSIO_HAS_ZLIB
        const std::string gz = gzip_of(t2);
        MemorySource gsrc(gz);
        CountingSink gsink;
        Summary gsum;
        CHECK(sniff(gz) == Format::gzip && extract(gsrc, gsink, Limits{}, gsum, err) && gsink.files == 2 && gsink.bytes == 3 && gsum.single_top);
        // A truncated gzip is an error, not a silent partial extraction.
        MemorySource tsrc(std::string_view(gz).substr(0, gz.size() / 2));
        CountingSink tsink;
        CHECK(!extract(tsrc, tsink, Limits{}, gsum, err) && !err.empty());
#endif
    }
    auto refused = [&](const std::string& bytes, const char* fragment) {
        MemorySource src(bytes);
        CountingSink sink;
        Summary sum;
        std::string err;
        const bool ok = extract(src, sink, Limits{}, sum, err);
        const bool hit = !ok && err.find(fragment) != std::string::npos;
        if (!hit) std::printf("expected refusal '%s', got ok=%d err='%s'\n", fragment, ok, err.c_str());
        return hit;
    };
    {
        // `tar -C dir .` starts with "./": the root itself, nothing to create; "./x" is x.
        const std::string dot = tar_entry("./", "", '5') + tar_entry("./x.txt", "x", '0') + tar_entry("./d/", "", '5') + tar_end();
        MemorySource src(dot);
        CountingSink sink;
        Summary sum;
        std::string err;
        CHECK(extract(src, sink, Limits{}, sum, err) && sink.files == 1 && sink.directories == 1 && !sum.single_top);
        CHECK(refused(tar_entry(".", "data", '0') + tar_end(), "empty name"));  // a file with no name is still refused
    }
    CHECK(refused(tar_entry("link", "", '2', 0777, "/etc/passwd") + tar_end(), "symbolic link"));
    CHECK(refused(tar_entry("hard", "", '1', 0644, "other") + tar_end(), "hard link"));
    CHECK(refused(tar_entry("dev", "", '3', 0644) + tar_end(), "device"));
    CHECK(refused(tar_entry("fifo", "", '6', 0644) + tar_end(), "fifo"));
    CHECK(refused(tar_entry("../escape.txt", "x", '0') + tar_end(), "'..'"));
    CHECK(refused(tar_entry("/abs.txt", "x", '0') + tar_end(), "absolute"));
    CHECK(refused(tar_entry("ok/../../x", "x", '0', 0644, "", "pre") + tar_end(), "'..'"));
    {
        std::string bad = tar_entry("f.txt", "x", '0') + tar_end();
        bad[0] = 'z';  // breaks the checksum
        CHECK(refused(bad, "checksum"));
        CHECK(refused(tar_entry("f.txt", std::string(600, 'x'), '0').substr(0, 700), "ends inside"));
        std::string sparse = tar_entry("s", "", 'S');
        CHECK(refused(sparse + tar_end(), "unsupported"));
    }
    {
        // Limits: entry count and total bytes.
        std::string many;
        for (int i = 0; i < 5; ++i) many += tar_entry("f" + std::to_string(i), "x", '0');
        many += tar_end();
        MemorySource src(many);
        CountingSink sink;
        Summary sum;
        std::string err;
        Limits l;
        l.max_entries = 3;
        CHECK(!extract(src, sink, l, sum, err) && err.find("more than 3 entries") != std::string::npos);
        Limits b;
        b.max_bytes = 3;
        MemorySource src2(many);
        CountingSink sink2;
        CHECK(!extract(src2, sink2, b, sum, err) && err.find("more than 3 bytes") != std::string::npos);
        Limits d;
        d.max_depth = 2;
        const std::string deep = tar_entry("a/b/c/d.txt", "x", '0') + tar_end();
        MemorySource src3(deep);
        CountingSink sink3;
        CHECK(!extract(src3, sink3, d, sum, err) && err.find("deeper") != std::string::npos);
    }
    // Zip: stored and deflated entries, directories, a symlink refused, CRC checked, zip64 refused.
    {
        ZipBuilder z;
        z.add("site/", "", false, 0040755);
        z.add("site/index.html", "<h1>hi</h1>", false);
        z.add("site/app.js", std::string(3000, 'j'), true, 0100755);
        const std::string bytes = z.build();
        CHECK(sniff(bytes) == Format::zip);
        MemorySource src(bytes);
        CountingSink sink;
        Summary sum;
        std::string err;
        const bool ok = extract(src, sink, Limits{}, sum, err);
        CHECK(ok);
        if (!ok) std::printf("zip: %s\n", err.c_str());
#ifdef AGENSIO_HAS_ZLIB
        CHECK(sink.files == 2 && sink.directories == 1 && sink.bytes == 11 + 3000 && sink.executables == 1 && sum.single_top && sum.top == "site");
#endif
        ZipBuilder sl;
        sl.add("evil", "/etc/passwd", false, 0120777);
        CHECK(refused(sl.build(), "symbolic link"));
        ZipBuilder tr;
        tr.add("../up.txt", "x");
        CHECK(refused(tr.build(), "'..'"));
        ZipBuilder enc;
        enc.add("secret.txt", "x", false, 0100644, 0, true);
        CHECK(refused(enc.build(), "encrypted"));
#ifdef AGENSIO_HAS_ZLIB
        ZipBuilder bad;
        bad.add("f.txt", "hello", true, 0100644, 0x12345678);
        CHECK(refused(bad.build(), "CRC"));
#endif
        ZipBuilder big;
        big.add("f.txt", "x");
        CHECK(refused(big.build(true), "zip64"));
        CHECK(refused("PK\x03\x04 not really a zip, just bytes that start like one and go on for a while", "end-of-central-directory"));
        CHECK(refused("plain text, no archive at all, long enough to be looked at ......................", "not a tar"));
    }
#ifndef _WIN32
    // DirectorySink and install::execute on a real directory: modes follow the target's,
    // a failure leaves the directory empty, a single top directory is unwrapped.
    {
        const fs::path dir = fs::temp_directory_path() / ("agensio-install-" + std::to_string(::getpid()));
        fs::remove_all(dir);
        fs::create_directories(dir / "target");
        ::chmod((dir / "target").c_str(), 0750);
        const std::string t2 = tar_entry("app/", "", '5') + tar_entry("app/a.txt", "a", '0') + tar_entry("app/bin/run", "r", '0', 0755) + tar_end();
        auto write_file = [&](const fs::path& p, const std::string& bytes) { std::ofstream o(p, std::ios::binary); o << bytes; };
        write_file(dir / "app.tar", t2);
        auto run = [&](const std::string& archive, const std::string& sha = "", int strip = -1, const std::string& sub = "", bool create = false, bool dry = false) {
            install::Request r;
            r.site_root = (dir / "target").string();
            r.target = sub.empty() ? r.site_root : r.site_root + "/" + sub;
            r.create_path = create;
            r.dry_run = dry;
            r.upload_fd = ::open((dir / archive).c_str(), O_RDONLY);
            r.upload_name = archive;
            r.sha256 = sha;
            r.strip = strip;
            const json::Value v = install::execute(r);
            ::close(r.upload_fd);
            return v;
        };
        json::Value v = run("app.tar");
        CHECK(v["ok"].boolean() && v.get("unwrapped") == "app" && v["files"].num() == 2);
        if (!v["ok"].boolean()) std::printf("install: %s\n", std::string(v.get("error")).c_str());
        struct stat st {};
        CHECK(::stat((dir / "target" / "a.txt").c_str(), &st) == 0 && (st.st_mode & 0777) == 0640);
        CHECK(::stat((dir / "target" / "bin").c_str(), &st) == 0 && (st.st_mode & 0777) == 0750);
        CHECK(::stat((dir / "target" / "bin" / "run").c_str(), &st) == 0 && (st.st_mode & 0777) == 0750);
        CHECK(!fs::exists(dir / "target" / "app"));
        CHECK(!v.get("sha256").empty() || !std::string(AGENSIO_VERSION).empty());
        // Not empty now: refused.
        v = run("app.tar");
        CHECK(!v["ok"].boolean() && std::string(v.get("error")).find("not empty") != std::string::npos);
        fs::remove_all(dir / "target");
        fs::create_directories(dir / "target");
        // A set-gid target: directories below keep the bit (the group stays the server's), files never get it.
        fs::remove_all(dir / "target");
        fs::create_directories(dir / "target");
        ::chmod((dir / "target").c_str(), 02750);
        v = run("app.tar");
        CHECK(v["ok"].boolean() && ::stat((dir / "target" / "bin").c_str(), &st) == 0 && (st.st_mode & 07777) == 02750);
        CHECK(::stat((dir / "target" / "bin" / "run").c_str(), &st) == 0 && (st.st_mode & 07777) == 0750);
        fs::remove_all(dir / "target");
        fs::create_directories(dir / "target");
        ::chmod((dir / "target").c_str(), 0750);
        // A wrong digest: refused before anything is written.
        v = run("app.tar", std::string(64, '0'));
        CHECK(!v["ok"].boolean() && std::string(v.get("error")).find("sha256 mismatch") != std::string::npos && fs::is_empty(dir / "target"));
#ifdef AGENSIO_HAS_TLS
        const std::string digest(v.get("error").substr(std::string(v.get("error")).find("archive is ") + 11, 64));
        v = run("app.tar", digest, 0);
        CHECK(v["ok"].boolean() && v.get("unwrapped").empty() && fs::exists(dir / "target" / "app" / "a.txt"));
        fs::remove_all(dir / "target");
        fs::create_directories(dir / "target");
#endif
        // A symlink in the middle of an archive: refused, and what came before it is gone.
        write_file(dir / "evil.tar", tar_entry("good.txt", "g", '0') + tar_entry("link", "", '2', 0777, "/etc") + tar_end());
        v = run("evil.tar");
        CHECK(!v["ok"].boolean() && std::string(v.get("error")).find("symbolic link") != std::string::npos && fs::is_empty(dir / "target"));
        // A site directory that is a symlink is refused (owned by someone else: only testable as root).
        fs::create_directory_symlink(dir / "target", dir / "link");
        install::Request r;
        r.site_root = r.target = (dir / "link").string();
        r.upload_fd = ::open((dir / "app.tar").c_str(), O_RDONLY);
        v = install::execute(r);
        ::close(r.upload_fd);
        CHECK(!v["ok"].boolean() && std::string(v.get("error")).find("symlink") != std::string::npos);
        // A plugin below an installed application (create_path): the site directory is not
        // empty, the plugin's own directory does not exist yet.
        ::chmod((dir / "target").c_str(), 0750);
        v = run("app.tar");
        CHECK(v["ok"].boolean() && v["created"].items().empty());
        v = run("app.tar", "", -1, "plugins/demo");
        CHECK(!v["ok"].boolean() && std::string(v.get("error")).find("does not exist; send create_path") != std::string::npos && !fs::exists(dir / "target" / "plugins"));
        v = run("app.tar", "", -1, "plugins/demo", true, true);  // dry run: the same walk, nothing made
        CHECK(v["ok"].boolean() && v["dry_run"].boolean() && v["would_create"].items().size() == 2 && !fs::exists(dir / "target" / "plugins"));
        CHECK(v["would_create"].items()[1].str() == (dir / "target" / "plugins" / "demo").string());
        v = run("app.tar", "", -1, "plugins/demo", false, true);  // dry run without create_path: the refusal
        CHECK(!v["ok"].boolean() && std::string(v.get("error")).find("create_path") != std::string::npos);
        v = run("app.tar", "", -1, "plugins/demo", true);
        CHECK(v["ok"].boolean() && v["created"].items().size() == 2 && v.get("unwrapped") == "app" && fs::exists(dir / "target" / "plugins" / "demo" / "a.txt"));
        CHECK(v["created"].items()[0].get("mode") == "0750" && ::stat((dir / "target" / "plugins" / "demo").c_str(), &st) == 0 && (st.st_mode & 0777) == 0750);
        // The same leaf again: it exists and is not empty (unchanged rule); an existing empty leaf works.
        v = run("app.tar", "", -1, "plugins/demo", true);
        CHECK(!v["ok"].boolean() && std::string(v.get("error")).find("not empty") != std::string::npos);
        fs::create_directories(dir / "target" / "plugins" / "empty");
        v = run("app.tar", "", -1, "plugins/empty");
        CHECK(v["ok"].boolean() && v["created"].items().empty());
        // A refusal in the middle of a two-level creation leaves no directory behind.
        v = run("evil.tar", "", -1, "themes/contrib/bad", true);
        CHECK(!v["ok"].boolean() && std::string(v.get("error")).find("symbolic link") != std::string::npos && !fs::exists(dir / "target" / "themes"));
        v = run("app.tar", std::string(64, '0'), -1, "themes/contrib/bad", true);
        CHECK(!v["ok"].boolean() && !fs::exists(dir / "target" / "themes"));
        // A symlinked component on the way, '..', and a target outside the site: refused.
        fs::create_directory_symlink(dir, dir / "target" / "out");
        v = run("app.tar", "", -1, "out/x", true);
        CHECK(!v["ok"].boolean() && std::string(v.get("error")).find("symlink") != std::string::npos && !fs::exists(dir / "x"));
        v = run("app.tar", "", -1, "plugins/../../x", true);
        CHECK(!v["ok"].boolean() && std::string(v.get("error")).find("'..'") != std::string::npos);
        r.site_root = (dir / "target").string();
        r.target = dir.string();
        r.upload_fd = ::open((dir / "app.tar").c_str(), O_RDONLY);
        v = install::execute(r);
        ::close(r.upload_fd);
        CHECK(!v["ok"].boolean() && std::string(v.get("error")).find("not below") != std::string::npos);
        // The credential files of the preset are 0600 whatever the directory's pattern, in
        // an install (after the unwrap) and in a copy, and reported under secured.
        fs::remove_all(dir / "target");
        fs::create_directories(dir / "target");
        ::chmod((dir / "target").c_str(), 0750);
        write_file(dir / "wp.tar", tar_entry("wordpress/", "", '5') + tar_entry("wordpress/index.php", "i", '0') + tar_entry("wordpress/wp-config.php", "<?php // db password", '0', 0644) + tar_end());
        {
            install::Request r2;
            r2.site_root = r2.target = (dir / "target").string();
            r2.secrets = {"wp-config.php", "wp-content/db.php"};
            r2.upload_fd = ::open((dir / "wp.tar").c_str(), O_RDONLY);
            v = install::execute(r2);
            ::close(r2.upload_fd);
            CHECK(v["ok"].boolean() && v.get("unwrapped") == "wordpress" && v["secured"].items().size() == 1 && v["secured"].items()[0].str() == (dir / "target" / "wp-config.php").string());
            CHECK(::stat((dir / "target" / "wp-config.php").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
            CHECK(::stat((dir / "target" / "index.php").c_str(), &st) == 0 && (st.st_mode & 0777) == 0640);
            // A secret below an install path (a plugin that ships its own credentials file).
            r2.target = (dir / "target").string() + "/plugins/demo";
            r2.create_path = true;
            r2.secrets = {"plugins/demo/wp-config.php"};
            r2.upload_fd = ::open((dir / "wp.tar").c_str(), O_RDONLY);
            v = install::execute(r2);
            ::close(r2.upload_fd);
            CHECK(v["ok"].boolean() && v["secured"].items().size() == 1 && ::stat((dir / "target" / "plugins" / "demo" / "wp-config.php").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
        }
        {
            install::CopyRequest c;
            c.site_root = (dir / "target").string();
            c.from = "index.php";
            c.to = "wp-config.php";
            c.overwrite = true;
            c.secrets = {"wp-config.php"};
            const json::Value d = install::copy_file([&] { auto x = c; x.dry_run = true; return x; }());
            CHECK(d["ok"].boolean() && d.get("mode") == "0600" && d["secured"].boolean());
            v = install::copy_file(c);
            CHECK(v["ok"].boolean() && v.get("mode") == "0600" && v["secured"].boolean() && ::stat((dir / "target" / "wp-config.php").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
            c.to = "other.php";
            v = install::copy_file(c);
            CHECK(v["ok"].boolean() && v.get("mode") == "0640" && !v["secured"].boolean());
        }
        fs::remove_all(dir / "target");
        fs::create_directories(dir / "target" / "plugins" / "demo");
        ::chmod((dir / "target").c_str(), 0750);
        fs::create_directory_symlink(dir, dir / "target" / "out");  // a symlink pointing outside, for the copy refusals
        write_file(dir / "app.tar", t2);
        // php-fpm's reload without process_control_timeout is a health finding.
        {
            fs::create_directories(dir / "fpm" / "pool.d");
            Config pc;
            pc.pools_dir = (dir / "fpm" / "pool.d").string();
            std::string conf;
            CHECK(!control::php_fpm_hard_reload(pc, conf));  // no php-fpm.conf: nothing to say
            write_file(dir / "fpm" / "php-fpm.conf", "[global]\npid = /run/php/php-fpm.pid\n;process_control_timeout = 10s\n");
            CHECK(control::php_fpm_hard_reload(pc, conf) && conf == (dir / "fpm" / "php-fpm.conf").string());
            write_file(dir / "fpm" / "php-fpm.conf", "[global]\nprocess_control_timeout = 0\n");
            CHECK(control::php_fpm_hard_reload(pc, conf));
            write_file(dir / "fpm" / "php-fpm.conf", "[global]\n process_control_timeout = 10s ; graceful\n");
            CHECK(!control::php_fpm_hard_reload(pc, conf));
        }
        // site-copy (F9b): one file to another path of the same site, every refusal of the report.
        const fs::path site = dir / "target";
        auto copy = [&](const std::string& from, const std::string& to, bool overwrite = false, bool dry = false, std::uint64_t cap = 512u << 20) {
            install::CopyRequest c;
            c.site_root = site.string();
            c.from = from;
            c.to = to;
            c.overwrite = overwrite;
            c.dry_run = dry;
            c.max_bytes = cap;
            return install::copy_file(c);
        };
        auto refused_with = [&](const json::Value& res, const char* fragment) {
            const bool hit = !res["ok"].boolean() && std::string(res.get("error")).find(fragment) != std::string::npos;
            if (!hit) std::printf("copy: expected '%s', got %s\n", fragment, res.dump().c_str());
            return hit;
        };
        write_file(site / "plugins" / "demo" / "db.copy", "<?php // drop-in\n");
        ::chmod((site / "plugins" / "demo" / "db.copy").c_str(), 0640);
        fs::create_directories(site / "wp-content");
        ::chmod((site / "wp-content").c_str(), 0750);
        v = copy("plugins/demo/db.copy", "wp-content/db.php", false, true);  // dry run first
        CHECK(v["ok"].boolean() && v["dry_run"].boolean() && v.get("to") == (site / "wp-content" / "db.php").string() && v.get("mode") == "0640" && !fs::exists(site / "wp-content" / "db.php"));
        v = copy("plugins/demo/db.copy", "wp-content/db.php");
        CHECK(v["ok"].boolean() && v["bytes"].num() == 17 && v.get("mode") == "0640" && v["replaced"].is_null());
        CHECK(::stat((site / "wp-content" / "db.php").c_str(), &st) == 0 && (st.st_mode & 0777) == 0640 && st.st_size == 17);
        CHECK(!fs::exists(site / "wp-content" / (".agensio-copy." + std::to_string(::getpid()))));
        v = copy("plugins/demo/db.copy", "wp-content/db.php");  // exists: refused without overwrite
        CHECK(refused_with(v, "exists; send overwrite"));
        v = copy("plugins/demo/db.copy", "wp-content/db.php", false, true);  // and the dry run says the same
        CHECK(refused_with(v, "exists; send overwrite"));
        write_file(site / "plugins" / "demo" / "db.copy", "<?php // drop-in, second edition\n");
        v = copy("plugins/demo/db.copy", "wp-content/db.php", true, true);
        CHECK(v["ok"].boolean() && !v["would_replace"].is_null() && v["would_replace"]["bytes"].num() == 17);
        v = copy("plugins/demo/db.copy", "wp-content/db.php", true);
        CHECK(v["ok"].boolean() && v["replaced"]["bytes"].num() == 17 && !v["replaced"].get("mtime").empty() && v["bytes"].num() == 33);
        // The executable bits follow the source when the directory grants them.
        ::chmod((site / "plugins" / "demo" / "db.copy").c_str(), 0750);
        v = copy("plugins/demo/db.copy", "wp-content/run.php");
        CHECK(v["ok"].boolean() && v.get("mode") == "0750");
        // Refusals: '..' on either side, absolute, same path, missing source, a directory,
        // a symlinked source, a symlinked component, a missing destination directory, a
        // destination that is a directory or a symlink, above the cap.
        CHECK(refused_with(copy("../app.tar", "wp-content/x"), "'..'") && refused_with(copy("plugins/demo/db.copy", "../x"), "'..'"));
        CHECK(refused_with(copy("/etc/passwd", "wp-content/x"), "absolute") && refused_with(copy("plugins/demo/db.copy", "plugins/demo/db.copy"), "same path"));
        CHECK(refused_with(copy("plugins/demo/nothere", "wp-content/x"), "does not exist"));
        CHECK(refused_with(copy("plugins/demo", "wp-content/x"), "is a directory"));
        fs::create_symlink(site / "plugins" / "demo" / "db.copy", site / "plugins" / "demo" / "link.copy");
        CHECK(refused_with(copy("plugins/demo/link.copy", "wp-content/x"), "symlink"));
        CHECK(refused_with(copy("out/passwd", "wp-content/x"), "symlink") && refused_with(copy("plugins/demo/db.copy", "out/x"), "symlink"));  // `out` -> outside, from the create_path test
        CHECK(refused_with(copy("plugins/demo/db.copy", "wp-content/cache/x"), "create-path"));
        CHECK(refused_with(copy("plugins/demo/db.copy", "wp-content"), "is a directory"));
        fs::create_symlink(site / "wp-content" / "db.php", site / "wp-content" / "alias.php");
        CHECK(refused_with(copy("plugins/demo/db.copy", "wp-content/alias.php", true), "symlink"));
        CHECK(refused_with(copy("plugins/demo/db.copy", "wp-content/big.php", false, false, 10), "above the limit") && !fs::exists(site / "wp-content" / "big.php"));
        // Nothing outside the site can be named: the site's own parent, through a path that
        // normalises inside, and a symlink placed inside pointing out are all refused above;
        // an absolute site root that is itself a symlink is refused too.
        install::CopyRequest c;
        c.site_root = (dir / "link").string();
        c.from = "plugins/demo/db.copy";
        c.to = "wp-content/y";
        v = install::copy_file(c);
        CHECK(refused_with(v, "symlink"));
        CHECK(!fs::exists(dir / "x") && !fs::exists(dir / "y") && !fs::exists(site / "wp-content" / "x"));
        fs::remove_all(dir);
    }
#endif
    // The downloader's fence and URL rule.
    auto priv = [](const char* a) { return fetch::is_private_address(asio::ip::make_address(a)); };
    CHECK(priv("127.0.0.1") && priv("10.1.2.3") && priv("172.16.0.1") && priv("172.31.255.255") && priv("192.168.1.1") && priv("169.254.169.254"));
    CHECK(priv("100.64.0.1") && priv("0.0.0.0") && priv("224.0.0.1") && priv("255.255.255.255"));
    CHECK(!priv("172.32.0.1") && !priv("8.8.8.8") && !priv("198.143.164.252") && !priv("100.128.0.1"));
    CHECK(priv("::1") && priv("::") && priv("fe80::1") && priv("fc00::1") && priv("fd12::1") && priv("ff02::1") && priv("::ffff:127.0.0.1") && priv("::ffff:10.0.0.1") && priv("2002:7f00:0001::1"));
    CHECK(!priv("2606:4700::1111") && !priv("::ffff:8.8.8.8"));
    std::string host, port, path;
    CHECK(fetch::split_url("https://wordpress.org/latest.tar.gz", host, port, path) && host == "wordpress.org" && port == "443" && path == "/latest.tar.gz");
    CHECK(fetch::split_url("https://mirror.example:8443/a/b.zip?x=1#frag", host, port, path) && port == "8443" && path == "/a/b.zip?x=1");
    CHECK(fetch::split_url("https://[2606:4700::1111]/x", host, port, path) && host == "2606:4700::1111");
    CHECK(!fetch::split_url("http://wordpress.org/latest.tar.gz", host, port, path));
    CHECK(!fetch::split_url("https://user:pw@host/x", host, port, path) && !fetch::split_url("https:///x", host, port, path));
    CHECK(!fetch::split_url("https://host/a b", host, port, path) && !fetch::split_url("https://ho st/a", host, port, path));
    // Validators.
    CHECK(install::valid_upload_name("wordpress-6.7.tar.gz") && install::valid_upload_name("a_b-c.zip"));
    CHECK(!install::valid_upload_name(".hidden") && !install::valid_upload_name("a/b") && !install::valid_upload_name("") && !install::valid_upload_name("a b") && !install::valid_upload_name(std::string(129, 'a')));
    CHECK(install::valid_sha256(std::string(64, 'a')) && install::valid_sha256(std::string(64, 'F')) && !install::valid_sha256(std::string(63, 'a')) && !install::valid_sha256(std::string(64, 'g')));
    // The preset sources and the helper's validation of app_install.
    CHECK(preset_source("wordpress", "") == "https://wordpress.org/latest.tar.gz" && preset_source("wordpress", "6.7.1") == "https://wordpress.org/wordpress-6.7.1.tar.gz");
    CHECK(preset_source("drupal", "").starts_with("https://") && preset_source("laravel", "").empty() && preset_source("php", "1").empty() && preset_source("static", "").empty());
    {
        Config c;
        c.control.sites_root = "/srv/sites";
        c.state_dir = "/var/lib/agensio";
        auto v = [&](const char* text) { json::Value r; std::string e2; json::parse(text, r, e2); return provision::validate(r, c); };
        CHECK(v(R"({"op":"app_install","site_root":"/srv/sites/a.test","target":"/srv/sites/a.test/web","user":"shop","url":"https://wordpress.org/latest.tar.gz"})").empty());
        CHECK(v(R"({"op":"app_install","site_root":"/srv/sites/a.test","target":"/srv/sites/a.test","upload":"wp.tgz","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","strip":1,"create_path":true,"dry_run":false})").empty());
        CHECK(!v(R"({"op":"app_install","target":"/srv/sites/a.test/web","upload":"wp.tgz"})").empty());  // no site_root
        CHECK(!v(R"({"op":"app_install","site_root":"/srv/sites","target":"/srv/sites/a/web","upload":"wp.tgz"})").empty());  // sites_root itself
        CHECK(!v(R"({"op":"app_install","site_root":"/srv/sites/a.test","target":"/srv/sites/b.test/web","upload":"wp.tgz"})").empty());  // target outside
        CHECK(!v(R"({"op":"app_install","site_root":"/srv/sites/a.test","target":"/srv/sites/a.test/web","upload":"wp.tgz","create_path":"yes"})").empty());
        CHECK(!v(R"({"op":"app_install","target":"/etc","upload":"wp.tgz"})").empty());
        CHECK(!v(R"({"op":"app_install","target":"/srv/sites/a/web","url":"http://x/y"})").empty());
        CHECK(!v(R"({"op":"app_install","target":"/srv/sites/a/web","url":"https://x/y","upload":"z"})").empty());
        CHECK(!v(R"({"op":"app_install","target":"/srv/sites/a/web","upload":"../etc/passwd"})").empty());
        CHECK(!v(R"({"op":"app_install","target":"/srv/sites/a/web","upload":"wp.tgz","user":"root"})").empty());
        CHECK(!v(R"({"op":"app_install","target":"/srv/sites/a/web","upload":"wp.tgz","sha256":"xyz"})").empty());
        CHECK(!v(R"({"op":"app_install","target":"/srv/sites/a/web","upload":"wp.tgz","strip":2})").empty());
        CHECK(v(R"({"op":"file_copy","site_root":"/srv/sites/a.test","user":"shop","from":"wp-content/plugins/x/db.copy","to":"wp-content/db.php","overwrite":true})").empty());
        CHECK(!v(R"({"op":"file_copy","site_root":"/srv/sites","from":"a","to":"b"})").empty() && !v(R"({"op":"file_copy","site_root":"/srv/sites/a.test","from":"../b/x","to":"y"})").empty());
        CHECK(!v(R"({"op":"file_copy","site_root":"/srv/sites/a.test","from":"/etc/passwd","to":"y"})").empty() && !v(R"({"op":"file_copy","site_root":"/srv/sites/a.test","from":"x","to":"x"})").empty());
        CHECK(!v(R"({"op":"file_copy","site_root":"/srv/sites/a.test","from":"x","to":"y","overwrite":"yes"})").empty() && !v(R"({"op":"file_copy","site_root":"/srv/sites/a.test","from":"","to":"y"})").empty());
        c.control.install = false;
        CHECK(!v(R"({"op":"app_install","site_root":"/srv/sites/a","target":"/srv/sites/a/web","url":"https://x/y"})").empty() && v(R"({"op":"app_install","site_root":"/srv/sites/a","target":"/srv/sites/a/web","upload":"wp.tgz"})").empty());
        CHECK(provision::uploads_dir(c) == "/var/lib/agensio/uploads");
    }
    // The configuration keys.
    {
        const fs::path dir = fs::temp_directory_path() / ("agensio-installcfg-" + std::to_string(::getpid()));
        fs::create_directories(dir / "www");
        std::ofstream(dir / "a.toml") << "[control]\ninstall = false\ninstall_private = true\nupload_max = \"64M\"\ninstall_ca = \"ca.pem\"\n[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n";
        const Config c = load_config(dir / "a.toml");
        CHECK(!c.control.install && c.control.install_private && c.control.upload_max == 64u * 1024 * 1024 && c.control.install_ca == (dir / "ca.pem").string());
        std::ofstream(dir / "b.toml") << "[control]\n[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n";
        const Config d = load_config(dir / "b.toml");
        CHECK(d.control.install && !d.control.install_private && d.control.upload_max == 512u * 1024 * 1024);
        const json::Value catalog = preset_catalog();
        CHECK(catalog["presets"].items()[0].get("app") == "static");
        bool wp_source = false;
        for (const auto& p : catalog["presets"].items())
            if (p.get("app") == "wordpress") wp_source = p.get("source") == "https://wordpress.org/latest.tar.gz";
        CHECK(wp_source);
        fs::remove_all(dir);
    }
}

static void test_server_account_and_rules() {
    // One helper decides the server's account for every validator: server.group, else the
    // primary group of server.user, never the group of the process running the check.
    HostFacts facts;
    facts.stat = [](const std::string&, FileFacts&) { return false; };
    facts.user = [](const std::string& n, unsigned& uid, unsigned& gid) {
        if (n == "agensio") { uid = 999; gid = 987; return true; }
        if (n == "t1") { uid = 1001; gid = 1001; return true; }
        return false;
    };
    facts.group = [](const std::string& n, unsigned& gid) {
        if (n == "agensio") { gid = 987; return true; }
        if (n == "t1") { gid = 1001; return true; }
        if (n == "web") { gid = 500; return true; }
        return false;
    };
    facts.group_name = [](unsigned gid) { return gid == 987 ? "agensio" : gid == 1001 ? "t1" : gid == 500 ? "web" : ""; };
    Config cfg;
    cfg.user = "agensio";
    ServerAccount a = server_account(cfg, facts);
    CHECK(a.known && a.uid == 999 && a.gid == 987 && a.group == "agensio");
    cfg.group = "web";
    a = server_account(cfg, facts);
    CHECK(a.known && a.gid == 500 && a.group == "web");
    cfg.user = "nobody-here";
    cfg.group.clear();
    CHECK(!server_account(cfg, facts).known);

    // The rules on a site with its own user: the socket's group is the server's group,
    // and the root must be readable by the server's account.
    cfg.user = "agensio";
    SiteConfig site;
    site.server_names = {"t.test"};
    site.user = "t1";
    site.root = "/srv/t/web";
    site.php.configured = true;
    site.php.address.unix = true;
    site.php.address.path = "/run/php/agensio-t1.sock";
    cfg.sites = {site};
    std::map<std::string, FileFacts> files;
    facts.stat = [&](const std::string& p, FileFacts& out) {
        auto it = files.find(p);
        if (it == files.end()) return false;
        out = it->second;
        return true;
    };
    auto dir = [](unsigned uid, unsigned gid, unsigned mode) { FileFacts f; f.is_dir = true; f.uid = uid; f.gid = gid; f.mode = mode; return f; };
    auto file = [](unsigned uid, unsigned gid, unsigned mode) { FileFacts f; f.uid = uid; f.gid = gid; f.mode = mode; return f; };
    auto has = [&](const std::vector<std::string>& errs, std::string_view what) {
        return std::any_of(errs.begin(), errs.end(), [&](const std::string& e) { return e.find(what) != std::string::npos; });
    };
    files["/srv/t/web"] = dir(1001, 987, 02750);            // t1:agensio 2750: the convention
    files[site.php.address.path] = file(1001, 987, 0660);   // t1:agensio 0660
    CHECK(check_hosting(cfg, facts).empty());
    files["/srv/t/web"] = dir(1001, 1001, 0750);             // t1:t1: the server cannot enter
    auto errs = check_hosting(cfg, facts);
    CHECK(errs.size() == 1 && has(errs, "cannot read it") && has(errs, "chown t1:agensio /srv/t/web && chmod 2750"));
    files["/srv/t/web"] = dir(1001, 987, 02750);
    files[site.php.address.path] = file(1001, 0, 0660);      // t1:root: what the process group of `-t` as root once demanded
    errs = check_hosting(cfg, facts);
    CHECK(errs.size() == 1 && has(errs, "expected group agensio (gid 987), the server's group"));
    // Without server.user the check applies to the process itself; as root everything is readable.
    Config bare = cfg;
    bare.user.clear();
    files[site.php.address.path] = file(1001, 987, 0660);
    (void)check_hosting(bare, facts);  // must not crash; the outcome depends on the running uid
    // The lookup prefers the site that serves content over its redirect stub.
    Config two;
    SiteConfig r; r.server_names = {"a.test"}; r.redirect = "https";
    SiteConfig t; t.server_names = {"a.test"}; t.tls = TlsConfig{}; t.app = "laravel";
    two.sites = {r, t};
    CHECK(control::find_site(two, "a.test") == &two.sites[1]);
    two.sites = {t, r};
    CHECK(control::find_site(two, "A.TEST") == &two.sites[0]);
}

// The request parser is stateless over its buffer: every prefix of a request is
// incomplete until the head is whole, and the whole parses to the same fields whether or
// not shorter prefixes were tried first (a live "GETGET" line, 2026-09-20, was a buffer
// bug in the connection, not here; this pins the parser's half of the invariant).
// The ceiling's health finding (hardening item 5): the fix follows from the refusals' shape.
static void test_refusal_finding() {
    using namespace control;
    CHECK(ago_text(3) == "3 s" && ago_text(59.9) == "59 s" && ago_text(720) == "12 min" && ago_text(7200) == "2 h" && ago_text(200000) == "2 d");
    RefusalReport one;
    one.refused = 100;
    one.connections = 300;
    one.idle = 10;
    one.ceiling = 100;
    one.workers = 3;
    one.first_s_ago = 720;
    one.last_s_ago = 3;
    one.addresses = {{"203.0.113.7", 90}, {"198.51.100.2", 10}};
    one.listeners = {{"0.0.0.0:443", 100}};
    Finding f = refusal_finding(one);
    CHECK(f.severity == "warn" && f.code == "connections_refused" && f.site.empty());
    CHECK(f.message.find("100 connection(s) refused at the ceiling since start (first 12 min ago, last 3 s ago) on 0.0.0.0:443, from 203.0.113.7 x90, 198.51.100.2 x10; the workers hold 300 of 300 connections, 10 idle") != std::string::npos);
    CHECK(f.fix.starts_with("most refusals came from 203.0.113.7") && f.fix.find("firewall") != std::string::npos);
    RefusalReport stuck = one;
    stuck.addresses = {{"a", 5}, {"b", 5}, {"c", 5}, {"d", 5}, {"e", 5}};
    stuck.more_addresses = true;
    stuck.refused = 25;
    stuck.idle = 280;
    stuck.listeners = {{"0.0.0.0:443", 20}, {"0.0.0.0:80", 5}};
    f = refusal_finding(stuck);
    CHECK(f.message.find("on 0.0.0.0:443 x20, 0.0.0.0:80 x5, from a x5, b x5, c x5 and 2 more addresses;") != std::string::npos && f.fix.starts_with("the workers are full of idle connections") &&
          f.fix.find("idle_timeout") != std::string::npos);
    RefusalReport load = stuck;
    load.idle = 20;
    load.addresses = {{"a", 5}, {"b", 5}, {"c", 5}};
    f = refusal_finding(load);
    CHECK(f.message.find("from a x5, b x5, c x5 and more addresses;") != std::string::npos && f.fix.starts_with("legitimate load") && f.fix.find("LimitNOFILE") != std::string::npos);
    load.connections = 100;  // workers far from full and no address dominating: still load
    CHECK(refusal_finding(load).fix.starts_with("legitimate load"));
}

// Host protection (2026-10-02, docs/configuration.md 18): the input from a configuration (the
// public ports, QUIC's, the logs, the presets' and the sites' login paths, loopback left out),
// the renderers held to the shipped files in packaging/, the helper's answer read (nft's JSON,
// the unit states, fail2ban's status text) and the findings for every state.
// The needs of a failure jail as the renderer writes them, for a hand-built jail in the tests.
static std::vector<std::string> tier_needs_for_test(const control::FailureJail& f) {
    std::vector<std::string> steps = control::failure_tier_steps(f.app, "/srv/x");
    if (!steps.empty()) steps.erase(steps.begin());  // the headline line
    return steps;
}

static void test_protection() {
    namespace fs = std::filesystem;
    using namespace control;
    // The input from a configuration.
    const fs::path dir = fs::temp_directory_path() / ("agensio-prot-" + std::to_string(::getpid()));
    fs::create_directories(dir / "www");
    std::ofstream(dir / "a.toml") << "[server]\nworkers = 1\n[log]\naccess = \"access.log\"\n[control]\nsocket = \"ctl.sock\"\nhost_protection = \"external\"\n"
                                     "[[site]]\nserver_name = [\"wp.test\"]\nlisten = [\"0.0.0.0:8080\", \"[::]:8443\"]\nroot = \"www\"\napp = \"wordpress\"\n"
                                     "php = { socket = \"unix:/run/php/x.sock\" }\nlogin_paths = [\"/login\", \"/login\", \"/api/token\"]\n"
                                     "[[site]]\nserver_name = [\"lo.test\"]\nlisten = [\"127.0.0.1:8081\"]\nroot = \"www\"\nlogin_paths = \"/one\"\naccess_log = \"off\"\n";
    {
        const Config cfg = load_config(dir / "a.toml");
        CHECK(cfg.control.host_protection == "external" && (cfg.sites[0].login_paths == std::vector<std::string>{"/login", "/api/token"}) &&
              (cfg.sites[1].login_paths == std::vector<std::string>{"/one"}));
        const ProtectionInput in = protection_input(cfg);
        CHECK(in.exposed && (in.tcp_ports == std::vector<unsigned>{8080, 8443}) && in.udp_ports.empty() && in.combined && in.host_protection == "external");
        CHECK((in.logs == std::vector<std::string>{(dir / "access.log").string()}) && (in.unlogged == std::vector<std::string>{"lo.test"}));
        CHECK((in.login_paths == std::vector<std::string>{"/api/token", "/login", "/one", "/wp-login.php", "/xmlrpc.php"}) && in.firewall_file == (dir / "firewall.nft").string());
        CHECK(in.login_jails.size() == 1 && in.login_jails[0].name == "agensio-login" && in.login_jails[0].log == (dir / "access.log").string() && in.login_jails[0].paths.size() == 4 &&
              in.login_jails[0].paths[0].path == "/api/token" && in.login_jails[0].paths[0].php && !in.login_jails[0].paths[0].format && (in.login_jails[0].sites == std::vector<std::string>{"wp.test"}));
        // The failure tier: the WordPress site brings the plugin's two jails, enabled only with the
        // filter and the log on the host (both looked for; here neither is asserted, the flags are
        // set by hand below), the needs naming the admin panel and root's copy, never an install.
        CHECK(in.failure_jails.size() == 2 && in.failure_jails[0].name == "agensio-wordpress-soft" && in.failure_jails[0].filter == "wordpress-soft" && in.failure_jails[0].maxretry == 5 &&
              in.failure_jails[1].name == "agensio-wordpress-hard" && in.failure_jails[1].maxretry == 1 && in.failure_jails[1].bantime == "1d" &&
              (in.failure_jails[0].sites == std::vector<std::string>{"wp.test"}) && in.failure_jails[0].needs.size() >= 3 &&
              in.failure_jails[0].needs[0].find("WordPress admin panel") != std::string::npos && in.failure_jails[0].needs[0].find("agensio installs no plugin") != std::string::npos &&
              in.failure_jails[0].needs[1].find("https://downloads.wordpress.org/plugin/wp-fail2ban.latest-stable.zip") != std::string::npos &&
              in.failure_jails[0].needs[1].find("or read " + (dir / "www").string() + "/wp-content/plugins/wp-fail2ban/filters.d/wordpress-hard.conf") != std::string::npos &&
              in.failure_jails[0].needs.back().find("agensio ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf; fail2ban-client reload") != std::string::npos);
        {
            ProtectionInput fi = in;
            fi.failure_jails[0].filter_installed = false;
            fi.failure_jails[0].log_present = true;
            fi.failure_jails[0].log = "/var/log/auth.log";
            fi.failure_jails[0].journal = false;
            fi.failure_jails[1].journal = false;
            std::string jail = render_jail(fi);
            CHECK(jail.find("\n[agensio-wordpress-soft]\n") != std::string::npos && jail.find("# Disabled: the filter wordpress-soft is not in /etc/fail2ban/filter.d/. Needs:\n#   install and activate the WP fail2ban plugin") != std::string::npos &&
                  jail.find("[agensio-wordpress-soft]\n# failed WordPress logins") != std::string::npos);
            fi.failure_jails[0].filter_installed = true;
            jail = render_jail(fi);
            const std::size_t at = jail.find("\n[agensio-wordpress-soft]\n");
            CHECK(at != std::string::npos && jail.find("enabled   = true\nport      = 8080,8443\nfilter    = wordpress-soft\nlogpath   = /var/log/auth.log\nbanaction = nftables-multiport\nmaxretry  = 5\nfindtime  = 10m\nbantime   = 1h\n", at) != std::string::npos);
            const json::Value r = protection_report(fi, read_probe(json::Value(nullptr), fi), {});
            CHECK(r["failure_jails"].items().size() == 2 && r["failure_jails"].items()[0]["enabled"].boolean() && r["failure_jails"].items()[1].get("name") == "agensio-wordpress-hard" &&
                  !r["failure_jails"].items()[0]["journal"].boolean());
            // A journald-only host (the alpha.47 report: a stale auth.log passed for a log): the
            // jail reads the journal, matched on the pool's unit and the site account's uid, and
            // needs no log file.
            fi.failure_jails[0].journal = true;
            fi.failure_jails[0].log_present = false;
            fi.failure_jails[0].journalmatch = "_SYSTEMD_UNIT=php8.4-fpm.service _UID=996";
            fi.failure_jails[0].needs = tier_needs_for_test(fi.failure_jails[0]);
            jail = render_jail(fi);
            const std::size_t jat = jail.find("\n[agensio-wordpress-soft]\n");
            CHECK(fi.failure_jails[0].enabled() && jat != std::string::npos && jail.find("# Reads the journal: no syslog daemon writes files on this host", jat) != std::string::npos &&
                  jail.find("enabled   = true\nport      = 8080,8443\nfilter    = wordpress-soft\nbackend   = systemd\njournalmatch = _SYSTEMD_UNIT=php8.4-fpm.service _UID=996\nbanaction", jat) != std::string::npos &&
                  jail.find("logpath   =", jat) > jail.find("\n[agensio-wordpress-hard]", jat));  // no log file in this jail's section; the next jail may keep its file
            CHECK(protection_report(fi, read_probe(json::Value(nullptr), fi), {})["failure_jails"].items()[0].get("journalmatch") == "_SYSTEMD_UNIT=php8.4-fpm.service _UID=996");
        }
        // The journal match as the input builds it (alpha.49 report): a group per site account's
        // uid, a trusted field, never the identity alone; a site without an account, or with one
        // not on this host, is listed as not read, and a jail with no readable site is disabled.
        const UidLookup fake = [](const std::string& u) -> std::optional<unsigned> {
            if (u == "web1") return 997u;
            if (u == "web3") return 995u;
            return std::nullopt;
        };
        {
            Config users = cfg;
            users.sites[0].user = "web1";
            const ProtectionInput ui = protection_input(users, fake, true);
            const std::string& m = ui.failure_jails[0].journalmatch;
            CHECK(ui.failure_jails.size() == 2 && ui.failure_jails[0].journal && (m == "_UID=997" || (m.starts_with("_SYSTEMD_UNIT=php") && m.ends_with("-fpm.service _UID=997"))) &&
                  m.find("SYSLOG_IDENTIFIER") == std::string::npos && ui.failure_jails[0].unidentified.empty() && ui.failure_jails[1].journalmatch == m &&
                  ui.failure_jails[0].enabled() == ui.failure_jails[0].filter_installed);
            const ProtectionInput nu = protection_input(cfg, fake, true);  // wp.test without an account: not read, the jail disabled
            CHECK(nu.failure_jails[0].journalmatch.empty() && !nu.failure_jails[0].enabled() &&
                  (nu.failure_jails[0].unidentified == std::vector<std::string>{"wp.test (no account of its own: the site's user is not set)"}) &&
                  nu.failure_jails[0].needs.size() == 4 && nu.failure_jails[0].needs[2].starts_with("give wp.test (no account of its own: the site's user is not set) an account of its own (site_update with user"));
            const std::string njail = render_jail(nu);
            CHECK(njail.find("# Not read, no trusted field tells their lines apart: wp.test (no account of its own: the site's user is not set).\n") != std::string::npos &&
                  njail.find("# Disabled: the filter wordpress-soft is not in /etc/fail2ban/filter.d/; no site of this jail has an account of its own on this host, so no trusted journal field (_UID) tells its lines from any other process's. Needs:\n") != std::string::npos &&
                  njail.find("\nbackend   = systemd\nbanaction") != std::string::npos && njail.find("journalmatch = \n") == std::string::npos);
            const ProtectionInput fm = protection_input(cfg, fake, false);  // file mode: accounts play no part
            CHECK(!fm.failure_jails[0].journal && fm.failure_jails[0].journalmatch.empty() && fm.failure_jails[0].unidentified.empty() && fm.failure_jails[0].needs.size() >= 3 &&
                  fm.failure_jails[0].needs[2].find("an account of its own") == std::string::npos);
        }
        Config dru = cfg;
        dru.sites[1].app = "drupal";
        dru.sites[1].php.configured = true;
        dru.sites[1].user = "web3";
        {
            const ProtectionInput di = protection_input(dru, fake, true);
            CHECK(di.failure_jails.size() == 3 && di.failure_jails[2].name == "agensio-drupal-auth" && di.failure_jails[2].filter == "drupal-auth" && (di.failure_jails[2].sites == std::vector<std::string>{"lo.test"}) &&
                  di.failure_jails[2].needs[0].find("Syslog module") != std::string::npos && (di.failure_jails[2].log == "/var/log/syslog" || di.failure_jails[2].log == "/var/log/messages") &&
                  di.failure_jails[2].journalmatch == "SYSLOG_IDENTIFIER=drupal _UID=995" && di.failure_jails[2].unidentified.empty());
            // Two more Drupal sites: one on an account the host does not have (listed), one on
            // web1 (a second group); two sites of one account make one group.
            Config more = dru;
            more.sites.push_back(more.sites[1]);
            more.sites.back().server_names = {"d2.test"};
            more.sites.back().user = "ghost";
            more.sites.push_back(more.sites[1]);
            more.sites.back().server_names = {"d3.test"};
            more.sites.back().user = "web1";
            more.sites.push_back(more.sites[1]);
            more.sites.back().server_names = {"d4.test"};
            const ProtectionInput dm = protection_input(more, fake, true);
            CHECK(dm.failure_jails[2].journalmatch == "SYSLOG_IDENTIFIER=drupal _UID=995 + SYSLOG_IDENTIFIER=drupal _UID=997" &&
                  (dm.failure_jails[2].unidentified == std::vector<std::string>{"d2.test (the account ghost does not exist on this host)"}) &&
                  (dm.failure_jails[2].sites == std::vector<std::string>{"lo.test", "d2.test", "d3.test", "d4.test"}) && dm.failure_jails[2].enabled() == dm.failure_jails[2].filter_installed &&
                  !dm.failure_jails[2].user_journals && render_jail(dm).find("\nbackend   = systemd\njournalmatch = SYSLOG_IDENTIFIER=drupal _UID=995 + ") != std::string::npos);
            // An account of an ordinary uid (a panel's web user): journald files its lines under
            // the user's journal, which fail2ban's backend skips by default, so the jail asks for
            // every local journal (docs/fail2ban-ref/wiki, the 0.10.5 page).
            const UidLookup panel = [](const std::string& u) -> std::optional<unsigned> { return u == "web3" ? std::optional<unsigned>(5003u) : std::nullopt; };
            const ProtectionInput pj = protection_input(dru, panel, true);
            CHECK(pj.failure_jails[2].user_journals && pj.failure_jails[2].journalmatch == "SYSLOG_IDENTIFIER=drupal _UID=5003" &&
                  render_jail(pj).find("\nbackend   = systemd[journalflags=1]\njournalmatch = SYSLOG_IDENTIFIER=drupal _UID=5003\n") != std::string::npos);
        }
        CHECK(failure_tier_steps("wordpress", "/srv/wp").size() >= 4 && failure_tier_steps("wordpress", "/srv/wp")[0].starts_with("fail2ban counts this site's failed logins") &&
              failure_tier_steps("drupal", "/srv/d")[1].find("Extend > Syslog") != std::string::npos && failure_tier_steps("laravel", "/srv/l").empty() &&
              (syslog_daemon_present() ? failure_tier_steps("drupal", "/srv/d", "d.test").size() == failure_tier_steps("drupal", "/srv/d").size()
                                       : failure_tier_steps("drupal", "/srv/d", "d.test")[2].starts_with("give d.test (no account of its own: the site's user is not set) an account of its own")) && failure_tier_steps("static", "").empty());
        Config own = cfg;
        own.sites[1].access_log = (dir / "lo.log").string();
        own.sites[1].app = "redmine";
        const ProtectionInput two = protection_input(own);
        CHECK(two.login_jails.size() == 2 && two.login_jails[1].name == "agensio-login-lo-test" && two.login_jails[1].log == (dir / "lo.log").string() && two.login_jails[1].paths.size() == 2 &&
              two.login_jails[1].paths[0].path == "/login" && two.login_jails[1].paths[0].format && !two.login_jails[1].paths[0].php && two.login_jails[1].paths[1].path == "/one");
        // A loopback-only host is not exposed; QUIC adds the TLS port to the UDP list.
        Config lo = cfg;
        lo.sites.erase(lo.sites.begin());
        CHECK(!protection_input(lo).exposed && protection_input(lo).tcp_ports.empty());
        Config h3 = cfg;
        h3.sites[0].tls = TlsConfig{};
        h3.sites[0].h3 = true;
        CHECK((protection_input(h3).udp_ports == std::vector<unsigned>{8080, 8443}));
    }
    {
        std::ofstream(dir / "e.toml") << "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\nencoded_slashes = \"Allow\"\n[[site]]\nlisten = [\"127.0.0.1:2\"]\nroot = \"www\"\n";
        const Config e = load_config(dir / "e.toml");
        CHECK(e.sites[0].encoded_slashes_allow && !e.sites[1].encoded_slashes_allow);
        bool refused = false;
        std::ofstream(dir / "e2.toml") << "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\nencoded_slashes = \"maybe\"\n";
        try {
            load_config(dir / "e2.toml");
        } catch (const std::exception&) {
            refused = true;
        }
        CHECK(refused);
        control::SiteSpec sp;
        sp.domain = "es.test";
        sp.https = "none";
        sp.app = "static";
        sp.root = "/srv/es";
        sp.user_decided = true;
        sp.encoded_slashes = "allow";
        const std::string text = control::render_site(sp, "now");
        CHECK(text.find("\nencoded_slashes = \"allow\"") != std::string::npos);
        control::SiteSpec back;
        CHECK(control::SiteSpec::from_json(sp.to_json(), back) && back.encoded_slashes == "allow");
        sp.encoded_slashes.clear();
        CHECK(control::render_site(sp, "now").find("encoded_slashes") == std::string::npos && control::SiteSpec::from_json(sp.to_json(), back) && back.encoded_slashes.empty());
    }
    for (const char* bad : {"login_paths = [\"login\"]", "login_paths = [\"/a//b\"]", "login_paths = [\"/a/../b\"]", "login_paths = [\"/\"]", "login_paths = [\"/a?\"]", "login_paths = [\"/a?b=%20\"]", "login_paths = 7"}) {
        std::ofstream(dir / "b.toml") << "[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n" << bad << "\n";
        bool refused = false;
        try {
            load_config(dir / "b.toml");
        } catch (const std::exception&) {
            refused = true;
        }
        if (!refused) std::printf("login_paths accepted %s\n", bad);
        CHECK(refused);
    }
    {
        std::ofstream(dir / "c.toml") << "[control]\nhost_protection = \"maybe\"\n[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n";
        bool refused = false;
        try {
            load_config(dir / "c.toml");
        } catch (const std::exception&) {
            refused = true;
        }
        CHECK(refused);
    }
    CHECK((preset_login_paths("wordpress") == std::vector<std::string>{"/wp-login.php", "/xmlrpc.php"}) && preset_login_paths("wagtail").size() == 2 && preset_login_paths("php").empty() &&
          (preset_login_paths("redmine") == std::vector<std::string>{"/login"}) && preset_login_paths("rails").empty());
    CHECK(check_login_path("/x.y-z_1/").empty() && !check_login_path("/x y").empty() && !check_login_path("").empty());
    // A login routed through the query string (the alpha.43 report: Kanboard, Roundcube, phpBB).
    for (const char* ok : {"/?controller=AuthController&action=check", "/?_task=login", "/ucp.php?mode=login", "/a/b?x=1&y=two+three:4~/"})
        if (!check_login_path(ok).empty()) std::printf("login path refused %s: %s\n", ok, check_login_path(ok).c_str());
    for (const char* bad : {"/login?", "/?", "/a?b?c", "/a?x=%20", "/x y?a=1", "/a?x=\"1\"", "/a//b?x=1", "/"})
        if (check_login_path(bad).empty()) std::printf("login path accepted %s\n", bad);
    CHECK(check_login_path("/?controller=AuthController&action=check").empty() && check_login_path("/ucp.php?mode=login").empty() && !check_login_path("/login?").empty() &&
          !check_login_path("/?").empty() && !check_login_path("/a?b?c").empty() && !check_login_path("/a?x=%20").empty() && !check_login_path("/x y?a=1").empty() &&
          !check_login_path("/a//b?x=1").empty() && check_login_path("/").find("written with it") != std::string::npos);
    {
        ProtectionInput kb;
        kb.tcp_ports = {443};
        kb.login_paths = {"/?controller=AuthController&action=check", "/ucp.php?mode=login", "/x+y"};
        kb.exposed = true;
        // The jail's regex for a path covers every spelling (the alpha.44 report): "/x" exactly,
        // a query entry's parameters as lookaheads, never a '%' (the jail file is configparser's).
        const std::string sl = "(?:/|\\x252F)+", dot = "(?:\\.|\\x252E)";
        const std::string sep_text = sl + "(?:(?:" + dot + sl + "|[^/?\\s.\\x25][^/?\\s\\x25]*" + sl + dot + dot + sl + "))*";
        const std::string sep = "<sep>";  // the filter's variable; fail2ban substitutes it in the jail's parameter too
        const std::string x = "(?:x|\\x25[57]8)";
        // A letter under both cases' codes; the front controller only before a PHP preset's path,
        // never alone; the format suffix only for Rails; path info only after a .php file.
        CHECK(spelling_regex({"/x", true, false}) == "(?:" + sep + "index" + dot + "php)?" + sep + x + "(?:/|\\x252F)*(?:[?&]\\S*)?");
        CHECK(spelling_regex({"/x", false, true}) == sep + x + "(?:" + dot + "[a-z0-9]{1,8})?(?:/|\\x252F)*(?:[?&]\\S*)?");
        CHECK(spelling_regex({"/x.php", true, false}) == "(?:" + sep + "index" + dot + "php)?" + sep + x + dot + "(?:p|\\x25[57]0)(?:h|\\x25[46]8)(?:p|\\x25[57]0)(?:" + sl + "[^?\\s]*)?(?:[?&]\\S*)?");
        // A query login (the alpha.46 report): the root's run with nothing after it, the literal
        // '?' before the parameters' lookaheads, each anchored after it.
        const std::string kbr = spelling_regex({"/?controller=Auth&a=1", true, false});
        CHECK(kbr.starts_with("(?:" + sep + "index" + dot + "php|" + sep + ")\\?(?=(?:\\S*&)?(?:c|\\x25[46]3)") &&
              kbr.find("=(?:A|\\x25[46]1)(?:u|\\x25[57]5)(?:t|\\x25[57]4)(?:h|\\x25[46]8)(?:[&\\s]|$))") != std::string::npos &&
              kbr.ends_with("(?=(?:\\S*&)?(?:a|\\x25[46]1)=(?:1|\\x2531)(?:[&\\s]|$))\\S*") && kbr.find('%') == std::string::npos && kbr.find("(?:/|\\x252F)*") == std::string::npos);
        CHECK(spelling_regex({"/?x=1", false, false}).starts_with(sep + "\\?(?=(?:\\S*&)?") && spelling_regex({"/a/b", false, false}) == sep + "(?:a|\\x25[46]1)" + sep + "(?:b|\\x25[46]2)(?:/|\\x252F)*(?:[?&]\\S*)?");
        CHECK(spelling_regex({"/ucp.php?mode=login", true, false}).find("(?:" + sl + "[^?\\s]*)?\\?(?=(?:\\S*&)?(?:m|\\x25[46]D)") != std::string::npos);
        // The filter carries the separator once; a path's entry stays around a hundred characters.
        CHECK(protection_filters()[0].text.find("\nsep = " + sep_text + "\n") != std::string::npos && spelling_regex({"/wp-login.php", true, false}).size() < 260 &&
              spelling_regex({"/wp-login.php", true, false}).find(sep_text) == std::string::npos);
        kb.login_jails = {LoginJail{"agensio-login", "/var/log/agensio/access.log", {"kb.test"}, {{"/?controller=AuthController&action=check", true, false}, {"/ucp.php?mode=login", true, false}, {"/x+y", false, false}}}};
        CHECK(render_jail(kb).find("filter    = agensio-login[paths=\"" + login_paths_regex(kb.login_jails[0].paths) + "\"]") != std::string::npos && render_jail(kb).find('%') == std::string::npos &&
              render_jail(kb).find("# Credentials posted to a login path of kb.test: ten in ten minutes bans for an hour.") != std::string::npos);
        CHECK(protection_filters()[0].text.find("failregex = (?i)^<HOST> \\S+ \\S+ \\[\\] \"POST (?:<paths>) HTTP/\\S+\" \\d{3} ") != std::string::npos &&
              protection_filters()[0].text.find("paths = " + login_paths_regex(default_protection_input().login_jails[0].paths) + "\n") != std::string::npos &&
              protection_filters()[0].text.find('%') == std::string::npos);
    }
    // The shipped files are the renderers' output for the default host.
    auto file = [](const char* rel) {
        std::ifstream f(std::string(AGENSIO_SOURCE_DIR) + "/" + rel);
        return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    };
    const ProtectionInput def = default_protection_input();
    CHECK((def.tcp_ports == std::vector<unsigned>{80, 443}) && (def.udp_ports == std::vector<unsigned>{443}) && def.exposed && def.login_paths.size() == 8 &&
          def.login_jails.size() == 1 && def.login_jails[0].paths.size() == 8 && def.login_jails[0].paths[0].path == "/admin" && def.login_jails[0].paths[0].php);
    CHECK(render_nft(def) == file("packaging/firewall/agensio.nft"));
    CHECK(render_jail(def) == file("packaging/fail2ban/jail.d/agensio.conf"));
    CHECK(render_firewall_unit(def) == file("packaging/agensio-firewall.service"));
    for (const auto& f : protection_filters()) CHECK(f.text == file(("packaging/fail2ban/filter.d/" + std::string(f.name) + ".conf").c_str()));
    CHECK(protection_filters().size() == 4);
    // What a host's rendering says: its ports, its logs, its paths (escaped for the regex), the
    // QUIC rule only with h3, the login jail disabled without a path.
    ProtectionInput in;
    in.tcp_ports = {80, 443};
    in.udp_ports = {443};
    in.logs = {"/var/log/agensio/access.log", "/var/log/agensio/wp.log"};
    in.login_paths = {"/login", "/wp-login.php"};
    in.login_jails = {LoginJail{"agensio-login", "/var/log/agensio/access.log", {"a.test", "b.test"}, {{"/login", false, false}, {"/wp-login.php", true, false}}}};
    in.exposed = true;
    in.firewall_file = "/etc/agensio/firewall.nft";
    {
        const std::string nft = render_nft(in), jail = render_jail(in);
        CHECK(nft.find("tcp dport { 80, 443 } ct state new update @new4") != std::string::npos && nft.find("udp dport { 443 } @th,64,8 & 0xc0 == 0xc0") != std::string::npos &&
              nft.starts_with("#!/usr/sbin/nft -f\n") && nft.find("table inet agensio\ndelete table inet agensio\ntable inet agensio {") != std::string::npos);
        CHECK(jail.find("filter    = agensio-login[paths=\"" + login_paths_regex(in.login_jails[0].paths) + "\"]") != std::string::npos &&
              jail.find("logpath   = /var/log/agensio/access.log\n            /var/log/agensio/wp.log\n") != std::string::npos && jail.find("port      = 80,443") != std::string::npos);
        ProtectionInput nol = in;
        nol.udp_ports.clear();
        nol.login_paths.clear();
        nol.login_jails.clear();
        nol.tcp_ports = {8080};
        CHECK(render_nft(nol).find("quic") == std::string::npos && render_nft(nol).find("tcp dport { 8080 }") != std::string::npos);
        CHECK(render_jail(nol).find("[agensio-login]\n# Credentials posted to a login path: ten in ten minutes bans for an hour.\n# No login path is known for the site(s)") != std::string::npos &&
              render_jail(nol).find("enabled   = false") != std::string::npos && render_jail(nol).find("filter    = agensio-login\n") != std::string::npos);
        ProtectionInput js = in;
        js.combined = false;
        CHECK(render_jail(js).find("NOTE: this host's access logs are JSON") != std::string::npos);
        CHECK(firewall_trial_commands(in).size() == 3 && firewall_trial_commands(in)[2].starts_with("systemd-run --on-active=10min --unit agensio-firewall-trial") &&
              (firewall_keep_commands(in) == std::vector<std::string>{"systemctl stop agensio-firewall-trial.timer", "systemctl enable --now agensio-firewall.service"}));
        ProtectionInput odd = in;
        odd.firewall_file = "/srv/agensio/firewall.nft";
        CHECK(firewall_keep_commands(odd).size() == 4 && firewall_keep_commands(odd)[1] == "agensio ctl protection --unit > /etc/systemd/system/agensio-firewall.service");
        CHECK(fail2ban_install_commands().size() == 3 && fail2ban_install_commands()[0].find("filter.d/agensio-post.conf /etc/fail2ban/filter.d/") != std::string::npos);
    }
    // The helper's answer, read: nft's JSON (our table with counters, a foreign rule through a
    // named port set), the units, fail2ban's status texts.
    const char* reply_text = R"json({"ok": true,
      "nft": {"available": true, "terse": false, "ruleset": {"nftables": [
        {"metainfo": {"version": "1.1.3"}},
        {"table": {"family": "inet", "name": "agensio", "handle": 17}},
        {"chain": {"family": "inet", "table": "agensio", "name": "input", "hook": "input", "prio": -10, "policy": "accept"}},
        {"rule": {"family": "inet", "table": "agensio", "chain": "input", "handle": 9, "comment": "agensio: new connections per IPv4 address",
                  "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [80, 443]}}},
                           {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "new"}},
                           {"set": {"op": "update", "elem": {"payload": {"protocol": "ip", "field": "saddr"}}, "set": "@new4", "stmt": [{"limit": {"rate": 30, "burst": 60, "per": "second", "inv": true}}]}},
                           {"counter": {"packets": 12, "bytes": 720}}, {"drop": null}]}},
        {"rule": {"family": "inet", "table": "agensio", "chain": "input", "handle": 10, "comment": "agensio: connections held per IPv4 address",
                  "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [80, 443]}}},
                           {"set": {"op": "add", "elem": {"payload": {"protocol": "ip", "field": "saddr"}}, "set": "@held4", "stmt": [{"ct count": {"val": 200, "inv": true}}]}},
                           {"counter": {"packets": 0, "bytes": 0}}, {"reject": {"type": "tcp reset"}}]}},
        {"rule": {"family": "inet", "table": "agensio", "chain": "input", "handle": 11, "comment": "agensio: QUIC handshakes per IPv4 address",
                  "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 443}},
                           {"set": {"op": "update", "elem": {"payload": {"protocol": "ip", "field": "saddr"}}, "set": "@quic4", "stmt": [{"limit": {"rate": 50, "burst": 100, "per": "second", "inv": true}}]}},
                           {"counter": {"packets": 3, "bytes": 3600}}, {"drop": null}]}},
        {"table": {"family": "inet", "name": "panel", "handle": 20}},
        {"set": {"family": "inet", "name": "web", "table": "panel", "type": "inet_service", "elem": [8080, {"range": [8443, 8445]}]}},
        {"rule": {"family": "inet", "table": "panel", "chain": "in", "handle": 21,
                  "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": "@web"}},
                           {"set": {"op": "add", "elem": {"payload": {"protocol": "ip", "field": "saddr"}}, "set": "@c", "stmt": [{"ct count": {"val": 50, "inv": true}}]}}, {"drop": null}]}},
        {"rule": {"family": "inet", "table": "panel", "chain": "in", "handle": 22,
                  "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}, {"accept": null}]}}
      ]}},
      "units": {"agensio-firewall.service": {"Id": "agensio-firewall.service", "LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled"},
                "agensio-firewall-trial.timer": {"Id": "agensio-firewall-trial.timer", "LoadState": "not-found", "ActiveState": "inactive"},
                "fail2ban.service": {"Id": "fail2ban.service", "LoadState": "loaded", "ActiveState": "active"},
                "nftables.service": {"Id": "nftables.service", "LoadState": "loaded", "ActiveState": "active"},
                "firewalld.service": {"Id": "firewalld.service", "LoadState": "not-found", "ActiveState": "inactive"}},
      "fail2ban": {"available": true, "status": "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, agensio-login", "jails": [
        {"name": "sshd", "status": "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n|  |- Total failed:\t0\n|  `- File list:\t/var/log/auth.log\n`- Actions\n   |- Currently banned:\t0\n   |- Total banned:\t0\n   `- Banned IP list:\t"},
        {"name": "agensio-login", "status": "Status for the jail: agensio-login\n|- Filter\n|  |- Currently failed:\t2\n|  |- Total failed:\t12\n|  `- File list:\t/var/log/agensio/access.log /var/log/agensio/wp.log\n`- Actions\n   |- Currently banned:\t1\n   |- Total banned:\t3\n   `- Banned IP list:\t203.0.113.9"}]}})json";
    json::Value reply;
    std::string perr;
    CHECK(json::parse(reply_text, reply, perr));
    const ProtectionProbe probe = read_probe(reply, in);
    {   // the journal answer (alpha.48 report): one entry per jail answered, none for a jail with a reason
        json::Value jr = reply;
        json::Value jails = json::Value::array();
        jails.push(json::Value::object().set("name", "agensio-drupal-auth").set("match", "SYSLOG_IDENTIFIER=drupal").set("seen", false));
        jails.push(json::Value::object().set("name", "agensio-wordpress-soft").set("why", "journalctl exited 1"));
        jr.set("journal", json::Value::object().set("available", true).set("jails", std::move(jails)));
        const ProtectionProbe jp = read_probe(jr, in);
        CHECK(jp.journal_seen.size() == 1 && jp.journal_seen[0].first == "agensio-drupal-auth" && !jp.journal_seen[0].second && probe.journal_seen.empty());
    }
    CHECK(probe.checked && probe.nft_available && probe.table);
    CHECK((probe.limited_tcp == std::vector<unsigned>{80, 443, 8080, 8443, 8444, 8445}) && (probe.limited_udp == std::vector<unsigned>{443}));
    CHECK(probe.rules.size() == 3 && probe.rules[0].comment == "agensio: new connections per IPv4 address" && probe.rules[0].packets == 12 && probe.rules[2].packets == 3);
    CHECK(probe.firewall_unit == "enabled" && !probe.trial_running && probe.units_why.empty() && probe.managers.size() == 1 && probe.managers[0].first == "nftables.service");
    CHECK(probe.fail2ban_available && probe.fail2ban_service == "active" && probe.jails.size() == 2 && !probe.jails[0].ours && probe.jails[1].ours &&
          probe.jails[1].files.size() == 2 && probe.jails[1].banned == 1 && probe.jails[1].total_banned == 3);
    // Everything in place: no finding, a summary that says so, and the report's shape.
    ProtectionFiles files;
    files.installed_jail = render_jail(in);
    files.firewall_file = render_nft(in);
    for (const auto& f : protection_filters()) files.installed_filters.emplace_back(f.text);
    auto codes = [&](const ProtectionInput& i, const ProtectionProbe& p, const ProtectionFiles& f) {
        std::string out;
        for (const auto& x : protection_findings(i, p, f)) out += (out.empty() ? "" : " ") + x.severity + ":" + x.code;
        return out;
    };
    CHECK(codes(in, probe, files).empty());
    {
        const json::Value r = protection_report(in, probe, files);
        CHECK(r["ok"].boolean() && r["exposed"].boolean() && r["ports"]["tcp"].items().size() == 2 && r["firewall"]["detected"]["covered"].boolean() &&
              r["firewall"]["detected"]["table_loaded"].boolean() && r["firewall"]["detected"].get("unit_state") == "enabled" && r["firewall"]["detected"]["rules"].items().size() == 3 &&
              r["firewall"]["trial"].items().size() == 3 && r["firewall"]["file_current"].boolean() && r["fail2ban"].get("installed_jail") == "same" &&
              r["fail2ban"]["detected"]["covered"].boolean() && r["fail2ban"]["detected"]["banned"].num() == 1 && r["fail2ban"]["filters"]["agensio-login"].is_string() &&
              r["findings"].items().empty());
        // A jail of someone else's: its file count, not its files (the Samba jail of the report).
        const json::Value& jails = r["fail2ban"]["detected"]["jails"];
        CHECK(jails.items().size() == 2 && jails.items()[0]["files"].is_null() && jails.items()[0]["files_count"].num() == 1 && jails.items()[1]["files"].items().size() == 2);
        CHECK(r.get("summary") == "the firewall limits are loaded and enabled at boot; fail2ban reads the access logs (1 address(es) banned now, 3 since start)");
    }
    // The states, one by one.
    ProtectionFiles stale = files;
    stale.installed_jail = "[agensio-login]\nenabled = true\n";
    CHECK(codes(in, probe, stale) == "info:fail2ban_jail_stale" && protection_findings(in, probe, stale)[0].fix.starts_with("as root: agensio ctl protection --jail"));
    // An upgrade changed a shipped filter (the alpha.44 report): the installed copy is stale, the
    // install line leads every fix, the report says which; a missing filter counts too.
    ProtectionFiles oldf = files;
    oldf.installed_filters[0] = "[Definition]\nfailregex = old\n";
    {
        const auto f = protection_findings(in, probe, oldf);
        CHECK(codes(in, probe, oldf) == "warn:fail2ban_filter_stale" && f[0].message.starts_with("the installed filter(s) agensio-login in /etc/fail2ban/filter.d/ differ") &&
              f[0].fix == "as root: install -m 644 /usr/share/agensio/fail2ban/filter.d/agensio-login.conf /usr/share/agensio/fail2ban/filter.d/agensio-auth.conf "
                          "/usr/share/agensio/fail2ban/filter.d/agensio-scan.conf /usr/share/agensio/fail2ban/filter.d/agensio-post.conf /etc/fail2ban/filter.d/; fail2ban-client reload");
        const json::Value r = protection_report(in, probe, oldf);
        CHECK(r["fail2ban"]["installed_filters"].get("state") == "stale" && r["fail2ban"]["installed_filters"]["stale"].items().size() == 1 &&
              r.get("summary").find("the installed filter(s) agensio-login are older than the shipped text") != std::string_view::npos);
        oldf.installed_jail = "[agensio-login]\nenabled = true\n";
        const auto g = protection_findings(in, probe, oldf);
        CHECK(codes(in, probe, oldf) == "warn:fail2ban_filter_stale info:fail2ban_jail_stale" && g[0].fix.find("; agensio ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf; fail2ban-client reload") != std::string::npos &&
              g[1].fix.starts_with("as root: install -m 644 "));
        ProtectionFiles none = files;
        none.installed_filters.clear();
        CHECK(protection_report(in, probe, none)["fail2ban"]["installed_filters"].get("state") == "missing" && codes(in, probe, none).empty());  // a panel's own jails read our logs: nothing to say
        ProtectionFiles part = files;
        part.installed_filters[3].reset();
        CHECK(protection_report(in, probe, part)["fail2ban"]["installed_filters"].get("state") == "partial" && protection_findings(in, probe, part)[0].message.find("agensio-post are not installed") != std::string::npos);
    }
    ProtectionFiles nojail = files;
    nojail.installed_jail.reset();
    CHECK(codes(in, probe, nojail).empty());  // the jails that read our logs are someone else's file: fine
    ProtectionProbe p2 = probe;
    p2.firewall_unit = "disabled";
    CHECK(codes(in, p2, files) == "warn:firewall_limits_unsaved" && protection_findings(in, p2, files)[0].fix == "as root: systemctl stop agensio-firewall-trial.timer; systemctl enable --now agensio-firewall.service");
    p2.trial_running = true;
    CHECK(codes(in, p2, files) == "info:firewall_limits_trial");
    p2.trial_running = false;
    p2.firewall_unit = "";
    p2.units_why = "systemctl not available on this host";
    CHECK(codes(in, p2, files) == "info:firewall_limits_unsaved" && protection_findings(in, p2, files)[0].message.find("could not be told: systemctl not available") != std::string::npos);
    ProtectionProbe p3 = probe;
    p3.limited_udp.clear();
    CHECK(codes(in, p3, files) == "info:firewall_quic_unlimited");
    ProtectionProbe none = probe;
    none.table = false;
    none.limited_tcp = {8080};
    none.limited_udp.clear();
    none.rules.clear();
    none.jails.clear();
    {
        const auto f = protection_findings(in, none, files);
        CHECK(codes(in, none, files) == "warn:firewall_limits_missing warn:fail2ban_missing");
        CHECK(f[0].message.starts_with("no per-address limit on the web ports (80, 443) in the kernel's firewall") &&
              f[0].fix.find("agensio ctl protection --nft > /etc/agensio/firewall.nft; nft -f /etc/agensio/firewall.nft; systemd-run --on-active=10min") != std::string::npos &&
              f[0].fix.find("then keep it: systemctl stop agensio-firewall-trial.timer; systemctl enable --now agensio-firewall.service") != std::string::npos);
        CHECK(f[1].message.starts_with("no fail2ban jail reads agensio's access logs (/var/log/agensio/access.log, /var/log/agensio/wp.log)") && f[1].message.find("/login, /wp-login.php") != std::string::npos &&
              f[1].fix.find("agensio ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf; fail2ban-client reload") != std::string::npos);
        ProtectionInput ext = in;
        ext.host_protection = "external";
        CHECK(codes(ext, none, files) == "info:firewall_limits_missing info:fail2ban_missing" && protection_findings(ext, none, files)[0].message.find("managed outside agensio") != std::string::npos);
        ext.host_protection = "off";
        CHECK(codes(ext, none, files).empty() && protection_report(ext, none, files).get("summary").starts_with("[control] host_protection = \"off\""));
        ProtectionInput lo = in;
        lo.exposed = false;
        CHECK(codes(lo, none, files).empty() && protection_report(lo, none, files).get("summary").starts_with("every listener is on loopback"));
        CHECK(protection_report(in, none, files).get("summary") == "no per-address limit on port(s) 80, 443; no fail2ban jail reads the access logs");
    }
    // Our table loaded for other ports than the listeners have now: render again.
    ProtectionProbe moved = probe;
    moved.limited_tcp = {80};
    CHECK(codes(in, moved, files) == "warn:firewall_limits_missing" && protection_findings(in, moved, files)[0].message.starts_with("the agensio firewall table is loaded but covers no limit on port(s) 443"));
    // Another table's limits count; fail2ban down; the tools absent; the helper away; JSON logs.
    ProtectionProbe theirs = probe;
    theirs.table = false;
    theirs.rules.clear();
    CHECK(codes(in, theirs, files).empty() && protection_report(in, theirs, files).get("summary").starts_with("per-address limits on the web ports exist in another table"));
    ProtectionProbe down = probe;
    down.fail2ban_service = "inactive";
    down.jails.clear();
    CHECK(codes(in, down, files) == "warn:fail2ban_missing" && protection_findings(in, down, files)[0].message.starts_with("fail2ban is installed but not running") &&
          protection_findings(in, down, files)[0].fix.find("systemctl enable --now fail2ban") != std::string::npos);
    json::Value bare = json::Value::object().set("ok", true).set("nft", json::Value::object().set("available", false).set("why", "nft is not installed (package nftables)"))
                           .set("units", json::Value(nullptr)).set("units_why", "systemctl not available on this host")
                           .set("fail2ban", json::Value::object().set("available", false).set("why", "fail2ban is not installed (package fail2ban)"));
    const ProtectionProbe absent = read_probe(bare, in);
    CHECK(absent.checked && !absent.nft_available && !absent.fail2ban_available && codes(in, absent, files) == "warn:firewall_limits_missing warn:fail2ban_missing" &&
          protection_findings(in, absent, files)[0].message.starts_with("nft is not installed") && protection_findings(in, absent, files)[1].fix.starts_with("install fail2ban, then as root:"));
    const ProtectionProbe busy = read_probe(json::Value::object().set("ok", false).set("busy", true), in);
    CHECK(!busy.checked && codes(in, busy, files) == "info:protection_unchecked" && protection_findings(in, busy, files)[0].message.find("the helper is busy") != std::string::npos);
    const ProtectionProbe nohelper = read_probe(json::Value(nullptr), in);
    CHECK(!nohelper.checked && nohelper.why.find("provisioning helper") != std::string::npos);
    ProtectionInput js = in;
    js.combined = false;
    CHECK(codes(js, probe, files) == "warn:fail2ban_log_format");
    ProtectionInput blind = in;
    blind.unlogged = {"quiet.test"};
    CHECK(codes(blind, probe, files) == "info:fail2ban_blind");
    // A failure jail not yet in place: informational while our jails run, with the user's steps.
    ProtectionInput unseen = in;
    FailureJail fj;
    fj.name = "agensio-wordpress-soft";
    fj.app = "wordpress";
    fj.sites = {"wp.test"};
    fj.filter = "wordpress-soft";
    fj.log = "/var/log/auth.log";
    fj.log_present = true;
    fj.needs = {"install the plugin from the admin panel", "root copies the filters", "render again"};
    unseen.failure_jails.push_back(fj);
    ProtectionFiles ufiles = files;
    ufiles.installed_jail = render_jail(unseen);  // the jail on disk is this rendering, so only the tier's finding remains
    CHECK(codes(unseen, probe, ufiles) == "info:fail2ban_failures_unseen" && protection_findings(unseen, probe, ufiles)[0].message.starts_with("wp.test (wordpress): failed logins are counted only as attempts at the login paths; the jail(s) agensio-wordpress-soft over") &&
          protection_findings(unseen, probe, ufiles)[0].message.find("the filter wordpress-soft is not in /etc/fail2ban/filter.d/") != std::string::npos &&
          protection_findings(unseen, probe, ufiles)[0].fix == "install the plugin from the admin panel; root copies the filters; render again");
    unseen.failure_jails[0].filter_installed = true;
    ufiles.installed_jail = render_jail(unseen);
    CHECK(codes(unseen, probe, ufiles).empty());
    // A journald-only host (alpha.48 report): the jail is enabled, since the journal always
    // exists, and the finding stays while the journal holds no line of the application; a
    // probe that could not ask claims nothing.
    unseen.failure_jails[0].journal = true;
    unseen.failure_jails[0].journalmatch = "_SYSTEMD_UNIT=php8.4-fpm.service _UID=996";
    unseen.failure_jails[0].silent = "the plugin is not active yet";
    ufiles.installed_jail = render_jail(unseen);
    ProtectionProbe silent = probe;
    silent.journal_seen = {{"agensio-wordpress-soft", false}};
    CHECK(codes(unseen, silent, ufiles) == "info:fail2ban_failures_unseen" &&
          protection_findings(unseen, silent, ufiles)[0].message ==
              "wp.test (wordpress): failed logins are counted only as attempts at the login paths; the jail(s) agensio-wordpress-soft read the journal and it holds no line matching _SYSTEMD_UNIT=php8.4-fpm.service _UID=996 from the last 30 days, so the plugin is not active yet" &&
          protection_findings(unseen, silent, ufiles)[0].fix == "install the plugin from the admin panel");
    CHECK(protection_report(unseen, silent, ufiles)["failure_jails"].items()[0]["journal_seen"].boolean() == false &&
          protection_report(unseen, probe, ufiles)["failure_jails"].items()[0]["journal_seen"].is_null());
    silent.journal_seen = {{"agensio-wordpress-soft", true}};
    CHECK(codes(unseen, silent, ufiles).empty() && protection_report(unseen, silent, ufiles)["failure_jails"].items()[0]["journal_seen"].boolean());
    CHECK(codes(unseen, probe, ufiles).empty());
    // One jail disabled and the other enabled over a silent journal: one finding, both named, the full steps.
    FailureJail hard = unseen.failure_jails[0];
    hard.name = "agensio-wordpress-hard";
    hard.filter = "wordpress-hard";
    hard.filter_installed = false;
    unseen.failure_jails.push_back(hard);
    silent.journal_seen = {{"agensio-wordpress-soft", false}};
    ufiles.installed_jail = render_jail(unseen);
    CHECK(codes(unseen, silent, ufiles) == "info:fail2ban_failures_unseen" &&
          protection_findings(unseen, silent, ufiles)[0].message.find("the jail(s) agensio-wordpress-hard over the application's own log are rendered disabled: the filter wordpress-hard is not in /etc/fail2ban/filter.d/; the jail(s) agensio-wordpress-soft read the journal and it holds no line") != std::string::npos &&
          protection_findings(unseen, silent, ufiles)[0].fix == "install the plugin from the admin panel; root copies the filters; render again");
    unseen.failure_jails.pop_back();
    // A site the enabled jail cannot read (no account of its own): named, with the account step
    // as the fix; the journal's answer about the other sites does not hide it.
    unseen.failure_jails[0].unidentified = {"wp2.test (no account of its own: the site's user is not set)"};
    unseen.failure_jails[0].needs = {"install the plugin from the admin panel", "root copies the filters", "give wp2.test (no account of its own: the site's user is not set) an account of its own", "render again"};
    ufiles.installed_jail = render_jail(unseen);
    silent.journal_seen = {{"agensio-wordpress-soft", true}};
    CHECK(codes(unseen, silent, ufiles) == "info:fail2ban_failures_unseen" &&
          protection_findings(unseen, silent, ufiles)[0].message ==
              "wp.test (wordpress): failed logins are counted only as attempts at the login paths; the jail(s) agensio-wordpress-soft read no line of wp2.test (no account of its own: the site's user is not set), which no trusted journal field tells from any other process's" &&
          protection_findings(unseen, silent, ufiles)[0].fix == "give wp2.test (no account of its own: the site's user is not set) an account of its own" &&
          protection_report(unseen, silent, ufiles)["failure_jails"].items()[0]["unidentified"].items().size() == 1);
    silent.journal_seen = {{"agensio-wordpress-soft", false}};  // silent and unread: both said, the application's step first
    CHECK(protection_findings(unseen, silent, ufiles)[0].message.find("read the journal and it holds no line matching _SYSTEMD_UNIT=php8.4-fpm.service _UID=996 from the last 30 days, so the plugin is not active yet; the jail(s) agensio-wordpress-soft read no line of wp2.test") != std::string::npos &&
          protection_findings(unseen, silent, ufiles)[0].fix == "install the plugin from the admin panel");
    unseen.failure_jails[0].unidentified.clear();
    unseen.failure_jails[0].needs = {"install the plugin from the admin panel", "root copies the filters", "render again"};
    unseen.failure_jails[0].journal = false;
    unseen.failure_jails[0].journalmatch.clear();
    unseen.failure_jails[0].filter_installed = false;
    ufiles.installed_jail = render_jail(unseen);
    CHECK(codes(unseen, none, ufiles) == "warn:firewall_limits_missing warn:fail2ban_missing");  // without our jails running, fail2ban_missing says it all
    fs::remove_all(dir);
}

// The configuration reference (F11) is held to the parser and to the reference document:
// every key the parser reads is a row, every row's section exists, docs/keys.md is what the
// binary prints (the integration suite diffs it), and the JSON carries running values.
static void test_config_reference() {
    namespace fs = std::filesystem;
    using namespace control;
    std::set<std::string> rows;
    for (const auto& d : key_defs()) {
        CHECK(*d.key && *d.type && *d.def && *d.meaning && *d.applies && *d.via && *d.doc);
        rows.insert(d.key);
    }
    // Every quoted lower-case identifier the parser reads as a key (config.cpp, the parse
    // functions) must be a row. Values ("static", "auto", ...) are listed apart.
    std::ifstream in(std::string(AGENSIO_SOURCE_DIR) + "/src/config.cpp");
    const std::string src((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CHECK(!src.empty());
    const std::set<std::string> values = {"static", "dynamic", "ondemand", "auto", "off", "on", "json", "combined", "info", "warn", "error", "stderr",
                                          "exact", "prefix", "suffix", "value", "agensio", "https", "http", "none", "allow", "deny", "append", "replace",
                                          "rfc7239", "rewrite", "pass", "fastcgi", "proxy", "cgi", "control", "php", "laravel", "wordpress", "drupal",
                                          "linux", "darwin", "unix", "tcp", "get", "head", "post", "put", "delete", "patch", "options", "trace", "connect",
                                          "server", "cache", "log", "site", "acme", "http2", "http3", "httparena"};  // table names, not keys
    std::set<std::string> missing;
    const std::size_t begin = src.find("void parse_proxy_policy"), end = src.find("json::Value preset_catalog");
    CHECK(begin != std::string::npos && end != std::string::npos && begin < end);
    for (std::size_t i = begin; i < end;) {
        const std::size_t q = src.find('"', i);
        if (q == std::string::npos || q >= end) break;
        const std::size_t e = src.find('"', q + 1);
        if (e == std::string::npos) break;
        const std::string word = src.substr(q + 1, e - q - 1);
        i = e + 1;
        bool ident = !word.empty();
        for (unsigned char c : word) ident = ident && ((c >= 'a' && c <= 'z') || c == '_' || (c >= '0' && c <= '9'));
        if (!ident || (src[q - 1] != '[' && src.compare(q - 6, 6, "count(") != 0)) continue;  // only n["key"] and count("key") reads
        if (!rows.count(word) && !values.count(word)) missing.insert(word);
    }
    if (!missing.empty()) {
        std::string list;
        for (const auto& m : missing) list += " " + m;
        std::printf("config keys read by the parser but missing from the reference table:%s\n", list.c_str());
    }
    CHECK(missing.empty());
    // Every doc section a row names is a heading of docs/configuration.md.
    std::ifstream din(std::string(AGENSIO_SOURCE_DIR) + "/docs/configuration.md");
    const std::string doc((std::istreambuf_iterator<char>(din)), std::istreambuf_iterator<char>());
    for (const auto& d : key_defs()) CHECK(doc.find("\n## " + std::string(d.doc) + ". ") != std::string::npos);
    // The JSON: the running values of a loaded configuration, and the file they come from.
    const fs::path dir = fs::temp_directory_path() / ("agensio-ref-" + std::to_string(::getpid()));
    fs::create_directories(dir / "www");
    std::ofstream(dir / "a.toml") << "[server]\nworkers = 3\n[[site]]\nlisten = [\"127.0.0.1:1\"]\nroot = \"www\"\n";
    const Config cfg = load_config(dir / "a.toml");
    const json::Value ref = config_reference(&cfg);
    bool workers = false;
    for (const auto& k : ref["keys"].items())
        if (k.get("key") == "workers" && k.get("table") == "[server]") workers = k["running"].num() == 3 && k.get("applies") == "restart" && k.get("via") == "file" && k.get("file") == (dir / "a.toml").string();
    CHECK(workers && !ref["how_to_change"].get("file").empty());
    CHECK(reference_markdown().find("| `workers` |") != std::string::npos);
    fs::remove_all(dir);
}

// The refused-endings rule, with the spellings a live host served as source.
// HTTP/2 framing, settings, the shared field rules and HPACK (RFC 7541 appendix C).
static std::string unhex(std::string_view hex) {
    std::string out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<char>(std::stoul(std::string(hex.substr(i, 2)), nullptr, 16)));
    return out;
}
static std::string tohex(std::string_view s) {
    static const char* d = "0123456789abcdef";
    std::string out;
    for (const unsigned char c : s) {
        out.push_back(d[c >> 4]);
        out.push_back(d[c & 15]);
    }
    return out;
}

// HTTP/2 and HTTP/3 request assembly: a browser's cookie crumbs (one field per pair) reach
// every handler as one field, in order (RFC 9113 8.2.3, RFC 9114 4.2.1; 2026-09-27 report:
// only the first crumb survived, so no browser stayed signed in to a proxied application).
static void test_request_assembly_cookies() {
    // `arena` plays the decoder's: reserved once, so the views stay put, and the caller's,
    // so they outlive the call.
    auto assemble = [](const std::vector<std::pair<std::string, std::string>>& fields, Request& req, std::string& cookie, http::RequestSeen& seen,
                       std::string& arena) {
        arena.clear();
        arena.reserve(64 * 1024);
        for (const auto& [n, v] : fields) {
            const std::size_t a = arena.size();
            arena.append(n);
            const std::size_t b = arena.size();
            arena.append(v);
            http::sink_field(seen, req, cookie, std::string_view(arena).substr(a, n.size()), std::string_view(arena).substr(b, v.size()), codec::Origin{});
        }
        bool known = false;
        std::uint64_t len = 0;
        return !seen.overflow && http::finish_request(seen, req, cookie, "HTTP/2.0", known, len) == http::Assembled::ok;
    };
    std::string arena;
    const std::vector<std::pair<std::string, std::string>> base = {{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {":authority", "a.test"}};
    {
        auto f = base;
        f.insert(f.end(), {{"cookie", "_writebook_session=S"}, {"accept", "*/*"}, {"cookie", "session_token=T"}, {"cookie", "c=3"}});
        Request req;
        std::string cookie;
        http::RequestSeen seen;
        const bool ok = assemble(f, req, cookie, seen, arena);
        std::vector<std::string> names;
        for (const HeaderField& h : req.headers) names.emplace_back(h.name);
        CHECK(ok && req.headers.get("cookie") == "_writebook_session=S; session_token=T; c=3" &&
              names == (std::vector<std::string>{"cookie", "accept", "host"}));
    }
    {   // one crumb: the field as it came, nothing copied
        auto f = base;
        f.push_back({"cookie", "a=1"});
        Request req;
        std::string cookie = "stale from the stream's last request";
        http::RequestSeen seen;
        const bool ok = assemble(f, req, cookie, seen, arena);
        CHECK(ok && req.headers.get("cookie") == "a=1" && req.headers.get("cookie").data() >= arena.data() && req.headers.get("cookie").data() < arena.data() + arena.size());
    }
    {   // 150 crumbs: one field, never the 100-field limit
        auto f = base;
        std::string want;
        for (int i = 0; i < 150; ++i) {
            f.push_back({"cookie", "c" + std::to_string(i) + "=v"});
            want += (i ? "; " : "") + ("c" + std::to_string(i) + "=v");
        }
        Request req;
        std::string cookie;
        http::RequestSeen seen;
        const bool ok = assemble(f, req, cookie, seen, arena);
        CHECK(ok && !seen.overflow && req.headers.size() == 2 && req.headers.get("cookie") == want);
    }
}

static void test_h2_frame_and_settings() {
    using namespace h2;
    unsigned char buf[kFrameHeaderSize];
    write_frame_header(buf, 0x123456, FrameType::headers, flag::end_headers | flag::end_stream, 0x80000007u);
    const FrameHeader h = read_frame_header(buf);
    CHECK(h.length == 0x123456 && h.type == 1 && h.flags == 5 && h.stream_id == 7);  // the reserved bit is dropped
    std::string out;
    append_goaway(out, 9, ErrorCode::enhance_your_calm, "calm");
    CHECK(tohex(out) == "00000c07000000000000000009000000" "0b" "63616c6d");
    out.clear();
    append_rst_stream(out, 3, ErrorCode::cancel);
    CHECK(tohex(out) == "000004030000000003" "00000008");
    out.clear();
    append_window_update(out, 0, 1u << 20);
    CHECK(tohex(out) == "000004080000000000" "00100000");
    out.clear();
    const SettingPair pairs[] = {{setting_max_concurrent_streams, 128}, {setting_no_rfc7540_priorities, 1}};
    append_settings(out, pairs);
    CHECK(tohex(out) == "00000c040000000000" "000300000080" "000900000001");
    out.clear();
    append_settings_ack(out);
    CHECK(tohex(out) == "000000040100000000");
    const unsigned char ping[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    out.clear();
    append_ping_ack(out, ping);
    CHECK(tohex(out) == "000008060100000000" "0102030405060708");
    PeerSettings ps;
    CHECK(ps.apply(setting_enable_push, 2) == ErrorCode::protocol_error);
    CHECK(ps.apply(setting_initial_window_size, 0x80000000u) == ErrorCode::flow_control_error);
    CHECK(ps.apply(setting_max_frame_size, 100) == ErrorCode::protocol_error);
    CHECK(ps.apply(setting_max_frame_size, 1u << 24) == ErrorCode::protocol_error);
    CHECK(ps.apply(setting_max_frame_size, 65536) == ErrorCode::no_error && ps.max_frame_size == 65536);
    CHECK(ps.apply(setting_initial_window_size, 1 << 20) == ErrorCode::no_error && ps.initial_window_size == 1u << 20);
    CHECK(ps.apply(setting_no_rfc7540_priorities, 1) == ErrorCode::no_error && ps.no_rfc7540_priorities);
    CHECK(ps.apply(0x99, 12345) == ErrorCode::no_error);  // unknown: ignored
    CHECK(error_name(ErrorCode::compression_error) == "COMPRESSION_ERROR");
    // The shared field rules.
    CHECK(fields::valid_name("content-type") && fields::valid_name("x-a_b.c~") && !fields::valid_name("Content-Type") &&
          !fields::valid_name("a b") && !fields::valid_name("") && !fields::valid_name("a\x7f" "b"));
    CHECK(fields::valid_value("text/html; charset=utf-8") && fields::valid_value("") && !fields::valid_value("a\r\nb") &&
          !fields::valid_value(std::string_view("a\0b", 3)) && !fields::valid_value(" x") && !fields::valid_value("x\t"));
    CHECK(fields::connection_specific("transfer-encoding") && fields::connection_specific("keep-alive") &&
          !fields::connection_specific("te") && !fields::connection_specific("host"));
}


// ---- QPACK (RFC 9204) over the static table, and the QUIC transport's codecs (RFC 9000, 9001, 9002) ----
static void test_qpack() {
    unsigned i = 0;
    CHECK(qpack::static_name("server", i) && i == 92);
    CHECK(qpack::static_name("date", i) && i == 6);
    CHECK(qpack::static_pair(":method", "GET", i) && i == 17);
    CHECK(qpack::static_pair("content-type", "application/json", i) && i == 46);
    CHECK(qpack::static_pair("accept-ranges", "bytes", i) && i == 32);
    CHECK(qpack::static_pair("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'", i) && i == 85);
    CHECK(!qpack::static_pair("content-type", "text/x-agensio", i) && !qpack::static_name("x-nothing", i));
    std::string sec;
    qpack::append_section_prefix(sec);
    qpack::append_status(sec, 200);
    CHECK(sec.size() == 3 && static_cast<unsigned char>(sec[2]) == 0xd9);  // 11 + 011001: static index 25
    qpack::append_field(sec, "content-type", "text/plain");             // static pair 53
    qpack::append_field(sec, "server", "agensio");                       // name reference 92
    qpack::append_field(sec, "content-length", "55");                    // name reference 4
    qpack::append_field(sec, "x-custom", "v");                           // literal name
    qpack::append_status(sec, 299);                                      // literal by name
    struct Field { std::string name, value; bool static_pair; };
    std::vector<Field> got;
    std::string arena;
    qpack::Decoder d;
    auto r = d.decode(sec, arena, 16384, [&](std::string_view n, std::string_view v, qpack::Origin o) {
        got.push_back({std::string(n), std::string(v), o.static_table});
        return true;
    });
    CHECK(r == qpack::Decoder::Result::ok && got.size() == 6);
    CHECK(got[0].name == ":status" && got[0].value == "200" && got[0].static_pair);
    CHECK(got[1].name == "content-type" && got[1].value == "text/plain" && got[1].static_pair);
    CHECK(got[2].name == "server" && got[2].value == "agensio" && !got[2].static_pair);
    CHECK(got[3].name == "content-length" && got[3].value == "55");
    CHECK(got[4].name == "x-custom" && got[4].value == "v");
    CHECK(got[5].name == ":status" && got[5].value == "299");
    // A dynamic reference is refused (the table capacity is 0), as is a bad prefix.
    std::string dyn = std::string("\0\0", 2) + std::string("\x80", 1);
    arena.clear();
    CHECK(d.decode(dyn, arena, 16384, [](std::string_view, std::string_view, qpack::Origin) { return true; }) == qpack::Decoder::Result::malformed);
    std::string ric = std::string("\x01\x00", 2) + std::string("\xd9", 1);
    CHECK(d.decode(ric, arena, 16384, [](std::string_view, std::string_view, qpack::Origin) { return true; }) == qpack::Decoder::Result::malformed);
    // The list-size budget stops the decode.
    std::string big;
    qpack::append_section_prefix(big);
    qpack::append_field(big, "x-a", std::string(100, 'a'));
    arena.clear();
    CHECK(d.decode(big, arena, 100, [](std::string_view, std::string_view, qpack::Origin) { return true; }) == qpack::Decoder::Result::too_large);
}


// RFC 9204 appendix B: the encoder stream, blocked and unblocked sections, the decoder stream.
static void test_qpack_dynamic() {
    using qpack::Decoder;
    struct Field { std::string name, value; };
    std::vector<Field> got;
    std::string arena, dec_out;
    auto sink = [&](std::string_view n, std::string_view v, qpack::Origin) { got.push_back({std::string(n), std::string(v)}); return true; };
    Decoder d;  // our capacity: 4096; the example's encoder sets 220
    std::uint64_t required = 99;
    std::size_t consumed = 0;
    // B.1: a literal with a static name reference, no dynamic table.
    got.clear();
    CHECK(d.decode(unhex("0000510b2f696e6465782e68746d6c"), arena, 16384, sink, required) == Decoder::Result::ok);
    CHECK(required == 0 && got.size() == 1 && got[0].name == ":path" && got[0].value == "/index.html");
    // B.2's section before its inserts arrive: blocked with Required Insert Count 2.
    got.clear();
    CHECK(d.decode(unhex("03811011"), arena, 16384, sink, required) == Decoder::Result::blocked && required == 2);
    // B.2: capacity 220, two inserts with static name references, cut at an instruction boundary and then completed.
    const std::string enc = unhex("3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468");
    CHECK(d.encoder_stream(std::string_view(enc).substr(0, 10), consumed) && consumed == 3 && d.capacity() == 220 && d.insert_count() == 0);
    CHECK(d.encoder_stream(std::string_view(enc).substr(3), consumed) && consumed == enc.size() - 3);
    CHECK(d.insert_count() == 2 && d.table_size() == 106 && d.table_entries() == 2);
    got.clear();
    CHECK(d.decode(unhex("03811011"), arena, 16384, sink, required) == Decoder::Result::ok && required == 2);
    CHECK(got.size() == 2 && got[0].name == ":authority" && got[0].value == "www.example.com" && got[1].name == ":path" && got[1].value == "/sample/path");
    d.section_acknowledged(4, required, dec_out);
    CHECK(tohex(dec_out) == "84" && d.known_received() == 2);
    dec_out.clear();
    // B.3: a speculative insert with a literal name; the decoder increments the insert count.
    CHECK(d.encoder_stream(unhex("4a637573746f6d2d6b65790c637573746f6d2d76616c7565"), consumed) && d.insert_count() == 3 && d.table_size() == 160);
    d.insert_count_increment(dec_out);
    CHECK(tohex(dec_out) == "01" && d.known_received() == 3);
    dec_out.clear();
    d.insert_count_increment(dec_out);
    CHECK(dec_out.empty());  // nothing new to tell
    // B.4: a duplicate of absolute index 0; the section on stream 8 references the copy and the static table.
    CHECK(d.encoder_stream(unhex("02"), consumed) && d.insert_count() == 4 && d.table_size() == 217);
    got.clear();
    CHECK(d.decode(unhex("050080c181"), arena, 16384, sink, required) == Decoder::Result::ok && required == 4);
    CHECK(got.size() == 3 && got[0].name == ":authority" && got[0].value == "www.example.com" && got[1].name == ":path" && got[1].value == "/" &&
          got[2].name == "custom-key" && got[2].value == "custom-value");
    d.stream_cancelled(8, dec_out);
    CHECK(tohex(dec_out) == "48");
    dec_out.clear();
    // B.5: an insert with a dynamic name reference (relative 1 = absolute 2) evicts the oldest entry.
    CHECK(d.encoder_stream(unhex("810d637573746f6d2d76616c756532"), consumed) && d.insert_count() == 5 && d.table_size() == 215 && d.table_entries() == 4);
    got.clear();
    CHECK(d.decode(unhex("050080"), arena, 16384, sink, required) == Decoder::Result::ok);  // absolute 3 (the duplicate) is still there
    CHECK(got.size() == 1 && got[0].value == "www.example.com");
    // A reference to the evicted entry (absolute 0, relative 4 at base 5) is malformed.
    CHECK(d.decode(unhex("060084"), arena, 16384, sink, required) == Decoder::Result::malformed);
    // Errors on the encoder stream: a capacity above ours, an entry larger than the capacity.
    CHECK(d.encoder_stream(unhex("3fe11f"), consumed) && d.capacity() == 4096);  // exactly ours: allowed
    CHECK(!d.encoder_stream(unhex("3fe21f"), consumed));  // 4096 + 1
    Decoder small;
    CHECK(small.encoder_stream(unhex("2a"), consumed) && small.capacity() == 10);  // 10 bytes: nothing fits
    CHECK(!small.encoder_stream(unhex("c00f7777772e6578616d706c652e636f6d"), consumed));
    // Blocked-section bookkeeping through the connection is exercised by the integration suite's clients.
}

// The encoder side (RFC 9204 appendix B from the encoder's chair, and the rules of
// sections 2.1.1 and 2.1.2): the instruction bytes, the section bytes, the round trip
// through our decoder, the peer's decoder stream, references holding entries in the
// table, the blocked-streams limit.
static void test_qpack_encoder() {
    using namespace agensio::qpack;
    {
        Encoder e;
        Section sec0;
        std::string sec;
        e.begin(sec0);
        e.server(sec, "agensio");  // no peer settings yet: a literal with a static name reference
        CHECK(!e.enabled() && (static_cast<unsigned char>(sec[0]) & 0xf0) == 0x50);
        std::string px;
        e.prefix(px);
        CHECK(px == std::string("\0\0", 2));
        e.end();
        CHECK(!sec0.pending && e.instructions().empty());
    }
    {
        // B.2: capacity 220, two inserts with static name references, the section that
        // references them post-base: the same section bytes the appendix shows.
        Encoder e;
        e.set_peer(220, 100);
        Encoder::Memo authority, path;
        Section s0;
        std::string sec, px;
        e.begin(s0);
        e.memo_field(sec, 0, ":authority", "www.example.com", authority);
        e.memo_field(sec, 1, ":path", "/sample/path", path);
        e.prefix(px);
        // The appendix writes the values raw; ours are Huffman when shorter, the same table results.
        CHECK(e.instructions().compare(0, 4, unhex("3fbd01c0")) == 0 && e.instructions().size() < 36);
        CHECK(px + sec == unhex("03811011"));
        e.end();
        CHECK(s0.pending && s0.ric == 2 && s0.n == 2 && e.insert_count() == 2 && e.table_entries() == 2 && e.known_received() == 0);
        // Our decoder reads it back.
        Decoder d;
        std::size_t consumed = 0;
        CHECK(d.encoder_stream(e.instructions(), consumed) && consumed == e.instructions().size() && d.insert_count() == 2);
        std::string arena, fields;
        std::uint64_t required = 0;
        CHECK(d.decode(px + sec, arena, 16384, [&](std::string_view n, std::string_view v, Origin) { fields += std::string(n) + "=" + std::string(v) + ";"; return true; }, required) == Decoder::Result::ok);
        CHECK(fields == ":authority=www.example.com;:path=/sample/path;" && required == 2);
        // The peer acknowledges the section (stream 0): the references are released, known received count 2.
        std::vector<std::pair<std::uint64_t, bool>> seen;
        auto route = [&](std::uint64_t id, bool cancelled) {
            seen.emplace_back(id, cancelled);
            if (id == 0) { if (cancelled) e.cancelled(s0); else e.acknowledged(s0); }
        };
        CHECK(e.decoder_stream(unhex("80"), consumed, route) && consumed == 1 && !s0.pending && e.known_received() == 2);
        // A second section references both again, relative to its base, and adds nothing.
        e.instructions().clear();
        Section s1;
        sec.clear(); px.clear();
        e.begin(s1);
        e.memo_field(sec, 0, ":authority", "www.example.com", authority);
        e.memo_field(sec, 1, ":path", "/sample/path", path);
        e.prefix(px);
        CHECK(e.instructions().empty() && px + sec == unhex("03008180"));
        e.end();
        Decoder d2;
        CHECK(d2.encoder_stream(unhex("3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468"), consumed));
        fields.clear();
        CHECK(d2.decode(px + sec, arena, 16384, [&](std::string_view n, std::string_view v, Origin) { fields += std::string(n) + "=" + std::string(v) + ";"; return true; }, required) == Decoder::Result::ok);
        CHECK(fields == ":authority=www.example.com;:path=/sample/path;");
        // A cancellation for stream 4 is reported and releases nothing here; an increment beyond the inserts is an error.
        CHECK(e.decoder_stream(unhex("44"), consumed, route) && seen.back() == std::make_pair(std::uint64_t{4}, true));
        CHECK(!e.decoder_stream(unhex("05"), consumed, route));
        CHECK(!e.decoder_stream(unhex("00"), consumed, route));  // an increment of 0 is an error
        e.cancelled(s1);
        CHECK(!s1.pending);
    }
    {
        // 2.1.1: an entry a pending section references is never evicted; the insert that
        // would need to is refused and the field goes as a literal.
        Encoder e;
        e.set_peer(100, 100);  // room for one entry: server (6 + 7 + 32 = 45) or date (4 + 29 + 32 = 65), not both
        Section s0, s1;
        std::string sec, px;
        e.begin(s0);
        e.server(sec, "agensio");
        CHECK(e.table_entries() == 1 && (static_cast<unsigned char>(sec[0]) & 0xf0) == 0x10);  // post-base reference
        e.date(sec, 1000, "Thu, 25 Sep 2026 06:00:00 GMT");
        CHECK(e.table_entries() == 1);  // could not evict the referenced server entry: a literal
        CHECK((static_cast<unsigned char>(sec[1]) & 0xf0) == 0x50);
        e.prefix(px);
        e.end();
        e.acknowledged(s0);  // acknowledged: the server entry may go
        sec.clear();
        e.begin(s1);
        e.date(sec, 1000, "Thu, 25 Sep 2026 06:00:00 GMT");
        CHECK(e.table_entries() == 1 && e.insert_count() == 2 && (static_cast<unsigned char>(sec[0]) & 0xf0) == 0x10);
        e.end();
    }
    {
        // 2.1.2: a peer that allows no blocked streams gets literals until it has acknowledged the insert.
        Encoder e;
        e.set_peer(4096, 0);
        Section s0, s1, s2, s3;
        std::string sec, px;
        e.begin(s0);
        e.server(sec, "agensio");
        CHECK(e.table_entries() == 1 && (static_cast<unsigned char>(sec[0]) & 0xf0) == 0x50);  // inserted, but a literal
        e.prefix(px);
        CHECK(px == std::string("\0\0", 2));
        e.end();
        CHECK(!s0.pending);
        CHECK(e.increment(1) && e.known_received() == 1);  // Insert Count Increment 1
        sec.clear(); px.clear();
        e.begin(s1);
        e.server(sec, "agensio");
        CHECK((static_cast<unsigned char>(sec[0]) & 0xc0) == 0x80);  // now an index byte
        e.prefix(px);
        CHECK(px == unhex("0200"));  // Required Insert Count 1 (encoded 2), base 1, delta 0
        e.end();
        // content-type: a static value is one static byte; another goes through the table once.
        sec.clear();
        e.begin(s2);
        e.content_type(sec, "text/html; charset=utf-8");
        CHECK(sec.size() == 1 && static_cast<unsigned char>(sec[0]) == (0xc0 | 52));  // static row 52
        e.content_type(sec, "text/html; charset=utf-8");
        CHECK(sec.size() == 2 && static_cast<unsigned char>(sec[1]) == (0xc0 | 52));  // remembered, no search
        e.content_type(sec, "text/x-agensio");
        e.content_type(sec, "text/x-agensio");
        CHECK(e.insert_count() == 2);
        {
            unsigned ct = 0;
            CHECK(static_name("content-type", ct) && ct == 44);  // kContentTypeName, the insert's name reference
        }
        e.end();
        CHECK(e.increment(1) && e.known_received() == 2);
        sec.clear();
        e.begin(s3);
        e.content_type(sec, "text/x-agensio");
        CHECK(sec.size() == 1 && e.insert_count() == 2);  // the memo: one index byte, no scan, no insert
        e.end();
        // The date by second: the same second is an index byte, the next second an insert.
        Section s4;
        sec.clear();
        e.begin(s4);
        e.date(sec, 5, "Thu, 25 Sep 2026 06:00:05 GMT");
        e.date(sec, 5, "Thu, 25 Sep 2026 06:00:05 GMT");
        e.date(sec, 6, "Thu, 25 Sep 2026 06:00:06 GMT");
        CHECK(e.insert_count() == 4);
        e.end();
    }
}

#ifdef AGENSIO_HAS_QUIC
static std::string bytes_of(std::string_view hex) { return unhex(std::string(hex)); }

// The stateless answers of the endpoint (design-http3 6.3, 6.4): reset tokens and Retry
// tokens from the process secret, the Retry packet, the stateless reset, the INVALID_TOKEN
// close.
static void test_quic_stateless() {
    using namespace agensio::quic;
    {
        // An unknown version (RFC 8999 5.1): the ids parse, the rest is opaque, and a
        // 1,200-byte datagram gets Version Negotiation naming the client's ids.
        unsigned char probe[1200] = {0xc0, 0xde, 0xad, 0xbe, 0xef, 8, 1, 2, 3, 4, 5, 6, 7, 8, 4, 9, 9, 9, 9, 0, 0x40, 0x00};
        PacketHeader ph;
        CHECK(parse_header(probe, sizeof probe, 8, ph));
        CHECK(ph.long_form && ph.version == 0xdeadbeef && ph.dcid.len == 8 && ph.scid.len == 4 && ph.total == sizeof probe);
        unsigned char vn[64 + 2 * kMaxCidLen];
        const std::size_t n = build_version_negotiation(vn, sizeof vn, ph.scid, ph.dcid, 0x0a0a0a0a, 0x33);
        CHECK(n == 1 + 4 + 1 + 4 + 1 + 8 + 8);
        CHECK((vn[0] & 0x80) != 0 && vn[1] == 0 && vn[4] == 0 && vn[5] == 4 && vn[10] == 8);
        CHECK(vn[n - 8] == 0 && vn[n - 5] == 1);  // version 1 first, then the reserved value
        PacketHeader vh;
        CHECK(parse_header(vn, n, 8, vh) && vh.version == 0 && vh.dcid.len == 4 && vh.scid.len == 8);
    }
    Cid a, b;
    a.assign(reinterpret_cast<const unsigned char*>("\x01\x02\x03\x04\x05\x06\x07\x08"), 8);
    b.assign(reinterpret_cast<const unsigned char*>("\x01\x02\x03\x04\x05\x06\x07\x09"), 8);
    unsigned char t1[16], t2[16], t3[16];
    reset_token(a, t1);
    reset_token(a, t2);
    reset_token(b, t3);
    CHECK(std::memcmp(t1, t2, 16) == 0);  // computed, never stored: the same id gives the same token
    CHECK(std::memcmp(t1, t3, 16) != 0);
    // Retry tokens: bound to the address, the original id and the time.
    const unsigned char addr[6] = {127, 0, 0, 1, 0x1f, 0x90};
    const unsigned char other[6] = {127, 0, 0, 1, 0x1f, 0x91};
    const std::string token = seal_token(addr, sizeof addr, a, 1000);
    CHECK(token.size() == 12 + 9 + 8 + 16);
    Cid out;
    CHECK(open_token(token, addr, sizeof addr, 1005, 10, out));
    CHECK(out == a);
    CHECK(!open_token(token, other, sizeof other, 1005, 10, out));  // another port
    CHECK(!open_token(token, addr, sizeof addr, 1011, 10, out));    // too old
    CHECK(!open_token(token, addr, sizeof addr, 999, 10, out));     // from the future
    std::string bad = token;
    bad[20] ^= 1;
    CHECK(!open_token(bad, addr, sizeof addr, 1005, 10, out));      // tampered
    CHECK(!open_token(token.substr(0, 30), addr, sizeof addr, 1005, 10, out));
    CHECK(seal_token(addr, sizeof addr, a, 1000) != token);         // a fresh nonce each time
    // The Retry packet: the layout of RFC 9000 17.2.5 and a tag that verifies (RFC 9001 5.8).
    Cid client_scid, ours;
    client_scid.assign(reinterpret_cast<const unsigned char*>("\xaa\xbb\xcc\xdd"), 4);
    ours.assign(reinterpret_cast<const unsigned char*>("\x00\x11\x22\x33\x44\x55\x66\x77"), 8);
    unsigned char pkt[256];
    const std::size_t n = build_retry(pkt, sizeof pkt, a, client_scid, ours, token);
    CHECK(n == 1 + 4 + 1 + 4 + 1 + 8 + token.size() + 16);
    CHECK((pkt[0] & 0xf0) == 0xf0);
    CHECK(pkt[4] == 1 && pkt[5] == 4 && std::memcmp(pkt + 6, client_scid.bytes, 4) == 0 && pkt[10] == 8);
    CHECK(std::memcmp(pkt + 11, ours.bytes, 8) == 0);
    CHECK(std::memcmp(pkt + 19, token.data(), token.size()) == 0);
    unsigned char tag[16];
    CHECK(retry_tag(a, pkt, n - 16, tag) && std::memcmp(tag, pkt + n - 16, 16) == 0);
    CHECK(build_retry(pkt, 20, a, client_scid, ours, token) == 0);  // no room
    CHECK(build_retry(pkt, sizeof pkt, a, client_scid, ours, "") == 0);  // a token is required
    // The stateless reset: a short header's fixed bits, the token last.
    unsigned char reset[43];
    build_stateless_reset(reset, sizeof reset, a);
    CHECK((reset[0] & 0xc0) == 0x40);
    CHECK(std::memcmp(reset + 43 - 16, t1, 16) == 0);
    // The INVALID_TOKEN close opens under the Initial keys of the client's destination id.
    PacketHeader h;
    h.dcid = ours;
    h.scid = client_scid;
    unsigned char close[256];
    const std::size_t cn = build_invalid_token_close(close, sizeof close, h);
    CHECK(cn > 0);
    CHECK((close[0] & 0xf0) == 0xc0);  // an Initial, protected
    unsigned char cs[32], ss[32];
    Keys rx;
    CHECK(initial_secrets(ours, cs, ss) && rx.install(Suite::aes128gcm, ss, 32, false));
    PacketHeader ph;
    CHECK(parse_header(close, cn, 8, ph) && ph.long_form && ph.type == LongType::initial);
    CHECK(ph.dcid == client_scid && ph.scid == ours);
    unsigned char mask[5];
    CHECK(rx.mask(close + ph.pn_offset + 4, mask));
    protect_header(close, ph.pn_offset, 1, true, mask);
    CHECK((close[0] & 0x03) == 0 && close[ph.pn_offset] == 0);  // packet number 0, one byte
    std::size_t plain = 0;
    CHECK(rx.open(0, close, ph.pn_offset + 1, close + ph.pn_offset + 1, cn - ph.pn_offset - 1, plain));
    Frame f;
    const unsigned char* fp = close + ph.pn_offset + 1;
    CHECK(read_frame(fp, fp + plain, f) && f.type == frame::connection_close && f.value == err::invalid_token);
    CHECK(f.reason == "invalid token");
}

static void test_quic() {
    using namespace quic;
    // Variable-length integers (RFC 9000 16): the RFC's examples and the boundaries.
    for (std::uint64_t v : {std::uint64_t{0}, std::uint64_t{63}, std::uint64_t{64}, std::uint64_t{16383}, std::uint64_t{16384},
                            std::uint64_t{1073741823}, std::uint64_t{1073741824}, kVarintMax}) {
        std::string out;
        append_varint(out, v);
        CHECK(out.size() == varint_size(v));
        const auto* p = reinterpret_cast<const unsigned char*>(out.data());
        std::uint64_t back = 0;
        CHECK(read_varint(p, p + out.size(), back) && back == v && p == reinterpret_cast<const unsigned char*>(out.data()) + out.size());
    }
    {
        const std::string ex = bytes_of("c2197c5eff14e88c");
        const auto* p = reinterpret_cast<const unsigned char*>(ex.data());
        std::uint64_t v = 0;
        CHECK(read_varint(p, p + ex.size(), v) && v == 151288809941952652ull);
        const std::string two = bytes_of("9d7f3e7d");
        p = reinterpret_cast<const unsigned char*>(two.data());
        CHECK(read_varint(p, p + two.size(), v) && v == 494878333);
        const std::string one = bytes_of("25");
        p = reinterpret_cast<const unsigned char*>(one.data());
        CHECK(read_varint(p, p + 1, v) && v == 37);
    }
    // Ranges.
    {
        RangeSet r;
        r.add(10, 20);
        r.add(30, 40);
        r.add(20, 30);
        CHECK(r.count() == 1 && r.contains(10, 40) && !r.contains(9, 11) && r.contiguous_from(10) == 40 && r.contiguous_from(5) == 5);
        r.add_point(50);
        CHECK(r.count() == 2 && r.max() == 50 && r.min() == 10);
        std::uint64_t gb = 0, ge = 0;
        CHECK(r.first_gap(10, 100, gb, ge) && gb == 40 && ge == 50);
        r.remove(15, 17);
        CHECK(r.count() == 3 && r.contains(10, 15) && r.contains(17, 40) && !r.contains_point(15));
        r.remove_below(18);
        CHECK(r.count() == 2 && r.min() == 18);
        r.keep_highest(1);
        CHECK(r.count() == 1 && r.min() == 50);
    }
    // Packet numbers (RFC 9000 A.2, A.3).
    CHECK(decode_pn(0xa82f30ea, true, 0x9b32, 16) == 0xa82f9b32);
    CHECK(pn_length(0xac5c02, 0xabe8b3, true) == 2);
    CHECK(decode_pn(0, false, 2, 32) == 2);
    // The deadline heap.
    {
        TimerHeap h;
        Timed a, b, c;
        const auto t0 = Clock::now();
        a.deadline = t0 + std::chrono::milliseconds(30);
        b.deadline = t0 + std::chrono::milliseconds(10);
        c.deadline = t0 + std::chrono::milliseconds(20);
        h.update(&a);
        h.update(&b);
        h.update(&c);
        CHECK(h.top() == &b);
        b.deadline = t0 + std::chrono::milliseconds(40);
        h.update(&b);
        CHECK(h.top() == &c);
        h.remove(&c);
        CHECK(h.top() == &a && h.earliest() == a.deadline);
        h.remove(&a);
        h.remove(&b);
        CHECK(h.empty());
    }
    // Frames: an ACK with gaps, STREAM headers, CONNECTION_CLOSE, round trips.
    {
        unsigned char buf[256];
        RangeSet got;
        got.add(1, 4);
        got.add(7, 10);
        got.add_point(12);
        const std::size_t n = put_ack(buf, sizeof buf, got, 5);
        CHECK(n > 0);
        const unsigned char* p = buf;
        Frame f;
        CHECK(read_frame(p, buf + n, f) && f.type == frame::ack && f.largest_ack == 12 && f.ack_delay == 5 && f.range_count == 3);
        CHECK(f.ranges[0].first == 12 && f.ranges[0].second == 13 && f.ranges[1].first == 7 && f.ranges[1].second == 10 &&
              f.ranges[2].first == 1 && f.ranges[2].second == 4);
        const std::size_t h = put_stream_header(buf, sizeof buf, 8, 1000, 5, true, true);
        std::memcpy(buf + h, "hello", 5);
        p = buf;
        CHECK(read_frame(p, buf + h + 5, f) && f.type == 0x0f && f.stream_id == 8 && f.offset == 1000 && f.length == 5 && f.fin &&
              std::string_view(reinterpret_cast<const char*>(f.data), 5) == "hello");
        const std::size_t c = put_connection_close(buf, sizeof buf, false, err::protocol_violation, frame::stream, "bad");
        p = buf;
        CHECK(read_frame(p, buf + c, f) && f.type == frame::connection_close && f.value == err::protocol_violation && f.value2 == frame::stream && f.reason == "bad");
        CHECK(frame_allowed(frame::crypto, Space::initial) && !frame_allowed(frame::stream, Space::handshake) && frame_allowed(frame::stream, Space::application));
    }
    // Transport parameters: a client's set round trips; the server-only ones are refused.
    {
        TransportParams t;
        t.max_idle_timeout = 30000;
        t.initial_max_data = 1 << 20;
        t.initial_max_stream_data_bidi_local = 65536;
        t.initial_max_streams_bidi = 100;
        t.initial_max_streams_uni = 3;
        t.active_connection_id_limit = 4;
        t.initial_scid.assign(reinterpret_cast<const unsigned char*>("\x01\x02\x03\x04"), 4);
        t.has_initial_scid = true;
        const std::string enc = encode_transport_params(t);
        TransportParams back;
        CHECK(decode_transport_params(reinterpret_cast<const unsigned char*>(enc.data()), enc.size(), back));
        CHECK(back.max_idle_timeout == 30000 && back.initial_max_data == (1u << 20) && back.initial_max_streams_bidi == 100 &&
              back.active_connection_id_limit == 4 && back.has_initial_scid && back.initial_scid == t.initial_scid && !back.disable_active_migration);
        std::string bad;
        append_param(bad, tp::ack_delay_exponent, 21);
        CHECK(!decode_transport_params(reinterpret_cast<const unsigned char*>(bad.data()), bad.size(), back));
        std::string dup;
        append_param(dup, tp::max_idle_timeout, 1);
        append_param(dup, tp::max_idle_timeout, 2);
        CHECK(!decode_transport_params(reinterpret_cast<const unsigned char*>(dup.data()), dup.size(), back));
        std::string server_only;
        append_param_bytes(server_only, tp::stateless_reset_token, reinterpret_cast<const unsigned char*>("0123456789abcdef"), 16);
        CHECK(!decode_transport_params(reinterpret_cast<const unsigned char*>(server_only.data()), server_only.size(), back));
    }
    // RFC 9001 appendix A: the Initial secrets and keys (A.1).
    Cid dcid;
    dcid.assign(reinterpret_cast<const unsigned char*>(bytes_of("8394c8f03e515708").data()), 8);
    unsigned char client[32], server[32];
    CHECK(initial_secrets(dcid, client, server));
    CHECK(tohex(std::string(reinterpret_cast<const char*>(client), 32)) == "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    CHECK(tohex(std::string(reinterpret_cast<const char*>(server), 32)) == "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
    // A.2: the client's protected Initial opens with the client keys: the header
    // protection mask, the packet number 2, the CRYPTO frame.
    {
        Keys k;
        CHECK(k.install(Suite::aes128gcm, client, 32, false));
        std::string pkt = bytes_of(quic_vectors::kClientInitialProtected);
        auto* data = reinterpret_cast<unsigned char*>(pkt.data());
        PacketHeader h;
        CHECK(parse_header(data, pkt.size(), 8, h) && h.long_form && h.type == LongType::initial && h.version == 1 && h.dcid == dcid && h.scid.len == 0 &&
              h.token_len == 0 && h.length == 1182 && h.pn_offset == 18);
        unsigned char mask[5];
        CHECK(k.mask(data + h.pn_offset + 4, mask) && tohex(std::string(reinterpret_cast<const char*>(mask), 5)) == "437b9aec36");
        data[0] ^= static_cast<unsigned char>(mask[0] & 0x0f);
        const unsigned pn_len = (data[0] & 3) + 1;
        std::uint64_t truncated = 0;
        for (unsigned i = 0; i < pn_len; ++i) {
            data[h.pn_offset + i] ^= mask[1 + i];
            truncated = (truncated << 8) | data[h.pn_offset + i];
        }
        CHECK(pn_len == 4 && truncated == 2);
        std::size_t plain = 0;
        CHECK(k.open(2, data, h.pn_offset + pn_len, data + h.pn_offset + pn_len, h.length - pn_len, plain) && plain == 1162);
        const std::string crypto = bytes_of(quic_vectors::kClientInitialCrypto);
        CHECK(std::memcmp(data + h.pn_offset + pn_len, crypto.data(), crypto.size()) == 0);
        const unsigned char* fp = data + h.pn_offset + pn_len;
        Frame f;
        CHECK(read_frame(fp, fp + plain, f) && f.type == frame::crypto && f.offset == 0 && f.length == 241);
        // A wrong tag is refused and counted.
        data[pkt.size() - 1] ^= 1;
        CHECK(!k.open(2, data, h.pn_offset + pn_len, data + h.pn_offset + pn_len, h.length - pn_len, plain) && k.failures == 1);
    }
    // A.3: the server's Initial, sealed and protected with the server keys, is the RFC's packet byte for byte.
    {
        Keys k;
        CHECK(k.install(Suite::aes128gcm, server, 32, true));
        std::string pkt = bytes_of("c1000000010008f067a5502a4262b50040750001");
        const std::size_t pn_offset = pkt.size() - 2;
        const std::string payload = bytes_of(quic_vectors::kServerInitialPayload);
        pkt.append(payload);
        pkt.resize(pkt.size() + kAeadTagLen);
        auto* data = reinterpret_cast<unsigned char*>(pkt.data());
        CHECK(k.seal(1, data, pn_offset + 2, payload.size()));
        unsigned char mask[5];
        CHECK(k.mask(data + pn_offset + 4, mask));
        protect_header(data, pn_offset, 2, true, mask);
        CHECK(tohex(pkt) == std::string(quic_vectors::kServerInitialProtected));
    }
    // A.5: a ChaCha20-Poly1305 short-header packet, sealed and protected (key, iv, hp from the secret).
    {
        const std::string secret = bytes_of("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        Keys k;
        CHECK(k.install(Suite::chacha20, reinterpret_cast<const unsigned char*>(secret.data()), secret.size(), true));
        std::string pkt = bytes_of("4200bff401");
        pkt.resize(pkt.size() + kAeadTagLen);
        auto* data = reinterpret_cast<unsigned char*>(pkt.data());
        CHECK(k.seal(654360564, data, 4, 1));
        CHECK(tohex(pkt.substr(4)) == "655e5cd55c41f69080575d7999c25a5bfb");
        unsigned char mask[5];
        CHECK(k.mask(data + 1 + 4, mask) && tohex(std::string(reinterpret_cast<const char*>(mask), 5)) == "aefefe7d03");
        protect_header(data, 1, 3, false, mask);
        CHECK(tohex(pkt) == "4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
        unsigned char next[32];
        CHECK(next_secret(Suite::chacha20, reinterpret_cast<const unsigned char*>(secret.data()), secret.size(), next) &&
              tohex(std::string(reinterpret_cast<const char*>(next), 32)) == "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9");
    }
    // Loss recovery: three packets sent, the third acknowledged: the first is lost by the
    // packet threshold, the second waits for the time threshold (RFC 9002 6.1).
    {
        Recovery rec;
        const auto t0 = Clock::now();
        PnSpace& sp = rec.space(Space::application);
        for (std::uint64_t pn = 0; pn < 4; ++pn) {
            SentPacket& p = sp.record(pn);
            p.bytes = 1200;
            p.ack_eliciting = p.in_flight = true;
            p.items.push_back({ItemKind::stream, false, 4, pn * 1000, 1000});
            ++sp.next_pn;
            rec.on_packet_sent(Space::application, p, t0 + std::chrono::milliseconds(pn));
        }
        CHECK(rec.bytes_in_flight == 4800);
        Frame ack;
        ack.type = frame::ack;
        ack.largest_ack = 3;
        ack.ack_delay = 0;
        ack.range_count = 1;
        ack.ranges[0] = {3, 4};
        CHECK(rec.on_ack_received(Space::application, ack, t0 + std::chrono::milliseconds(50)));
        CHECK(rec.acked.size() == 1 && rec.acked[0].offset == 3000);
        CHECK(rec.lost.size() == 1 && rec.lost[0].offset == 0);  // pn 0: largest_acked (3) >= 0 + 3
        CHECK(rec.bytes_in_flight == 2400 && sp.loss_time != TimePoint{});
        Frame bad;
        bad.type = frame::ack;
        bad.largest_ack = 10;
        bad.range_count = 1;
        bad.ranges[0] = {10, 11};
        CHECK(!rec.on_ack_received(Space::application, bad, t0));  // never sent
        CHECK(rec.has_rtt && rec.smoothed_rtt == std::chrono::milliseconds(47));
    }
}
#endif

static void test_hpack() {
    using namespace hpack;
    // Integers (RFC 7541 C.1).
    std::string out;
    append_integer(out, 10, 5, 0);
    CHECK(tohex(out) == "0a");
    out.clear();
    append_integer(out, 1337, 5, 0);
    CHECK(tohex(out) == "1f9a0a");
    out.clear();
    append_integer(out, 42, 8, 0);
    CHECK(tohex(out) == "2a");
    std::size_t pos = 0;
    std::uint32_t v = 0;
    CHECK(read_integer(unhex("1f9a0a"), pos, 5, v) && v == 1337 && pos == 3);
    pos = 0;
    CHECK(!read_integer(unhex("1f9a"), pos, 5, v));  // truncated
    pos = 0;
    CHECK(!read_integer(unhex("ffffffffffff7f"), pos, 7, v));  // more than 32 bits
    // Huffman (the literals of C.4 and C.6).
    out.clear();
    huffman_encode(out, "www.example.com");
    CHECK(tohex(out) == "f1e3c2e5f23a6ba0ab90f4ff" && huffman_size("www.example.com") == 12);
    out.clear();
    huffman_encode(out, "no-cache");
    CHECK(tohex(out) == "a8eb10649cbf");
    out.clear();
    huffman_encode(out, "custom-key");
    CHECK(tohex(out) == "25a849e95ba97d7f");
    std::string dec;
    CHECK(huffman_decode(unhex("f1e3c2e5f23a6ba0ab90f4ff"), dec, 100) == HuffStatus::ok && dec == "www.example.com");
    dec.clear();
    CHECK(huffman_decode(unhex("a8eb10649cbf"), dec, 100) == HuffStatus::ok && dec == "no-cache");
    dec.clear();
    CHECK(huffman_decode("", dec, 100) == HuffStatus::ok && dec.empty());
    dec.clear();
    CHECK(huffman_decode(unhex("1f"), dec, 100) == HuffStatus::ok && dec == "a");  // 00011 + 111 padding
    dec.clear();
    CHECK(huffman_decode(unhex("ff"), dec, 100) == HuffStatus::malformed);        // 8 bits of padding
    dec.clear();
    CHECK(huffman_decode(unhex("ffffffff"), dec, 100) == HuffStatus::malformed);  // EOS
    dec.clear();
    CHECK(huffman_decode(unhex("18"), dec, 100) == HuffStatus::malformed);        // 00011 then 000: not padding
    dec.clear();
    CHECK(huffman_decode(unhex("a8eb10649cbf"), dec, 3) == HuffStatus::too_large);
    // Every byte round-trips, alone and in a run.
    for (int c = 0; c < 256; ++c) {
        const std::string one(1, static_cast<char>(c));
        out.clear();
        huffman_encode(out, one);
        dec.clear();
        CHECK(huffman_decode(out, dec, 8) == HuffStatus::ok && dec == one);
    }
    std::string all;
    for (int c = 0; c < 256; ++c) all.push_back(static_cast<char>(c));
    out.clear();
    huffman_encode(out, all);
    dec.clear();
    CHECK(huffman_decode(out, dec, 1000) == HuffStatus::ok && dec == all && out.size() == huffman_size(all));
    // Static table lookups and the encoder.
    CHECK(static_name_index(":method") == 2 && static_name_index("content-type") == 31 && static_name_index("date") == 33 &&
          static_name_index("etag") == 34 && static_name_index("server") == 54 && static_name_index("nope") == 0);
    CHECK(static_index(":method", "GET") == 2 && static_index(":method", "POST") == 3 && static_index(":status", "200") == 8 &&
          static_index(":status", "304") == 11 && static_index("accept-encoding", "gzip, deflate") == 16 &&
          static_index("content-type", "text/html") == 0);
    out.clear();
    append_field(out, ":method", "GET");
    CHECK(tohex(out) == "82");
    out.clear();
    append_status(out, 200);
    CHECK(tohex(out) == "88");
    out.clear();
    append_status(out, 421);
    CHECK(tohex(out) == "08" "03" "343231");
    out.clear();
    append_field(out, "content-type", "text/html");
    CHECK(tohex(out).substr(0, 4) == "0f10");  // literal without indexing, name index 31 (15 + 16)
    out.clear();
    append_field(out, "x-custom", "v");
    CHECK(tohex(out).substr(0, 2) == "00" && out.size() == 1 + 1 + 6 + 1 + 1);  // literal name (Huffman: 45 bits), raw value
    // The RFC's examples: groups share one decoder (the dynamic table evolves).
    std::map<int, std::unique_ptr<Decoder>> decoders;
    for (const auto& vec : hpack_vectors::all()) {
        auto& d = decoders[vec.group];
        if (!d || vec.group == 2) d = std::make_unique<Decoder>(vec.max_table);  // C.2's examples are independent
        std::string arena;
        std::vector<std::pair<std::string, std::string>> got;
        const Decoder::Result r = d->decode(unhex(vec.hex), arena, 4096, [&](std::string_view n, std::string_view v2) {
            got.emplace_back(n, v2);
            return true;
        });
        bool same = r == Decoder::Result::ok && got.size() == vec.fields.size();
        for (std::size_t i = 0; same && i < got.size(); ++i)
            same = got[i].first == vec.fields[i].name && got[i].second == vec.fields[i].value;
        if (!same || d->table_size() != vec.table_size_after)
            std::printf("hpack vector %s: result %d, %zu fields, table %zu (expected %u)\n", std::string(vec.name).c_str(),
                        static_cast<int>(r), got.size(), d->table_size(), vec.table_size_after);
        CHECK(same && d->table_size() == vec.table_size_after);
    }
    // Our encoder's output decodes back, with names and values as given.
    {
        out.clear();
        append_status(out, 200);
        append_field(out, "server", "agensio");
        append_field(out, "content-type", "text/html; charset=utf-8");
        append_field(out, "content-length", "1234");
        append_field(out, "x-custom-header", "a value with spaces and UTF-8 \xce\xb1");
        Decoder d;
        std::string arena;
        std::vector<std::pair<std::string, std::string>> got;
        CHECK(d.decode(out, arena, 4096, [&](std::string_view n, std::string_view v2) {
                  got.emplace_back(n, v2);
                  return true;
              }) == Decoder::Result::ok);
        CHECK(got.size() == 5 && got[0].first == ":status" && got[0].second == "200" && got[1].second == "agensio" &&
              got[2].first == "content-type" && got[3].second == "1234" && got[4].second == "a value with spaces and UTF-8 \xce\xb1");
        CHECK(d.table_size() == 0);  // nothing we encode ever enters a dynamic table
    }
    // Errors: index 0, an index past the tables, a size update above the ceiling or after
    // a field, a truncated literal, bad Huffman data.
    auto result = [](std::string_view raw, std::size_t max_list = 4096, std::size_t ceiling = 4096) {
        Decoder d(ceiling);
        std::string arena;
        return d.decode(raw, arena, max_list, [](std::string_view, std::string_view) { return true; });
    };
    CHECK(result(unhex("80")) == Decoder::Result::malformed);          // indexed 0
    CHECK(result(unhex("bf80")) == Decoder::Result::malformed);        // indexed 191: nothing there
    CHECK(result(unhex("3fe11f")) == Decoder::Result::ok);             // size update to exactly the ceiling (4096)
    CHECK(result(unhex("3fe21f")) == Decoder::Result::malformed);      // 4097: above the ceiling
    CHECK(result(unhex("8220")) == Decoder::Result::malformed);        // size update after a field
    CHECK(result(unhex("20")) == Decoder::Result::ok);                 // size update to 0, nothing else
    CHECK(result(unhex("0f10ff")) == Decoder::Result::malformed);      // literal value: length 127 + continuation missing
    CHECK(result(unhex("0f1005ffffffffff")) == Decoder::Result::ok);         // a raw value of five 0xff bytes is fine
    CHECK(result(unhex("0f1085ffffffffff")) == Decoder::Result::malformed);  // the same as Huffman data: EOS
    CHECK(result(unhex("0f10")) == Decoder::Result::malformed);        // value missing
    CHECK(result(unhex("00")) == Decoder::Result::malformed);          // literal name missing
    // The list size limit stops the decode at the field that crosses it, whatever the
    // representation: three 46-byte fields (name 10 + value 4 + 32) against a 100-byte budget.
    {
        std::string block;
        for (int i = 0; i < 3; ++i) append_field(block, "abcdefghij", "wxyz");
        CHECK(result(block, 100) == Decoder::Result::too_large && result(block, 138) == Decoder::Result::ok);
        // The compression bomb shape: a table entry referenced many times costs its full size each time.
        std::string bomb = unhex("40") + std::string(1, 8) + "12345678" + std::string(1, 100) + std::string(100, 'x');
        for (int i = 0; i < 100; ++i) bomb += unhex("be");  // index 62 = the entry just added
        CHECK(result(bomb, 2000) == Decoder::Result::too_large);
        std::string arena;
        Decoder d;
        std::size_t n = 0;
        CHECK(d.decode(bomb, arena, 2000, [&](std::string_view, std::string_view) { ++n; return true; }) == Decoder::Result::too_large);
        CHECK(n <= 2000 / 140 + 1 && arena.size() <= 2000 + 64);  // stopped where the budget ended
        // A sink that refuses.
        CHECK(d.decode(unhex("8286"), arena, 4096, [](std::string_view, std::string_view) { return false; }) == Decoder::Result::too_many);
    }
    // Eviction: a 256-byte table takes the entries the RFC's C.5 sequence says (checked above); an
    // entry larger than the table empties it.
    {
        Decoder d(64);
        std::string arena;
        std::string block = unhex("40") + std::string(1, 1) + "a" + std::string(1, 1) + "b";  // a: b (34 bytes)
        CHECK(d.decode(block, arena, 4096, [](std::string_view, std::string_view) { return true; }) == Decoder::Result::ok &&
              d.table_entries() == 1);
        block = unhex("40") + std::string(1, 1) + "c" + std::string(1, 60) + std::string(60, 'v');  // 93 bytes > 64
        CHECK(d.decode(block, arena, 4096, [](std::string_view, std::string_view) { return true; }) == Decoder::Result::ok &&
              d.table_entries() == 0 && d.table_size() == 0);
    }
}

static void test_refused_suffix() {
    const std::vector<std::string> deny = {".php", ".phtml", ".inc", "~"};
    for (const char* p : {"/files/x.php", "/files/x.PHP", "/files/x.PhP", "/files/x.php.", "/files/x.PHP..", "/files/x.phtml", "/files/x.INC", "/files/x.php~", "/files/x.jpg.php", "/x.php"})
        CHECK(refused_suffix(p, deny));
    for (const char* p : {"/files/x.php.jpg", "/files/x.jpg", "/files/php", "/files/x.ph", "/files/xphp", "/", ""})
        CHECK(!refused_suffix(p, deny));
    CHECK(!refused_suffix("/files/x.php", {}));
}

// The protected-names rule: every backup spelling of a name a preset never serves, on
// the real WordPress expansion, hand-written locations included.
static void test_backup_of_protected() {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "agensio-protect";
    fs::remove_all(dir);
    fs::create_directories(dir / "wp" / "wp-content" / "uploads");
    auto write = [&](const char* name, const std::string& text) {
        std::ofstream(dir / name) << text;
    };
    write("wp.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"wp\"\napp = \"wordpress\"\nphp = { socket = \"unix:/run/php/fpm.sock\" }\n"
                     "[[site.location]]\npath = \"/wp-content/uploads/\"\nfinal = true\ndeny_suffixes = [\".php\"]\n");
    Config cfg = load_config(dir / "wp.toml");
    const SiteConfig& site = cfg.sites[0];
    const LocationConfig& root = Router::location(site, "/wp-config.php.bak");
    CHECK(root.path == "/" && root.protects.size() == 7 && root.protects[0].dir_stem == "/wp-config" && root.protects[0].ext == ".php" && root.protects[0].dir_len == 1);
    const LocationConfig& uploads = Router::location(site, "/wp-content/uploads/x.txt");
    CHECK(uploads.origin.empty() && uploads.protects.size() == 7);  // the hand-written shield protects the names too
    CHECK(std::find(root.deny_suffixes.begin(), root.deny_suffixes.end(), ".inc") != root.deny_suffixes.end() &&
          std::find(root.deny_suffixes.begin(), root.deny_suffixes.end(), "~") != root.deny_suffixes.end());
    const auto& names = root.protects;
    for (const char* p : {"/wp-config.php~", "/wp-config.php.bak", "/wp-config.php.save", "/wp-config.php.orig", "/wp-config.php.txt",
                          "/wp-config.php.old", "/wp-config.php.dist", "/wp-config.php.1", "/wp-config.php.2024-01-01", "/wp-config.phps",
                          "/wp-config.bak", "/wp-config.txt", "/wp-config.old", "/WP-CONFIG.PHP", "/WP-CONFIG.PHP.BAK", "/Wp-Config.Bak",
                          "/.wp-config.php.swp", "/.wp-config.php.swo", "/#wp-config.php#", "/.wp-config.php", "/.wp-config",
                          "/wp-config.php-old", "/wp-config.php_bak", "/wp-config.php#", "/wp-config.php.bak~",
                          "/wp-content/db.php.bak", "/wp-content/.db.php.swp", "/wp-content/db.php~", "/readme.html.bak", "/license.txt~", "/license.bak"})
        CHECK(backup_of_protected(p, names));
    for (const char* p : {"/wp-config", "/readme", "/license", "/license-agreement", "/readme_first", "/wp-configx.php", "/wp-config.php/x",
                          "/sub/wp-config.php.bak", "/wp-content/uploads/db.php.bak", "/wp-content/db-error.php", "/wp-content/dbx.php",
                          "/", "/index.php", "/wp-login.php", "/wp-content/uploads/2026/09/photo.jpg", "/x/wp-config", "/wp-conf.php"})
        CHECK(!backup_of_protected(p, names));
    CHECK(!backup_of_protected("/wp-config.php.bak", {}));
    // A name without an extension and one deeper down.
    const std::vector<ProtectedName> other = {{"/sub/dir/secret", "", 9}, {"/license", "", 1}};
    CHECK(backup_of_protected("/sub/dir/secret~", other) && backup_of_protected("/sub/dir/SECRET.bak", other) && backup_of_protected("/license~", other) &&
          backup_of_protected("/license.old", other) && !backup_of_protected("/sub/dir/secrets", other) && !backup_of_protected("/sub/secret~", other) &&
          !backup_of_protected("/license", other));
    // Every preset's never-served names come out as valid protected names; a static preset has none.
    write("d.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"wp\"\napp = \"drupal\"\nphp = { socket = \"unix:/run/php/fpm.sock\" }\n[[site]]\nlisten = [\"127.0.0.1:18081\"]\nroot = \"wp\"\n");
    Config dcfg = load_config(dir / "d.toml");
    const LocationConfig& droot = Router::location(dcfg.sites[0], "/x.txt");
    CHECK(droot.protects.size() == 9 && backup_of_protected("/sites/default/settings.php.bak", droot.protects) && backup_of_protected("/sites/default/settings.bak", droot.protects) &&
          backup_of_protected("/composer.json~", droot.protects) && backup_of_protected("/web.config.old", droot.protects) && !backup_of_protected("/sites/default/files/settings.php.bak", droot.protects));
    CHECK(Router::location(dcfg.sites[1], "/x.txt").protects.empty());
    // Every PHP preset's root refuses PHP in the spellings the suffix location does not take
    // (x.PHP, x.phtml would be served as source) and the shared backup list; the plain php
    // preset too.
    write("p.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"wp\"\napp = \"php\"\nphp = { socket = \"unix:/run/php/fpm.sock\" }\n");
    Config pcfg = load_config(dir / "p.toml");
    for (const SiteConfig* sc : std::initializer_list<const SiteConfig*>{&site, &dcfg.sites[0], &pcfg.sites[0]}) {
        const LocationConfig& r = Router::location(*sc, "/x.txt");
        CHECK(r.path == "/" && r.origin == "preset:" + sc->app && refused_suffix("/x.PHP", r.deny_suffixes) && refused_suffix("/x.phtml", r.deny_suffixes) &&
              refused_suffix("/x.php.bak", r.deny_suffixes) && refused_suffix("/x.inc", r.deny_suffixes) && refused_suffix("/x.php~", r.deny_suffixes) && !refused_suffix("/x.txt", r.deny_suffixes));
        CHECK(Router::location(*sc, "/x.php").kind == HandlerKind::fastcgi);  // the exact spelling still runs
    }
    fs::remove_all(dir);
}

static void test_parser_prefixes() {
    const std::string text = "GET /wp-admin/js/plugin-install.min.js?ver=7.1.1 HTTP/1.1\r\nHost: ag2.example\r\nReferer: https://ag2.example/wp-admin/plugins.php\r\nUser-Agent: Firefox\r\n\r\nGET /next HTTP/1.1\r\n";
    const std::size_t head = text.find("\r\n\r\n") + 4;
    Request r;
    for (std::size_t i = 0; i < head; ++i) {
        const auto st = parse_request(std::string_view(text).substr(0, i), r);
        CHECK(st == ParseStatus::incomplete);
    }
    for (std::size_t i = head; i <= text.size(); ++i) {
        const auto st = parse_request(std::string_view(text).substr(0, i), r);
        CHECK(st == ParseStatus::complete && r.length == head && r.method == Method::get && r.method_name == "GET");
        CHECK(r.target == "/wp-admin/js/plugin-install.min.js?ver=7.1.1" && r.host == "ag2.example");
    }
    // A duplicated method token is a valid token: 405 territory, and now logged.
    CHECK(parse_request("GETGET /a HTTP/1.1\r\nHost: h\r\n\r\n", r) == ParseStatus::complete && r.method == Method::other && r.method_name == "GETGET");
    CHECK(parse_request("GET GET /a HTTP/1.1\r\nHost: h\r\n\r\n", r) == ParseStatus::bad_request);
}

static void test_strict_hosts() {
    // The authority of a TLS connection: the names of the certificate it presented
    // (RFC 6125 matching), against a raw Host header value.
    {
        char buf[256];
        CHECK(normalize_host("Example.COM.:8443", buf) == "example.com" && normalize_host("[::1]:8443", buf) == "::1" && normalize_host("a.test", buf) == "a.test");
        CHECK(normalize_host("", buf).empty() && normalize_host(std::string(300, 'a'), buf).empty() && normalize_host(":8080", buf).empty());
        CertNames c;
        c.add("Example.com");
        c.add("*.wild.test");
        c.add("127.0.0.1");
        c.add("*");        // not a name
        c.add("a.*.b");    // not a wildcard anyone matches
        CHECK(c.exact.size() == 2 && c.wildcard.size() == 1 && c.wildcard[0] == ".wild.test");
        CHECK(c.covers("example.com") && c.covers("EXAMPLE.COM:443") && c.covers("example.com.") && c.covers("127.0.0.1:8443"));
        CHECK(c.covers("x.wild.test") && c.covers("X.Wild.Test:8446") && !c.covers("wild.test") && !c.covers("a.b.wild.test") && !c.covers(".wild.test"));
        CHECK(!c.covers("other.com") && !c.covers("") && !c.covers("sub.example.com") && !c.covers("[::1]"));
        CertNames none;
        CHECK(none.empty() && !none.covers("example.com"));
    }
    // A named site answers its names only; adding sites never changes that; "*" or
    // default = true is the only catch-all.
    SiteConfig a; a.server_names = {"a.test"};
    SiteConfig b; b.server_names = {"b.test", "www.b.test"};
    SiteConfig any; any.server_names = {"*"};
    SiteConfig def; def.server_names = {"d.test"}; def.is_default = true;
    Router r;
    r.add_site(a);
    CHECK(r.site("a.test") == &a && r.site("A.TEST:8080") == &a && r.site("z.test") == nullptr && r.site("") == nullptr);
    CHECK(r.default_site() == nullptr);
    r.add_site(b);
    CHECK(r.site("z.test") == nullptr && r.site("www.b.test") == &b && r.site("a.test") == &a);  // the second site changed nothing
    r.add_site(any);
    CHECK(r.site("z.test") == &any && r.site("") == &any && r.site("a.test") == &a && r.default_site() == &any);
    Router r2;
    r2.add_site(a);
    r2.add_site(def);
    CHECK(r2.site("z.test") == &def && r2.site("d.test") == &def && r2.default_site() == &def);
    CHECK(control::is_catch_all(any) && control::is_catch_all(def) && !control::is_catch_all(a));
    Config cfg;
    a.listen = {"0.0.0.0:80"}; def.listen = {"0.0.0.0:443"};
    cfg.sites = {a, def};
    CHECK(!control::listener_has_catch_all(cfg, "0.0.0.0:80") && control::listener_has_catch_all(cfg, "0.0.0.0:443"));
}

int main() {
    test_path();
    test_parser();
    test_security_parser();
    test_security_path();
    test_security_regressions();
    test_date();
    test_mime();
    test_size();
    test_cache();
    test_hpack_encoder();
    test_site_protocols();
#ifdef AGENSIO_HTTPARENA
    test_httparena();
#endif
    test_encoding();
    test_precompressed();
    test_chunked();
    test_core_types();
    test_route_and_etag();
    test_config_locations();
    test_cidr();
    test_presets();
    test_fcgi_http_params();
    test_log_format();
    test_fcgi_codec();
    test_pools();
    test_tasks();
    test_appenv();
    test_hosting_rules();
    test_proxy();
    test_range();
    test_json();
    test_control();
    test_control_commands();
    test_control_sites();
    test_server_account_and_rules();
    test_strict_hosts();
    test_parser_prefixes();
    test_refused_suffix();
    test_backup_of_protected();
    test_h2_frame_and_settings();
    test_hpack();
    test_request_assembly_cookies();
    test_qpack();
    test_qpack_dynamic();
    test_qpack_encoder();
#ifdef AGENSIO_HAS_QUIC
    test_quic();
    test_quic_stateless();
#endif
    test_config_reference();
    test_refusal_finding();
    test_protection();
    test_install();
#ifdef AGENSIO_HAS_TLS
    test_acme();
#endif
    if (failures) {
        std::printf("%d failure(s)\n", failures);
        return 1;
    }
    std::printf("all tests passed\n");
    return 0;
}
