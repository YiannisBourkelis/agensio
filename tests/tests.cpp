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
#include "control/reference.hpp"
#include "control/settings.hpp"
#include "control/sites.hpp"
#include "services/provision.hpp"
#include "services/archive.hpp"
#include "services/fetch.hpp"
#include "services/install.hpp"
#include "services/json.hpp"
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
    // The hand-written /build/ location wins over the preset's.
    CHECK(build.origin.empty() && build.add_headers.size() == 1 && build.add_headers[0].second == "no-store");
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
    CHECK(up.deny_suffixes.size() == 22 && up.add_headers.size() == 1 && up.origin == "preset:wordpress");
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
    CHECK(app_presets().size() == 7 && app_presets().front() == "static" && app_presets()[5] == "grav" && app_presets().back() == "proxy");
    const json::Value catalog = preset_catalog();
    CHECK(catalog["presets"].items().size() == 7 && catalog["presets"].items()[0].get("app") == "static" && catalog["presets"].items()[5].get("app") == "grav" && catalog["presets"].items()[6].get("app") == "proxy");
    CHECK(catalog["presets"].items()[5]["never_served_directories"].items().size() == 9 && catalog["presets"].items()[5]["never_served_directories"].items()[0].str() == "/logs/" &&
          catalog["presets"].items()[3]["never_served_directories"].items().empty() && catalog["presets"].items()[5].get("source").starts_with("https://getgrav.org/"));
    const json::Value& laravel_row = catalog["presets"].items()[2];
    CHECK(laravel_row.get("app") == "laravel" && !laravel_row.get("summary").empty() && laravel_row.get("php").starts_with("only /index.php"));
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
            CHECK(refused(R"({"memory_limit":"64M"})", false, "needs a site with its own user"));
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
        CHECK(next_steps(ok, loaded).size() == 1);  // the port-80 note for auto certificates
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
    test_qpack();
    test_qpack_dynamic();
    test_qpack_encoder();
#ifdef AGENSIO_HAS_QUIC
    test_quic();
    test_quic_stateless();
#endif
    test_config_reference();
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
