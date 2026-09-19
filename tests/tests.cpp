// Minimal self-contained unit tests (no framework dependency).
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <map>
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
#include "control/sites.hpp"
#include "services/json.hpp"
#include "handlers/proxy.hpp"
#include "core/headers.hpp"
#include "core/result.hpp"
#include "core/router.hpp"
#include "handlers/fastcgi.hpp"
#include "handlers/static.hpp"
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

static void test_cache() {
    FileCache cache(100, 250, 0.5, 2);
    auto make = [](std::size_t n, std::int64_t access) {
        auto e = std::make_shared<CacheEntry>();
        e->data.assign(n, 'x');
        e->last_access = access;
        return e;
    };
    int site = 0;
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
    const LocationConfig& droot = Router::location(d, "/dump.sqlite");
    CHECK(droot.path == "/" && std::find(droot.deny_suffixes.begin(), droot.deny_suffixes.end(), ".sqlite") != droot.deny_suffixes.end() &&
          std::find(droot.deny_suffixes.begin(), droot.deny_suffixes.end(), ".inc") != droot.deny_suffixes.end());
    // WordPress: wp-config.php is never an entry point.
    fs::create_directories(dir / "wp2");
    write("wp2.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"wp2\"\napp = \"wordpress\"\nphp = { socket = \"unix:/run/php/fpm.sock\" }\n");
    Config wcfg2 = load_config(dir / "wp2.toml");
    CHECK(Router::location(wcfg2.sites[0], "/wp-config.php").try_files[0].status == 404 && Router::location(wcfg2.sites[0], "/wp-login.php").kind == HandlerKind::fastcgi);
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
    CHECK(up.deny_suffixes.size() == 7 && up.add_headers.size() == 1 && up.origin == "preset:wordpress");
    CHECK(Router::location(w, "/wp-includes/js/x.js").final);
    CHECK(Router::location(w, "/wp-admin/").path == "/");
    CHECK(rejects("badfinal.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n"
                                   "[[site.location]]\npath = \".php\"\nmatch = \"suffix\"\nfinal = true\n"));
    CHECK(rejects("baddeny.toml", "[[site]]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"www\"\n"
                                  "[[site.location]]\npath = \"/u/\"\ndeny_suffixes = [\"php\"]\n"));

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
                             "listen.mode = 0660", "pm = static", "pm.max_children = 6", "clear_env = yes",
                             "php_admin_value[memory_limit] = 512M", "php_admin_value[date.timezone] = UTC",
                             "php_admin_value[upload_max_filesize] = 1M"})
        CHECK(ini.find(std::string(line) + "\n") != std::string::npos);
    CHECK(ini.find("php_admin_value[open_basedir] = " + a.pool.open_basedir[0] + ":") != std::string::npos);
    CHECK(render_pool(cfg, b, "www").find("pm.start_servers = 4\n") != std::string::npos);
    CHECK(generated_pools(cfg, "www").size() == 2);

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
          "[[site]]\nserver_name = [\"blog\"]\nlisten = [\"127.0.0.1:1\"]\nroot = \"blog\"\nuser = \"web2\"\napp = \"wordpress\"\naccess_log = \"/var/log/agensio/blog.log\"\n");
    Config cfg = load_config(dir / "h.toml");
    const std::string app = fs::canonical(dir / "app").string();
    const std::string blog = fs::canonical(dir / "blog").string();
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
    files["/run/php/agensio-web1.sock"] = file(1001, 1001, 0666);
    CHECK(count_with("expected group agensio") == 1 && count_with("any user could connect") == 1);
    files["/run/php/agensio-web1.sock"] = file(1002, 33, 0660);
    CHECK(count_with("socket /run/php/agensio-web1.sock is owned") == 1);
    files["/run/php/agensio-web1.sock"] = file(1001, 33, 0660);
    files["/var/log/agensio/shop.log"] = file(33, 33, 0644);
    CHECK(count_with("access log /var/log/agensio/shop.log is readable") == 1);
    files["/var/log/agensio/shop.log"] = file(33, 1001, 0640);
    files["/var/log/agensio"] = file(33, 1001, 0770, true);
    CHECK(count_with("log directory /var/log/agensio is writable") == 2);  // both sites log there
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
    CHECK(json::parse(R"({"app":"weird"})", body, err) && (apply_request(body, cfg, spec, err), err.find("app must be one of: static, php, laravel, drupal, wordpress, proxy") != std::string::npos));
    CHECK(app_presets().size() == 6 && app_presets().front() == "static" && app_presets().back() == "proxy");
    const json::Value catalog = preset_catalog();
    CHECK(catalog["presets"].items().size() == 6 && catalog["presets"].items()[0].get("app") == "static" && catalog["presets"].items()[5].get("app") == "proxy");
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
        CHECK(loaded.sites[0].root.empty());  // a redirect site has no document root, never the configuration directory
        CHECK(prerequisites(ok, loaded).empty());
        SiteSpec missing = ok;
        missing.user = "no-such-user-zz";
        missing.root = (dir / "missing").string();
        const auto pre = prerequisites(missing, loaded);
        CHECK(pre.size() == 2 && pre[0].starts_with("useradd --system --no-create-home --home-dir /var/lib/agensio/no-such-user-zz") && pre[1].starts_with("mkdir -p"));
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

static void test_strict_hosts() {
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
