// Minimal self-contained unit tests (no framework dependency).
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <sstream>
#include <string_view>
#include <unistd.h>

#include "cache.hpp"
#include "http1/chunked.hpp"
#include "config.hpp"
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
#include "upstream/fcgi_options.hpp"

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
    CHECK(cache.insert(CacheKeyView{&site, "/a"}, make(100, 1)) != nullptr);
    CHECK(cache.insert(CacheKeyView{&site, "/b"}, make(100, 2)) != nullptr);
    CHECK_EQ(cache.total_bytes(), 200u);
    CHECK(cache.insert(CacheKeyView{&site, "/big"}, make(101, 3)) == nullptr);  // above max_file_size
    auto a = cache.find(CacheKeyView{&site, "/a"});
    CHECK(a != nullptr);
    // Third 100-byte entry does not fit: /a (oldest) must be evicted and marked stale.
    CHECK(cache.insert(CacheKeyView{&site, "/c"}, make(100, 3)) != nullptr);
    CHECK(a->stale.load());
    CHECK(cache.find(CacheKeyView{&site, "/a"}) == nullptr);
    CHECK(cache.total_bytes() <= 250u);
    // Same key twice returns the existing entry.
    auto c1 = cache.find(CacheKeyView{&site, "/c"});
    auto c2 = cache.insert(CacheKeyView{&site, "/c"}, make(10, 9));
    CHECK(c1 == c2);
    // erase only removes the expected pointer.
    cache.erase(CacheKeyView{&site, "/c"}, a.get());
    CHECK(cache.find(CacheKeyView{&site, "/c"}) != nullptr);
    cache.erase(CacheKeyView{&site, "/c"}, c1.get());
    CHECK(cache.find(CacheKeyView{&site, "/c"}) == nullptr);
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
    auto d1 = cache.insert(CacheKeyView{&site, "/d1"}, make_fd(1));
    CHECK(d1 != nullptr);
    CHECK(cache.insert(CacheKeyView{&site, "/d2"}, make_fd(5)) != nullptr);
    CHECK_EQ(cache.open_files(), 2u);
    CHECK_EQ(cache.total_bytes(), bytes_before);
    // Third descriptor exceeds the budget: the oldest descriptor entry goes, memory entries stay.
    auto d3 = cache.insert(CacheKeyView{&site, "/d3"}, make_fd(6));
    CHECK(d3 != nullptr);
    CHECK(d1->stale.load());
    CHECK(cache.find(CacheKeyView{&site, "/d1"}) == nullptr);
    CHECK(cache.open_files() <= 2u);
    CHECK(cache.find(CacheKeyView{&site, "/b"}) != nullptr);
    // Byte pressure evicts memory entries only: /b (access 2) is older than the descriptors but
    // the descriptors free no bytes, so they survive.
    auto b = cache.find(CacheKeyView{&site, "/b"});
    CHECK(cache.insert(CacheKeyView{&site, "/e"}, make(100, 7)) != nullptr);
    CHECK(cache.insert(CacheKeyView{&site, "/f"}, make(100, 8)) != nullptr);
    CHECK(b->stale.load());
    CHECK(!d3->stale.load());
    CHECK(cache.find(CacheKeyView{&site, "/d3"}) != nullptr);
    CHECK_EQ(cache.open_files(), 2u);
    // erase releases the descriptor budget.
    cache.erase(CacheKeyView{&site, "/d3"}, d3.get());
    CHECK_EQ(cache.open_files(), 1u);
    // A zero-byte memory entry is not a descriptor entry.
    CHECK(cache.insert(CacheKeyView{&site, "/empty"}, make(0, 9)) != nullptr);
    CHECK_EQ(cache.open_files(), 1u);
    // max_open_files = 0 refuses descriptor entries; the handler then streams uncached.
    FileCache none(100, 250, 0.5, 0);
    CHECK(none.insert(CacheKeyView{&site, "/d"}, make_fd(1)) == nullptr);
    CHECK(none.insert(CacheKeyView{&site, "/m"}, make(10, 1)) != nullptr);

    LocalIndex local(2);
    local.insert(CacheKeyView{&site, "/x"}, make(1, 0));
    local.insert(CacheKeyView{&site, "/y"}, make(1, 0));
    CHECK(local.find(CacheKeyView{&site, "/x"}) != nullptr);
    local.insert(CacheKeyView{&site, "/z"}, make(1, 0));  // exceeds max: cleared, then inserted
    CHECK(local.find(CacheKeyView{&site, "/x"}) == nullptr);
    CHECK(local.find(CacheKeyView{&site, "/z"}) != nullptr);
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
    CHECK_EQ(out.size(), (8 + 65535 + 1) + (8 + 4465 + 7) + 8);
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
    CHECK(Router::location(s, "/other.php").kind == HandlerKind::static_);  // only the front controller runs
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
          status_for(FcgiFailure::child_closed_early) == 502);
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
    if (failures) {
        std::printf("%d failure(s)\n", failures);
        return 1;
    }
    std::printf("all tests passed\n");
    return 0;
}
