// Minimal self-contained unit tests (no framework dependency).
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>

#include "cache.hpp"
#include "config.hpp"
#include "core/headers.hpp"
#include "core/result.hpp"
#include "handlers/static.hpp"
#include "http1/parser.hpp"
#include "http_date.hpp"
#include "mime.hpp"
#include "path.hpp"

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
    CHECK(r.method == Method::GET);
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
    CHECK(r.method == Method::HEAD);
    CHECK_EQ(r.host, "a");
    CHECK(parse_request("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello", r) == ParseStatus::complete);
    CHECK(r.method == Method::OTHER);
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
    Route r;
    r.by_name.emplace("example.com", &a);
    r.by_name.emplace("www.example.com", &a);
    r.by_name.emplace("other.test", &b);
    r.default_site = &a;
    CHECK(r.lookup("example.com") == &a);
    CHECK(r.lookup("EXAMPLE.com:8080") == &a);
    CHECK(r.lookup("other.test:443") == &b);
    CHECK(r.lookup("other.test.") == &b);
    CHECK(r.lookup("[::1]:8080") == &a);
    CHECK(r.lookup("unknown.host") == &a);
    CHECK(r.lookup("") == &a);

    std::string etag;
    make_etag(0x5a630d3c, 0x6b, etag);
    CHECK_EQ(etag, "\"5a630d3c-6b\"");
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
    test_core_types();
    test_route_and_etag();
    if (failures) {
        std::printf("%d failure(s)\n", failures);
        return 1;
    }
    std::printf("all tests passed\n");
    return 0;
}
