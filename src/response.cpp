#include "response.hpp"

#include <map>

namespace agensio {

namespace {

struct Status {
    int code;
    std::string_view line;
    std::string_view reason;
};

constexpr Status kStatus[] = {
    {200, "HTTP/1.1 200 OK\r\n", "OK"},
    {301, "HTTP/1.1 301 Moved Permanently\r\n", "Moved Permanently"},
    {304, "HTTP/1.1 304 Not Modified\r\n", "Not Modified"},
    {400, "HTTP/1.1 400 Bad Request\r\n", "Bad Request"},
    {403, "HTTP/1.1 403 Forbidden\r\n", "Forbidden"},
    {404, "HTTP/1.1 404 Not Found\r\n", "Not Found"},
    {405, "HTTP/1.1 405 Method Not Allowed\r\n", "Method Not Allowed"},
    {413, "HTTP/1.1 413 Content Too Large\r\n", "Content Too Large"},
    {417, "HTTP/1.1 417 Expectation Failed\r\n", "Expectation Failed"},
    {431, "HTTP/1.1 431 Request Header Fields Too Large\r\n", "Request Header Fields Too Large"},
    {500, "HTTP/1.1 500 Internal Server Error\r\n", "Internal Server Error"},
    {501, "HTTP/1.1 501 Not Implemented\r\n", "Not Implemented"},
    {505, "HTTP/1.1 505 HTTP Version Not Supported\r\n", "HTTP Version Not Supported"},
};

const Status& lookup(int code) noexcept {
    for (auto& s : kStatus)
        if (s.code == code) return s;
    return lookup(500);
}

const std::map<int, ErrorPage>& pages() {
    static const std::map<int, ErrorPage> m = [] {
        std::map<int, ErrorPage> out;
        for (auto& s : kStatus) {
            if (s.code == 200 || s.code == 304) continue;
            ErrorPage p;
            std::string title = std::to_string(s.code) + " " + std::string(s.reason);
            p.body = "<!doctype html><html><head><title>" + title + "</title></head><body><center><h1>" + title +
                     "</h1></center><hr><center>agensio</center></body></html>\n";
            p.headers =
                "Content-Type: text/html; charset=utf-8\r\nContent-Length: " + std::to_string(p.body.size()) + "\r\n";
            out.emplace(s.code, std::move(p));
        }
        return out;
    }();
    return m;
}

}  // namespace

std::string_view status_line(int code) noexcept {
    return lookup(code).line;
}

void warm_response_tables() {
    (void)pages();
}

// NOLINTNEXTLINE(bugprone-exception-escape): the page table is built once, at Server construction
// (warm_response_tables).
// The page table is built once at Server construction (warm_response_tables), so this cannot throw at runtime.
const ErrorPage& error_page(int code) noexcept {  // NOLINT(bugprone-exception-escape)
    auto& m = pages();
    auto it = m.find(code);
    if (it == m.end()) it = m.find(500);  // always present
    return it->second;
}

}  // namespace agensio
