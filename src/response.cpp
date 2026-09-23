#include "response.hpp"

#include "http2/hpack.hpp"

#include <map>

namespace agensio {

namespace {

// Every registered status code (RFC 9110 and the IANA registry); applications behind
// FastCGI or a proxy may answer with any of them, so the status line must exist for all.
struct Reason {
    int code;
    std::string_view reason;
};

constexpr Reason kReasons[] = {
    {100, "Continue"}, {101, "Switching Protocols"}, {102, "Processing"}, {103, "Early Hints"},
    {200, "OK"}, {201, "Created"}, {202, "Accepted"}, {203, "Non-Authoritative Information"},
    {204, "No Content"}, {205, "Reset Content"}, {206, "Partial Content"}, {207, "Multi-Status"},
    {208, "Already Reported"}, {226, "IM Used"},
    {300, "Multiple Choices"}, {301, "Moved Permanently"}, {302, "Found"}, {303, "See Other"},
    {304, "Not Modified"}, {307, "Temporary Redirect"}, {308, "Permanent Redirect"},
    {400, "Bad Request"}, {401, "Unauthorized"}, {402, "Payment Required"}, {403, "Forbidden"},
    {404, "Not Found"}, {405, "Method Not Allowed"}, {406, "Not Acceptable"},
    {407, "Proxy Authentication Required"}, {408, "Request Timeout"}, {409, "Conflict"}, {410, "Gone"},
    {411, "Length Required"}, {412, "Precondition Failed"}, {413, "Content Too Large"},
    {414, "URI Too Long"}, {415, "Unsupported Media Type"}, {416, "Range Not Satisfiable"},
    {417, "Expectation Failed"}, {418, "I'm a teapot"}, {421, "Misdirected Request"},
    {422, "Unprocessable Content"}, {423, "Locked"}, {424, "Failed Dependency"}, {425, "Too Early"},
    {426, "Upgrade Required"}, {428, "Precondition Required"}, {429, "Too Many Requests"},
    {431, "Request Header Fields Too Large"}, {451, "Unavailable For Legal Reasons"},
    {500, "Internal Server Error"}, {501, "Not Implemented"}, {502, "Bad Gateway"},
    {503, "Service Unavailable"}, {504, "Gateway Timeout"}, {505, "HTTP Version Not Supported"},
    {506, "Variant Also Negotiates"}, {507, "Insufficient Storage"}, {508, "Loop Detected"},
    {510, "Not Extended"}, {511, "Network Authentication Required"},
};

std::string_view reason_of(int code) noexcept {
    for (auto& r : kReasons)
        if (r.code == code) return r.reason;
    return {};
}

// "HTTP/1.1 NNN Reason\r\n" for every code 100-599, built once; unregistered codes get an
// empty reason phrase, which RFC 9112 allows.
const std::string* status_lines() {
    static const std::string* lines = [] {
        auto* t = new std::string[500];  // NOLINT(cppcoreguidelines-owning-memory): lives for the process
        for (int code = 100; code <= 599; ++code) {
            std::string& l = t[code - 100];
            l = "HTTP/1.1 " + std::to_string(code) + " ";
            l.append(reason_of(code)).append("\r\n");
        }
        return t;
    }();
    return lines;
}

// Codes agensio answers with itself get a canned page.
constexpr int kPageCodes[] = {301, 400, 403, 404, 405, 413, 417, 421, 431, 500, 501, 502, 503, 504, 505};

const std::map<int, ErrorPage>& pages() {
    static const std::map<int, ErrorPage> m = [] {
        std::map<int, ErrorPage> out;
        for (int code : kPageCodes) {
            ErrorPage p;
            std::string title = std::to_string(code) + " " + std::string(reason_of(code));
            p.body = "<!doctype html><html><head><title>" + title + "</title></head><body><center><h1>" + title +
                     "</h1></center><hr><center>agensio</center></body></html>\n";
            p.headers =
                "Content-Type: text/html; charset=utf-8\r\nContent-Length: " + std::to_string(p.body.size()) + "\r\n";
            hpack::append_field(p.h2_headers, "content-type", "text/html; charset=utf-8");
            hpack::append_field(p.h2_headers, "content-length", std::to_string(p.body.size()));
            out.emplace(code, std::move(p));
        }
        return out;
    }();
    return m;
}

}  // namespace

std::string_view status_line(int code) noexcept {
    if (code < 100 || code > 599) code = 500;
    return status_lines()[code - 100];
}

void warm_response_tables() {
    (void)status_lines();
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
