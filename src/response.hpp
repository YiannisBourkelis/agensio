// Static response fragments: status lines and canned error pages.
#pragma once

#include <string>
#include <string_view>

namespace agensio {

// "HTTP/1.1 404 Not Found\r\n". Unknown codes map to 500.
std::string_view status_line(int code) noexcept;

struct ErrorPage {
    std::string body;     // small HTML document
    std::string headers;  // "Content-Type: text/html; charset=utf-8\r\nContent-Length: N\r\n"
};

// Canned page for an error status. Unknown codes map to 500.
const ErrorPage& error_page(int code) noexcept;

// Builds the page table up front so the first request never allocates. Called by Server.
void warm_response_tables();

}  // namespace agensio
