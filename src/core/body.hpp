// Response bodies. The two fast paths are plain data (memory, written zero-copy in the
// same scatter list as the headers) and files (sendfile or chunked reads); both live in
// the Response by value, no allocation per response. Bodies that arrive over time
// (FastCGI, proxy, CGI in later phases) implement StreamBody and are pulled with
// backpressure: the connection asks for the next chunk only when the previous one has
// been written to the client.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>
#include <system_error>
#include <variant>

#include "file.hpp"

namespace agensio {

struct NoBody {};

struct MemoryBody {
    std::string_view data;  // storage owned by whatever Response::entry or a static keeps alive
};

struct FileBody {
    const File* file = nullptr;  // owned by Response::owned_file or by a cache entry (Response::entry)
    std::uint64_t size = 0;
    std::uint64_t sent = 0;
};

class StreamBody {
public:
    virtual ~StreamBody() = default;
    // Total length if known up front (Content-Length); otherwise the connection frames the body.
    virtual bool length(std::uint64_t& out) const noexcept = 0;
    // Reads up to `len` bytes into `buf`; completes with the byte count, 0 at end of body.
    using ReadHandler = std::function<void(std::error_code, std::size_t)>;
    virtual void async_read(char* buf, std::size_t len, ReadHandler handler) = 0;
};

using Body = std::variant<NoBody, MemoryBody, FileBody, std::unique_ptr<StreamBody>>;

inline bool has_body(const Body& b) noexcept { return !std::holds_alternative<NoBody>(b); }

}  // namespace agensio
