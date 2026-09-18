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
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <variant>

#include "file.hpp"

namespace agensio {

struct NoBody {};

struct MemoryBody {
    std::string_view data;  // storage owned by whatever Response::entry or a static keeps alive
};

struct FileBody {
    const File* file = nullptr;  // owned by Response::owned_file or by a cache entry (Response::entry)
    std::uint64_t size = 0;      // bytes to send
    std::uint64_t sent = 0;
    std::uint64_t offset = 0;    // where in the file they start (a range)
};

// The HTTP/1 writer frames a StreamBody itself: Content-Length when length() is known,
// otherwise chunked on HTTP/1.1 or close-delimited on HTTP/1.0. Handlers producing one
// must not add Content-Length or Transfer-Encoding fields. A read error mid-body closes
// the connection, so the client sees a truncated body rather than a false end.
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

// Errors a body source can complete with (besides transport errors from Asio).
enum class BodyError {
    too_large = 1,  // exceeds server.max_body_size
    malformed = 2,  // bad chunked framing
};

inline const std::error_category& body_category() noexcept {
    static const struct Category final : std::error_category {
        const char* name() const noexcept override { return "agensio.body"; }
        std::string message(int c) const override {
            switch (static_cast<BodyError>(c)) {
                case BodyError::too_large: return "request body too large";
                case BodyError::malformed: return "malformed request body";
            }
            return "body error";
        }
    } category;
    return category;
}

inline std::error_code make_error_code(BodyError e) noexcept {
    return std::error_code(static_cast<int>(e), body_category());
}

}  // namespace agensio

template <>
struct std::is_error_code_enum<agensio::BodyError> : std::true_type {};
