// Thin portable wrapper over a read-only file descriptor.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace agensio {

struct FileInfo {
    std::uint64_t size = 0;
    std::int64_t mtime = 0;  // seconds since epoch
    bool is_regular = false;
    bool is_directory = false;
};

// stat() without opening. Returns false if the path does not exist or is inaccessible.
bool stat_path(const char* path, FileInfo& out) noexcept;

class File {
public:
    File() = default;
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    File(File&& o) noexcept : fd_(std::exchange(o.fd_, -1)) {}
    File& operator=(File&& o) noexcept {
        if (this != &o) {
            close();
            fd_ = std::exchange(o.fd_, -1);
        }
        return *this;
    }
    ~File() { close(); }

    // Opens read-only. Returns an invalid File on failure (check is_open()).
    static File open(const char* path) noexcept;
    // An anonymous read/write temporary file (unlinked at once; freed when closed).
    static File temporary() noexcept;
    // Appends len bytes (temporary files only). False on a short write or error.
    bool append(const void* data, std::size_t len) noexcept;

    bool is_open() const noexcept { return fd_ >= 0; }
    bool info(FileInfo& out) const noexcept;

    // Reads up to len bytes at offset. Returns bytes read, 0 at EOF, -1 on error.
    std::int64_t read_at(void* buf, std::size_t len, std::uint64_t offset) const noexcept;

    // Reads exactly len bytes starting at offset 0 into buf. Returns false on short read.
    bool read_all(void* buf, std::size_t len) const noexcept;

    void close() noexcept;

    int native_handle() const noexcept { return fd_; }

private:
    int fd_ = -1;
};

struct IoSlice {
    const void* data;
    std::size_t len;
};

struct SendFileResult {
    std::int64_t sent = 0;             // bytes handed to the socket in this call (headers included)
    bool would_block = false;          // socket buffer full; wait for writability and call again
    bool unsupported = false;          // platform has no sendfile: use the read/write path
    bool headers_unsupported = false;  // platform cannot attach headers: write them first, then call again
};

// Zero-copy file-to-socket transfer (sendfile on macOS, Linux, FreeBSD). The socket
// must be non-blocking. Up to `header_count` header slices are sent before the file
// data where the platform supports it (macOS, FreeBSD). `sent` counts header bytes
// first, then file bytes. sent == 0 with would_block == false and no headers pending
// means EOF (file shrank). sent < 0 means a socket error (errno set).
SendFileResult send_file(int socket_fd, const File& file, std::uint64_t offset, std::uint64_t count,
                         const IoSlice* headers = nullptr, int header_count = 0) noexcept;

// TCP_CORK (Linux) / TCP_NOPUSH (BSD, macOS): while set, the kernel coalesces sendfile
// page batches into full-size segments instead of pushing each one; must be cleared at the
// end of the response to flush the tail. No-op on other platforms.
void set_tcp_cork(int socket_fd, bool on) noexcept;

// Raises the soft open-file limit to the hard limit. Returns the resulting soft limit.
std::uint64_t raise_open_file_limit() noexcept;

// True if the canonical (symlink-resolved) form of `path` is `root` itself or lies
// under `root/`. `root` must already be canonical. False if the path cannot be
// resolved. Costs one realpath() call; only used on cache misses.
bool path_within_root(const char* path, std::string_view root) noexcept;

}  // namespace agensio
