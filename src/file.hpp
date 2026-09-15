// Thin portable wrapper over a read-only file descriptor.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace agensio {

struct FileInfo {
    std::uint64_t size = 0;
    std::int64_t mtime = 0;     // seconds since epoch
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
        if (this != &o) { close(); fd_ = std::exchange(o.fd_, -1); }
        return *this;
    }
    ~File() { close(); }

    // Opens read-only. Returns an invalid File on failure (check is_open()).
    static File open(const char* path) noexcept;

    bool is_open() const noexcept { return fd_ >= 0; }
    bool info(FileInfo& out) const noexcept;

    // Reads up to len bytes at offset. Returns bytes read, 0 at EOF, -1 on error.
    std::int64_t read_at(void* buf, std::size_t len, std::uint64_t offset) const noexcept;

    // Reads exactly len bytes starting at offset 0 into buf. Returns false on short read.
    bool read_all(void* buf, std::size_t len) const noexcept;

    void close() noexcept;

private:
    int fd_ = -1;
};

}  // namespace agensio
