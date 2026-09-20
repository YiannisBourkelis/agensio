// Archive extraction for site-install (F9): .tar, .tar.gz and .zip read from a Source,
// entries written through a Sink. Written for hostile input: the path of every entry is
// normalised and refused when it is absolute, contains "..", a backslash or a control
// character; symbolic links, hard links, devices, fifos and sockets are refused, not
// skipped; sizes, entry count, path length and depth are capped; tar checksums and zip
// CRCs are verified. No entry is ever created through a symlink (DirectorySink opens
// with O_NOFOLLOW | O_EXCL). Asio-free, so it is unit tested in memory and fuzzed.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace agensio::archive {

enum class Format { unknown, tar, gzip, zip };

// From the first bytes (512 are enough for tar; 4 for the others).
Format sniff(std::string_view head) noexcept;

// Random-access bytes: zip reads its directory from the end, tar reads forward.
struct Source {
    virtual ~Source() = default;
    virtual std::uint64_t size() = 0;
    // A short read means the end; false is an I/O error.
    virtual bool read_at(std::uint64_t offset, char* buf, std::size_t len, std::size_t& got) = 0;
};

class MemorySource : public Source {
public:
    explicit MemorySource(std::string_view bytes) noexcept : bytes_(bytes) {}
    std::uint64_t size() override { return bytes_.size(); }
    bool read_at(std::uint64_t offset, char* buf, std::size_t len, std::size_t& got) override;

private:
    std::string_view bytes_;
};

class FdSource : public Source {
public:
    explicit FdSource(int fd) noexcept : fd_(fd) {}
    std::uint64_t size() override;
    bool read_at(std::uint64_t offset, char* buf, std::size_t len, std::size_t& got) override;

private:
    int fd_;
};

// Where entries go. Every path is relative, cleaned, never empty; parents may be missing.
struct Sink {
    virtual ~Sink() = default;
    virtual bool directory(const std::string& path, std::string& error) = 0;
    virtual bool begin_file(const std::string& path, bool executable, std::uint64_t size, std::string& error) = 0;
    virtual bool data(const char* p, std::size_t n, std::string& error) = 0;
    virtual bool end_file(std::string& error) = 0;
};

struct Limits {
    std::size_t max_entries = 200000;
    std::uint64_t max_bytes = 4ull << 30;  // every file's bytes together
    std::uint64_t max_file = 2ull << 30;   // one file
    std::size_t max_path = 1024;
    std::size_t max_depth = 32;
};

struct Summary {
    std::size_t files = 0;
    std::size_t directories = 0;
    std::uint64_t bytes = 0;
    // The first path component every entry shares ("" when they differ), and whether no
    // file sits at that path: then the archive is one directory and can be unwrapped.
    std::string top;
    bool single_top = false;
};

// Extracts every entry; false with `error` at the first refused or malformed entry (the
// sink may have received part of the archive by then: the caller cleans up).
bool extract(Source& in, Sink& out, const Limits& limits, Summary& summary, std::string& error);

// The path rule, pure: strips "./" segments, duplicate and trailing slashes; refuses empty
// results, absolute paths, "..", backslashes and control characters.
bool clean_path(std::string_view raw, std::string& out, std::string& why);

// Counts what it is given (tests, fuzzing).
class CountingSink : public Sink {
public:
    bool directory(const std::string&, std::string&) override { ++directories; return true; }
    bool begin_file(const std::string&, bool executable, std::uint64_t, std::string&) override { ++files; executables += executable; return true; }
    bool data(const char*, std::size_t n, std::string&) override { bytes += n; return true; }
    bool end_file(std::string&) override { return true; }
    std::size_t files = 0, directories = 0, executables = 0;
    std::uint64_t bytes = 0;
};

#ifndef _WIN32
// Writes below an open directory descriptor. Directories get `dir_mode`'s permission
// bits (the set-gid bit and the group come from the parent, as the kernel hands them
// down: a 2750 site directory keeps the server's group on everything below), files
// `dir_mode & 0666` plus the directory's execute bits for executables: new content
// inherits the target directory's pattern. Files are
// created O_EXCL | O_NOFOLLOW, so an entry that exists already, or a symlink in the way,
// fails the extraction instead of being followed. Modes are exact whatever the umask.
class DirectorySink : public Sink {
public:
    DirectorySink(int dir_fd, unsigned dir_mode) noexcept : dir_fd_(dir_fd), dir_mode_(dir_mode & 0777) {}
    ~DirectorySink() override;
    bool directory(const std::string& path, std::string& error) override;
    bool begin_file(const std::string& path, bool executable, std::uint64_t size, std::string& error) override;
    bool data(const char* p, std::size_t n, std::string& error) override;
    bool end_file(std::string& error) override;

private:
    bool ensure_parents(const std::string& path, std::string& error);
    bool make_dir(const std::string& path, std::string& error);
    int dir_fd_;
    unsigned dir_mode_;
    int file_ = -1;
    unsigned file_mode_ = 0;
    std::string file_path_;
};
#endif

}  // namespace agensio::archive
