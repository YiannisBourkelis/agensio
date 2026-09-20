#include "services/archive.hpp"

#include <algorithm>
#include <cstring>
#include <memory>
#include <vector>

#ifdef AGENSIO_HAS_ZLIB
#include <zlib.h>
#endif

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace agensio::archive {

// ---- sources ----

bool MemorySource::read_at(std::uint64_t offset, char* buf, std::size_t len, std::size_t& got) {
    if (offset >= bytes_.size()) {
        got = 0;
        return true;
    }
    got = static_cast<std::size_t>(std::min<std::uint64_t>(len, bytes_.size() - offset));
    std::memcpy(buf, bytes_.data() + offset, got);
    return true;
}

#ifndef _WIN32
std::uint64_t FdSource::size() {
    struct stat st {};
    return ::fstat(fd_, &st) == 0 ? static_cast<std::uint64_t>(st.st_size) : 0;
}

bool FdSource::read_at(std::uint64_t offset, char* buf, std::size_t len, std::size_t& got) {
    got = 0;
    while (got < len) {
        const ssize_t n = ::pread(fd_, buf + got, len - got, static_cast<off_t>(offset + got));
        if (n < 0) return errno == EINTR;
        if (n == 0) break;
        got += static_cast<std::size_t>(n);
    }
    return true;
}
#else
std::uint64_t FdSource::size() { return 0; }
bool FdSource::read_at(std::uint64_t, char*, std::size_t, std::size_t& got) { got = 0; return false; }
#endif

// ---- the path rule ----

bool clean_path(std::string_view raw, std::string& out, std::string& why) {
    out.clear();
    if (raw.empty()) {
        why = "empty name";
        return false;
    }
    for (unsigned char c : raw) {
        if (c < 0x20 || c == 0x7f) {
            why = "control character in name";
            return false;
        }
        if (c == '\\') {
            why = "backslash in name";
            return false;
        }
    }
    if (raw.front() == '/') {
        why = "absolute path";
        return false;
    }
    std::size_t pos = 0;
    while (pos <= raw.size()) {
        const std::size_t next = raw.find('/', pos);
        const std::string_view part = raw.substr(pos, next == std::string_view::npos ? std::string_view::npos : next - pos);
        pos = next == std::string_view::npos ? raw.size() + 1 : next + 1;
        if (part.empty() || part == ".") continue;
        if (part == "..") {
            why = "'..' in name";
            return false;
        }
        if (!out.empty()) out.push_back('/');
        out.append(part);
    }
    if (out.empty()) {
        why = "empty name";
        return false;
    }
    return true;
}

Format sniff(std::string_view head) noexcept {
    if (head.size() >= 2 && static_cast<unsigned char>(head[0]) == 0x1f && static_cast<unsigned char>(head[1]) == 0x8b) return Format::gzip;
    if (head.size() >= 4 && head[0] == 'P' && head[1] == 'K' && (head[2] == 3 || head[2] == 5) && (head[3] == 4 || head[3] == 6)) return Format::zip;
    if (head.size() >= 262 && head.compare(257, 5, "ustar") == 0) return Format::tar;
    return Format::unknown;
}

namespace {

// ---- the entry bookkeeping every format shares ----

class Emitter {
public:
    Emitter(Sink& out, const Limits& limits, Summary& summary) : out_(out), limits_(limits), summary_(summary) {}

    // False with `error` when refused; true with an empty `path` for the archive's own
    // root entry ("./" or ".", what `tar -C dir .` writes first), which is nothing to create.
    bool entry(std::string_view raw, bool is_dir, std::string& path, std::string& error) {
        std::string why;
        if (!clean_path(raw, path, why)) {
            if (is_dir && why == "empty name" && raw.find_first_not_of("./") == std::string_view::npos) {
                path.clear();
                return true;
            }
            error = "entry '" + std::string(raw.substr(0, 200)) + "': " + why;
            return false;
        }
        if (path.size() > limits_.max_path) {
            error = "entry name longer than " + std::to_string(limits_.max_path) + " bytes";
            return false;
        }
        if (static_cast<std::size_t>(std::count(path.begin(), path.end(), '/')) >= limits_.max_depth) {
            error = "entry '" + path + "' nested deeper than " + std::to_string(limits_.max_depth);
            return false;
        }
        if (++entries_ > limits_.max_entries) {
            error = "more than " + std::to_string(limits_.max_entries) + " entries";
            return false;
        }
        const std::string_view first = std::string_view(path).substr(0, path.find('/'));
        if (entries_ == 1) {
            summary_.top = first;
            summary_.single_top = true;
        } else if (summary_.top != first) {
            summary_.single_top = false;
        }
        if (!is_dir && path == summary_.top) summary_.single_top = false;  // a file at the top: nothing to unwrap
        return true;
    }
    bool directory(const std::string& path, std::string& error) {
        ++summary_.directories;
        return out_.directory(path, error);
    }
    bool begin_file(const std::string& path, bool executable, std::uint64_t size, std::string& error) {
        if (size > limits_.max_file) {
            error = "entry '" + path + "' larger than " + std::to_string(limits_.max_file) + " bytes";
            return false;
        }
        if (summary_.bytes + size > limits_.max_bytes) {
            error = "archive unpacks to more than " + std::to_string(limits_.max_bytes) + " bytes";
            return false;
        }
        ++summary_.files;
        return out_.begin_file(path, executable, size, error);
    }
    bool data(const char* p, std::size_t n, std::string& error) {
        summary_.bytes += n;
        if (summary_.bytes > limits_.max_bytes) {
            error = "archive unpacks to more than " + std::to_string(limits_.max_bytes) + " bytes";
            return false;
        }
        return out_.data(p, n, error);
    }
    bool end_file(std::string& error) { return out_.end_file(error); }

private:
    Sink& out_;
    const Limits& limits_;
    Summary& summary_;
    std::size_t entries_ = 0;
};

// ---- forward byte streams for tar: plain, or through gzip ----

struct ByteStream {
    virtual ~ByteStream() = default;
    // Fills exactly len bytes, or returns false (short: end of data; error set on a fault).
    virtual bool read_exact(char* buf, std::size_t len, std::string& error) = 0;
    virtual bool at_end() = 0;
};

class PlainStream : public ByteStream {
public:
    explicit PlainStream(Source& src) : src_(src), size_(src.size()) {}
    bool read_exact(char* buf, std::size_t len, std::string& error) override {
        std::size_t got = 0;
        if (!src_.read_at(pos_, buf, len, got)) {
            error = "read error";
            return false;
        }
        pos_ += got;
        return got == len;
    }
    bool at_end() override { return pos_ >= size_; }

private:
    Source& src_;
    std::uint64_t size_;
    std::uint64_t pos_ = 0;
};

#ifdef AGENSIO_HAS_ZLIB
class GzipStream : public ByteStream {
public:
    explicit GzipStream(Source& src) : src_(src), size_(src.size()) {
        std::memset(&z_, 0, sizeof z_);
        ok_ = inflateInit2(&z_, 15 + 16) == Z_OK;  // gzip framing
    }
    ~GzipStream() override {
        if (ok_) inflateEnd(&z_);
    }
    bool read_exact(char* buf, std::size_t len, std::string& error) override {
        if (!ok_) {
            error = "zlib init failed";
            return false;
        }
        z_.next_out = reinterpret_cast<Bytef*>(buf);
        z_.avail_out = static_cast<uInt>(len);
        while (z_.avail_out > 0) {
            if (finished_) return false;
            if (z_.avail_in == 0) {
                std::size_t got = 0;
                if (!src_.read_at(pos_, in_, sizeof in_, got)) {
                    error = "read error";
                    return false;
                }
                if (got == 0) {
                    error = "gzip stream ends early";
                    return false;
                }
                pos_ += got;
                z_.next_in = reinterpret_cast<Bytef*>(in_);
                z_.avail_in = static_cast<uInt>(got);
            }
            const int rc = inflate(&z_, Z_NO_FLUSH);
            if (rc == Z_STREAM_END) {
                // Concatenated members (gzip allows them): continue when input remains.
                if (z_.avail_in == 0 && pos_ >= size_) {
                    finished_ = true;
                    if (z_.avail_out > 0) return false;
                } else if (inflateReset(&z_) != Z_OK) {
                    error = "gzip: cannot restart after a member";
                    return false;
                }
            } else if (rc != Z_OK && rc != Z_BUF_ERROR) {
                error = std::string("gzip: ") + (z_.msg ? z_.msg : "corrupt data");
                return false;
            } else if (rc == Z_BUF_ERROR && z_.avail_in > 0 && z_.avail_out > 0) {
                error = "gzip: no progress";
                return false;
            }
        }
        return true;
    }
    bool at_end() override { return finished_ || (z_.avail_in == 0 && pos_ >= size_); }

private:
    Source& src_;
    std::uint64_t size_;
    std::uint64_t pos_ = 0;
    z_stream z_{};
    bool ok_ = false;
    bool finished_ = false;
    char in_[64 * 1024];
};
#endif

// ---- tar ----

std::uint64_t tar_number(const char* field, std::size_t len) {
    if (static_cast<unsigned char>(field[0]) & 0x80) {  // GNU base-256
        std::uint64_t v = static_cast<unsigned char>(field[0]) & 0x7f;
        for (std::size_t i = 1; i < len; ++i) v = (v << 8) | static_cast<unsigned char>(field[i]);
        return v;
    }
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < len; ++i) {
        const char c = field[i];
        if (c == ' ' || c == '\0') {
            if (v) break;
            continue;
        }
        if (c < '0' || c > '7') break;
        v = v * 8 + static_cast<std::uint64_t>(c - '0');
    }
    return v;
}

std::string tar_string(const char* field, std::size_t len) {
    std::size_t n = 0;
    while (n < len && field[n] != '\0') ++n;
    return std::string(field, n);
}

bool tar_extract(ByteStream& in, Emitter& em, std::string& error) {
    char h[512];
    char buf[64 * 1024];
    std::string long_name, pax_path;
    bool have_long = false, have_pax = false;
    for (;;) {
        if (in.at_end()) return true;
        if (!in.read_exact(h, sizeof h, error)) {
            if (error.empty()) return true;  // a stream that stops on a block boundary
            return false;
        }
        bool zero = true;
        for (char c : h)
            if (c != '\0') { zero = false; break; }
        if (zero) return true;  // end-of-archive marker
        // Checksum: the field itself counts as spaces.
        unsigned sum = 0;
        for (std::size_t i = 0; i < 512; ++i) sum += (i >= 148 && i < 156) ? 32u : static_cast<unsigned char>(h[i]);
        if (sum != tar_number(h + 148, 8)) {
            error = "tar: header checksum mismatch (not a tar archive, or corrupt)";
            return false;
        }
        const std::uint64_t size = tar_number(h + 124, 12);
        const char type = h[156];
        const bool ustar = std::memcmp(h + 257, "ustar", 5) == 0;
        std::string name = tar_string(h, 100);
        if (ustar && h[345] != '\0') name = tar_string(h + 345, 155) + "/" + name;
        if (have_long) { name = long_name; have_long = false; }
        if (have_pax) { name = pax_path; have_pax = false; }
        const std::uint64_t padded = (size + 511) & ~std::uint64_t(511);
        auto skip = [&](std::uint64_t n) {
            while (n > 0) {
                const std::size_t step = static_cast<std::size_t>(std::min<std::uint64_t>(n, sizeof buf));
                if (!in.read_exact(buf, step, error)) {
                    if (error.empty()) error = "tar: archive ends inside an entry";
                    return false;
                }
                n -= step;
            }
            return true;
        };
        if (type == 'L' || type == 'x' || type == 'K' || type == 'g') {  // GNU long name / pax headers
            if (size > 65536) {
                error = "tar: extended header larger than 64 KB";
                return false;
            }
            std::string text(static_cast<std::size_t>(padded), '\0');
            if (padded && !in.read_exact(text.data(), text.size(), error)) {
                if (error.empty()) error = "tar: archive ends inside an entry";
                return false;
            }
            text.resize(static_cast<std::size_t>(size));
            if (type == 'L') {
                long_name = text.substr(0, text.find('\0'));
                have_long = true;
            } else if (type == 'x') {  // "len key=value\n" records; only path matters here
                std::size_t p = 0;
                while (p < text.size()) {
                    const std::size_t sp = text.find(' ', p);
                    if (sp == std::string::npos) break;
                    const std::size_t len = std::strtoul(text.substr(p, sp - p).c_str(), nullptr, 10);
                    if (len == 0 || p + len > text.size()) break;
                    const std::string rec = text.substr(sp + 1, p + len - sp - 2);
                    if (rec.starts_with("path=")) {
                        pax_path = rec.substr(5);
                        have_pax = true;
                    }
                    p += len;
                }
            }
            continue;
        }
        if (type == '2') { error = "tar: entry '" + name + "' is a symbolic link; refused"; return false; }
        if (type == '1') { error = "tar: entry '" + name + "' is a hard link; refused"; return false; }
        if (type == '3' || type == '4') { error = "tar: entry '" + name + "' is a device; refused"; return false; }
        if (type == '6') { error = "tar: entry '" + name + "' is a fifo; refused"; return false; }
        const bool is_dir = type == '5' || (type == '0' && !name.empty() && name.back() == '/');
        if (type != '0' && type != '\0' && type != '7' && type != '5') {
            error = std::string("tar: entry '") + name + "' has unsupported type '" + type + "'";
            return false;
        }
        std::string path;
        if (!em.entry(name, is_dir, path, error)) return false;
        if (is_dir) {
            if (!path.empty() && !em.directory(path, error)) return false;
            if (!skip(padded)) return false;
            continue;
        }
        const bool executable = (tar_number(h + 100, 8) & 0111) != 0;
        if (!em.begin_file(path, executable, size, error)) return false;
        std::uint64_t left = size;
        while (left > 0) {
            const std::size_t step = static_cast<std::size_t>(std::min<std::uint64_t>(left, sizeof buf));
            if (!in.read_exact(buf, step, error)) {
                if (error.empty()) error = "tar: archive ends inside '" + path + "'";
                return false;
            }
            if (!em.data(buf, step, error)) return false;
            left -= step;
        }
        if (!em.end_file(error)) return false;
        if (!skip(padded - size)) return false;
    }
}

// ---- zip ----

std::uint32_t le32(const char* p) {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(p[0])) | (static_cast<std::uint32_t>(static_cast<unsigned char>(p[1])) << 8) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(p[2])) << 16) | (static_cast<std::uint32_t>(static_cast<unsigned char>(p[3])) << 24);
}
std::uint16_t le16(const char* p) {
    return static_cast<std::uint16_t>(static_cast<unsigned char>(p[0]) | (static_cast<unsigned char>(p[1]) << 8));
}

bool read_all(Source& src, std::uint64_t off, char* buf, std::size_t len, std::string& error) {
    std::size_t got = 0;
    if (!src.read_at(off, buf, len, got) || got != len) {
        error = "zip: truncated archive";
        return false;
    }
    return true;
}

bool zip_extract(Source& src, Emitter& em, std::string& error) {
    const std::uint64_t size = src.size();
    if (size < 22) {
        error = "zip: too small";
        return false;
    }
    // The end-of-central-directory record is in the last 64 KB + 22 bytes.
    const std::size_t tail_len = static_cast<std::size_t>(std::min<std::uint64_t>(size, 65557));
    std::string tail(tail_len, '\0');
    if (!read_all(src, size - tail_len, tail.data(), tail_len, error)) return false;
    std::size_t eocd = std::string::npos;
    for (std::size_t i = tail_len - 22 + 1; i-- > 0;) {
        if (tail[i] == 'P' && tail[i + 1] == 'K' && tail[i + 2] == 5 && tail[i + 3] == 6) {
            eocd = i;
            break;
        }
    }
    if (eocd == std::string::npos) {
        error = "zip: no end-of-central-directory record";
        return false;
    }
    const char* e = tail.data() + eocd;
    const std::uint16_t entries = le16(e + 10);
    const std::uint32_t cd_size = le32(e + 12);
    const std::uint32_t cd_off = le32(e + 16);
    if (entries == 0xffff || cd_size == 0xffffffffu || cd_off == 0xffffffffu) {
        error = "zip: zip64 archives are not supported; use a .tar.gz";
        return false;
    }
    if (static_cast<std::uint64_t>(cd_off) + cd_size > size) {
        error = "zip: central directory outside the file";
        return false;
    }
    std::string cd(cd_size, '\0');
    if (cd_size && !read_all(src, cd_off, cd.data(), cd_size, error)) return false;
    std::vector<char> buf(64 * 1024);
    std::vector<char> outbuf(64 * 1024);
    std::size_t p = 0;
    for (std::uint16_t i = 0; i < entries; ++i) {
        if (p + 46 > cd.size() || std::memcmp(cd.data() + p, "PK\x01\x02", 4) != 0) {
            error = "zip: corrupt central directory";
            return false;
        }
        const char* h = cd.data() + p;
        const std::uint16_t made_by = le16(h + 4);
        const std::uint16_t flags = le16(h + 8);
        const std::uint16_t method = le16(h + 10);
        const std::uint32_t crc = le32(h + 16);
        const std::uint32_t csize = le32(h + 20);
        const std::uint32_t usize = le32(h + 24);
        const std::uint16_t name_len = le16(h + 28), extra_len = le16(h + 30), comment_len = le16(h + 32);
        const std::uint32_t ext_attr = le32(h + 38);
        const std::uint32_t local_off = le32(h + 42);
        if (p + 46 + name_len + extra_len + comment_len > cd.size()) {
            error = "zip: corrupt central directory";
            return false;
        }
        const std::string name(h + 46, name_len);
        p += 46 + name_len + extra_len + comment_len;
        if (csize == 0xffffffffu || usize == 0xffffffffu || local_off == 0xffffffffu) {
            error = "zip: zip64 entry '" + name + "' is not supported; use a .tar.gz";
            return false;
        }
        if (flags & 1) {
            error = "zip: entry '" + name + "' is encrypted; refused";
            return false;
        }
        const unsigned unix_mode = (made_by >> 8) == 3 ? (ext_attr >> 16) & 0xffff : 0;
        if ((unix_mode & 0170000) == 0120000) {
            error = "zip: entry '" + name + "' is a symbolic link; refused";
            return false;
        }
        if (unix_mode && (unix_mode & 0170000) != 0100000 && (unix_mode & 0170000) != 0040000) {
            error = "zip: entry '" + name + "' is a special file; refused";
            return false;
        }
        const bool is_dir = (!name.empty() && name.back() == '/') || (unix_mode & 0170000) == 0040000;
        std::string path;
        if (!em.entry(name, is_dir, path, error)) return false;
        if (is_dir && path.empty()) continue;
        if (is_dir) {
            if (usize != 0) {
                error = "zip: directory entry '" + path + "' carries data";
                return false;
            }
            if (!em.directory(path, error)) return false;
            continue;
        }
        if (method != 0 && method != 8) {
            error = "zip: entry '" + path + "' uses compression method " + std::to_string(method) + "; only stored and deflate are supported";
            return false;
        }
        // The local header gives where the data starts (its own name/extra lengths).
        char lh[30];
        if (!read_all(src, local_off, lh, sizeof lh, error)) return false;
        if (std::memcmp(lh, "PK\x03\x04", 4) != 0) {
            error = "zip: entry '" + path + "': bad local header";
            return false;
        }
        const std::uint64_t data_off = static_cast<std::uint64_t>(local_off) + 30 + le16(lh + 26) + le16(lh + 28);
        if (data_off + csize > size) {
            error = "zip: entry '" + path + "' outside the file";
            return false;
        }
        if (!em.begin_file(path, (unix_mode & 0111) != 0, usize, error)) return false;
        std::uint32_t running = 0;
        std::uint64_t produced = 0;
#ifdef AGENSIO_HAS_ZLIB
        running = static_cast<std::uint32_t>(crc32(0L, nullptr, 0));
#endif
        if (method == 0) {
            if (csize != usize) {
                error = "zip: entry '" + path + "': stored sizes differ";
                return false;
            }
            std::uint64_t left = csize, off = data_off;
            while (left > 0) {
                const std::size_t step = static_cast<std::size_t>(std::min<std::uint64_t>(left, buf.size()));
                if (!read_all(src, off, buf.data(), step, error)) return false;
#ifdef AGENSIO_HAS_ZLIB
                running = static_cast<std::uint32_t>(crc32(running, reinterpret_cast<const Bytef*>(buf.data()), static_cast<uInt>(step)));
#endif
                if (!em.data(buf.data(), step, error)) return false;
                left -= step;
                off += step;
                produced += step;
            }
        } else {
#ifdef AGENSIO_HAS_ZLIB
            z_stream z;
            std::memset(&z, 0, sizeof z);
            if (inflateInit2(&z, -15) != Z_OK) {  // raw deflate
                error = "zlib init failed";
                return false;
            }
            std::unique_ptr<z_stream, void (*)(z_stream*)> guard(&z, [](z_stream* s) { inflateEnd(s); });
            std::uint64_t left = csize, off = data_off;
            bool done = false;
            while (!done) {
                if (z.avail_in == 0) {
                    if (left == 0) {
                        error = "zip: entry '" + path + "': deflate stream ends early";
                        return false;
                    }
                    const std::size_t step = static_cast<std::size_t>(std::min<std::uint64_t>(left, buf.size()));
                    if (!read_all(src, off, buf.data(), step, error)) return false;
                    left -= step;
                    off += step;
                    z.next_in = reinterpret_cast<Bytef*>(buf.data());
                    z.avail_in = static_cast<uInt>(step);
                }
                z.next_out = reinterpret_cast<Bytef*>(outbuf.data());
                z.avail_out = static_cast<uInt>(outbuf.size());
                const int rc = inflate(&z, Z_NO_FLUSH);
                if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
                    error = "zip: entry '" + path + "': " + (z.msg ? z.msg : "corrupt deflate data");
                    return false;
                }
                const std::size_t got = outbuf.size() - z.avail_out;
                if (got) {
                    produced += got;
                    if (produced > usize) {
                        error = "zip: entry '" + path + "' inflates past its declared size";
                        return false;
                    }
                    running = static_cast<std::uint32_t>(crc32(running, reinterpret_cast<const Bytef*>(outbuf.data()), static_cast<uInt>(got)));
                    if (!em.data(outbuf.data(), got, error)) return false;
                }
                if (rc == Z_STREAM_END) done = true;
                else if (rc == Z_BUF_ERROR && got == 0 && z.avail_in == 0 && left == 0) {
                    error = "zip: entry '" + path + "': deflate stream ends early";
                    return false;
                }
            }
#else
            error = "zip: deflate needs zlib, which this build lacks; use a plain .tar";
            return false;
#endif
        }
        if (produced != usize) {
            error = "zip: entry '" + path + "': size mismatch";
            return false;
        }
#ifdef AGENSIO_HAS_ZLIB
        if (running != crc) {
            error = "zip: entry '" + path + "': CRC mismatch";
            return false;
        }
#endif
        if (!em.end_file(error)) return false;
    }
    return true;
}

}  // namespace

bool extract(Source& in, Sink& out, const Limits& limits, Summary& summary, std::string& error) {
    summary = Summary{};
    error.clear();
    char head[512];
    std::size_t got = 0;
    if (!in.read_at(0, head, sizeof head, got)) {
        error = "read error";
        return false;
    }
    Emitter em(out, limits, summary);
    switch (sniff(std::string_view(head, got))) {
        case Format::tar: {
            PlainStream s(in);
            return tar_extract(s, em, error);
        }
        case Format::gzip: {
#ifdef AGENSIO_HAS_ZLIB
            GzipStream s(in);
            return tar_extract(s, em, error);
#else
            error = "gzip needs zlib, which this build lacks; use a plain .tar";
            return false;
#endif
        }
        case Format::zip:
            return zip_extract(in, em, error);
        default:
            error = "not a tar, tar.gz or zip archive";
            return false;
    }
}

#ifndef _WIN32

DirectorySink::~DirectorySink() {
    if (file_ >= 0) ::close(file_);
}

bool DirectorySink::make_dir(const std::string& path, std::string& error) {
    if (::mkdirat(dir_fd_, path.c_str(), dir_mode_ & 0777) == 0) {
        // The permission bits exact whatever the umask is, through a descriptor that never
        // follows a symlink. The set-gid bit is the kernel's: a set-gid parent hands it
        // down with its group, and a chmod by an account outside that group would clear
        // it, so the mode is only touched when the umask took bits away.
        const int d = ::openat(dir_fd_, path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat st {};
        if (d < 0 || ::fstat(d, &st) != 0) {
            error = path + ": " + std::strerror(errno);
            if (d >= 0) ::close(d);
            return false;
        }
        if ((st.st_mode & 0777) != (dir_mode_ & 0777) && ::fchmod(d, (dir_mode_ & 0777) | (st.st_mode & 02000)) != 0) {
            error = path + ": chmod: " + std::strerror(errno);
            ::close(d);
            return false;
        }
        ::close(d);
        return true;
    }
    if (errno == EEXIST) {
        struct stat st {};
        if (::fstatat(dir_fd_, path.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(st.st_mode)) return true;
        error = path + ": exists and is not a directory";
        return false;
    }
    error = path + ": " + std::strerror(errno);
    return false;
}

bool DirectorySink::ensure_parents(const std::string& path, std::string& error) {
    std::size_t slash = path.find('/');
    while (slash != std::string::npos) {
        if (!make_dir(path.substr(0, slash), error)) return false;
        slash = path.find('/', slash + 1);
    }
    return true;
}

bool DirectorySink::directory(const std::string& path, std::string& error) {
    return ensure_parents(path, error) && make_dir(path, error);
}

bool DirectorySink::begin_file(const std::string& path, bool executable, std::uint64_t, std::string& error) {
    if (file_ >= 0) {
        error = "internal: file already open";
        return false;
    }
    if (!ensure_parents(path, error)) return false;
    file_mode_ = (dir_mode_ & 0666) | (executable ? (dir_mode_ & 0111) : 0);  // never set-uid/gid on a file
    file_ = ::openat(dir_fd_, path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, file_mode_);
    if (file_ < 0) {
        error = path + ": " + (errno == EEXIST ? "exists already (duplicate entry or something in the way)" : std::strerror(errno));
        return false;
    }
    file_path_ = path;
    return true;
}

bool DirectorySink::data(const char* p, std::size_t n, std::string& error) {
    while (n > 0) {
        const ssize_t w = ::write(file_, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            error = file_path_ + ": write: " + std::strerror(errno);
            return false;
        }
        p += w;
        n -= static_cast<std::size_t>(w);
    }
    return true;
}

bool DirectorySink::end_file(std::string& error) {
    bool ok = true;
    if (::fchmod(file_, file_mode_) != 0) {
        error = file_path_ + ": chmod: " + std::strerror(errno);
        ok = false;
    }
    if (::close(file_) != 0 && ok) {
        error = file_path_ + ": close: " + std::strerror(errno);
        ok = false;
    }
    file_ = -1;
    return ok;
}

#endif

}  // namespace agensio::archive
