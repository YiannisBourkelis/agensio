#include "file.hpp"

#ifdef _WIN32
#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>
#else
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/uio.h>  // preadv
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#elif defined(__linux__)
#include <sys/sendfile.h>
#elif defined(__FreeBSD__)
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#endif
#endif

namespace agensio {

#ifdef _WIN32

bool stat_path(const char* path, FileInfo& out) noexcept {
    struct __stat64 st;
    if (_stat64(path, &st) != 0) return false;
    out.size = static_cast<std::uint64_t>(st.st_size);
    out.mtime = static_cast<std::int64_t>(st.st_mtime);
    out.is_regular = (st.st_mode & _S_IFREG) != 0;
    out.is_directory = (st.st_mode & _S_IFDIR) != 0;
    return true;
}

File File::open(const char* path) noexcept {
    File f;
    int fd = -1;
    if (_sopen_s(&fd, path, _O_RDONLY | _O_BINARY, _SH_DENYNO, 0) != 0) return f;
    f.fd_ = fd;
    return f;
}

File File::temporary() noexcept {
    File f;
    char path[L_tmpnam_s];
    if (tmpnam_s(path, sizeof(path)) != 0) return f;
    int fd = -1;
    if (_sopen_s(&fd, path, _O_RDWR | _O_CREAT | _O_EXCL | _O_BINARY | _O_TEMPORARY, _SH_DENYRW,
                 _S_IREAD | _S_IWRITE) != 0)
        return f;
    f.fd_ = fd;
    return f;
}

bool File::append(const void* data, std::size_t len) noexcept {
    const char* p = static_cast<const char*>(data);
    while (len > 0) {
        const int n = _write(fd_, p, static_cast<unsigned>(len));
        if (n < 0) return false;
        p += n;
        len -= static_cast<std::size_t>(n);
    }
    return true;
}

bool File::info(FileInfo& out) const noexcept {
    struct __stat64 st;
    if (_fstat64(fd_, &st) != 0) return false;
    out.size = static_cast<std::uint64_t>(st.st_size);
    out.mtime = static_cast<std::int64_t>(st.st_mtime);
    out.is_regular = (st.st_mode & _S_IFREG) != 0;
    out.is_directory = (st.st_mode & _S_IFDIR) != 0;
    return true;
}

std::int64_t File::read_at(void* buf, std::size_t len, std::uint64_t offset) const noexcept {
    if (_lseeki64(fd_, static_cast<__int64>(offset), SEEK_SET) < 0) return -1;
    int n = _read(fd_, buf, static_cast<unsigned>(len));
    return n;
}

std::int64_t File::read_at(const MutSlice* slices, int count, std::uint64_t offset) const noexcept {
    std::int64_t total = 0;
    for (int i = 0; i < count; ++i) {
        const std::int64_t n = read_at(slices[i].data, slices[i].len, offset + static_cast<std::uint64_t>(total));
        if (n < 0) return total > 0 ? total : -1;
        total += n;
        if (static_cast<std::size_t>(n) < slices[i].len) break;
    }
    return total;
}

void File::close() noexcept {
    if (fd_ >= 0) {
        _close(fd_);
        fd_ = -1;
    }
}

#else

namespace {
void fill(const struct stat& st, FileInfo& out) noexcept {
    out.size = static_cast<std::uint64_t>(st.st_size);
    out.mtime = static_cast<std::int64_t>(st.st_mtime);
    out.is_regular = S_ISREG(st.st_mode);
    out.is_directory = S_ISDIR(st.st_mode);
}
}  // namespace

bool stat_path(const char* path, FileInfo& out) noexcept {
    struct stat st;
    if (::stat(path, &st) != 0) return false;
    fill(st, out);
    return true;
}

File File::open(const char* path) noexcept {
    File f;
    f.fd_ = ::open(path, O_RDONLY | O_CLOEXEC);
    return f;
}

File File::temporary() noexcept {
    File f;
    const char* dir = std::getenv("TMPDIR");
    if (!dir || !*dir) dir = "/tmp";
#ifdef O_TMPFILE
    f.fd_ = ::open(dir, O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    if (f.fd_ >= 0) return f;
#endif
    std::string tmpl = std::string(dir) + "/agensio-XXXXXX";
    f.fd_ = ::mkstemp(tmpl.data());
    if (f.fd_ >= 0) ::unlink(tmpl.c_str());
    return f;
}

bool File::append(const void* data, std::size_t len) noexcept {
    const char* p = static_cast<const char*>(data);
    while (len > 0) {
        const ssize_t n = ::write(fd_, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += n;
        len -= static_cast<std::size_t>(n);
    }
    return true;
}

bool File::info(FileInfo& out) const noexcept {
    struct stat st;
    if (::fstat(fd_, &st) != 0) return false;
    fill(st, out);
    return true;
}

std::int64_t File::read_at(void* buf, std::size_t len, std::uint64_t offset) const noexcept {
    for (;;) {
        ssize_t n = ::pread(fd_, buf, len, static_cast<off_t>(offset));
        if (n < 0 && errno == EINTR) continue;
        return n;
    }
}

std::int64_t File::read_at(const MutSlice* slices, int count, std::uint64_t offset) const noexcept {
    struct iovec iov[16];
    if (count > 16) count = 16;
    for (int i = 0; i < count; ++i) {
        iov[i].iov_base = slices[i].data;
        iov[i].iov_len = slices[i].len;
    }
    for (;;) {
        const ssize_t n = ::preadv(fd_, iov, count, static_cast<off_t>(offset));
        if (n < 0 && errno == EINTR) continue;
        return n;
    }
}

void File::close() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

#endif

SendFileResult send_file(int socket_fd, const File& file, std::uint64_t offset, std::uint64_t count,
                         const IoSlice* headers, int header_count) noexcept {
    SendFileResult r;
#if defined(__APPLE__) || defined(__FreeBSD__)
    struct iovec iov[8];
    if (header_count > 8) header_count = 8;
    std::size_t header_bytes = 0;
    for (int i = 0; i < header_count; ++i) {
        iov[i].iov_base = const_cast<void*>(headers[i].data);
        iov[i].iov_len = headers[i].len;
        header_bytes += headers[i].len;
    }
    struct sf_hdtr hdtr{};
    hdtr.headers = iov;
    hdtr.hdr_cnt = header_count;
#if defined(__APPLE__)
    off_t len = static_cast<off_t>(count + header_bytes);  // with headers: max header+file bytes
    int rc = ::sendfile(file.native_handle(), socket_fd, static_cast<off_t>(offset), &len,
                        header_count > 0 ? &hdtr : nullptr, 0);
    r.sent = static_cast<std::int64_t>(len);
#else
    off_t sbytes = 0;
    int rc = ::sendfile(file.native_handle(), socket_fd, static_cast<off_t>(offset), static_cast<std::size_t>(count),
                        header_count > 0 ? &hdtr : nullptr, &sbytes, 0);
    r.sent = static_cast<std::int64_t>(sbytes);
#endif
    if (rc == 0) return r;
    if (errno == EAGAIN || errno == EINTR) {
        r.would_block = true;
        return r;
    }
    r.sent = -1;
    return r;
#elif defined(__linux__)
    if (header_count > 0) {
        r.headers_unsupported = true;
        return r;
    }
    off_t off = static_cast<off_t>(offset);
    std::size_t chunk = static_cast<std::size_t>(count > 0x7ffff000u ? 0x7ffff000u : count);
    ssize_t n = ::sendfile(socket_fd, file.native_handle(), &off, chunk);
    if (n >= 0) {
        r.sent = n;
        return r;
    }
    if (errno == EAGAIN || errno == EINTR) {
        r.would_block = true;
        return r;
    }
    r.sent = -1;
    return r;
#else
    (void)socket_fd;
    (void)file;
    (void)offset;
    (void)count;
    (void)headers;
    (void)header_count;
    r.unsupported = true;
    return r;
#endif
}

void set_tcp_cork(int socket_fd, bool on) noexcept {
#if defined(__linux__)
    int v = on ? 1 : 0;
    ::setsockopt(socket_fd, IPPROTO_TCP, TCP_CORK, &v, sizeof v);
#elif defined(__APPLE__) || defined(__FreeBSD__)
    int v = on ? 1 : 0;
    ::setsockopt(socket_fd, IPPROTO_TCP, TCP_NOPUSH, &v, sizeof v);
#else
    (void)socket_fd;
    (void)on;
#endif
}

std::uint64_t raise_open_file_limit() noexcept {
#ifdef _WIN32
    return 0;
#else
    struct rlimit rl{};
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
    rlim_t target = rl.rlim_max;
#ifdef __APPLE__
    if (target == RLIM_INFINITY || target > 1048576) target = 1048576;  // macOS refuses larger soft limits
#endif
    if (rl.rlim_cur < target) {
        rl.rlim_cur = target;
        ::setrlimit(RLIMIT_NOFILE, &rl);
        ::getrlimit(RLIMIT_NOFILE, &rl);
    }
    return static_cast<std::uint64_t>(rl.rlim_cur);
#endif
}

bool path_within_root(const char* path, std::string_view root) noexcept {
#ifdef _WIN32
    (void)path;
    (void)root;
    return true;  // TODO(windows): GetFinalPathNameByHandle; symlinks = "deny" is refused at config load
#else
    char resolved[PATH_MAX];
    if (::realpath(path, resolved) == nullptr) return false;
    std::string_view r(resolved);
    if (r.size() < root.size() || r.compare(0, root.size(), root) != 0) return false;
    return r.size() == root.size() || r[root.size()] == '/' || root == "/";
#endif
}

bool File::read_all(void* buf, std::size_t len) const noexcept {
    std::size_t done = 0;
    char* p = static_cast<char*>(buf);
    while (done < len) {
        std::int64_t n = read_at(p + done, len - done, done);
        if (n <= 0) return false;
        done += static_cast<std::size_t>(n);
    }
    return true;
}


std::string write_file_atomic(const std::string& path, std::string_view text, unsigned mode) {
#ifdef _WIN32
    // Not a host whose root loads these files; whole or not at all still holds for the reader.
    (void)mode;
    const std::string tmp = path + ".agensio-tmp";
    std::FILE* f = std::fopen(tmp.c_str(), "wb");
    if (!f) return "cannot write " + path;
    const bool ok = std::fwrite(text.data(), 1, text.size(), f) == text.size();
    if (std::fclose(f) != 0 || !ok) {
        std::remove(tmp.c_str());
        return "cannot write " + path;
    }
    std::remove(path.c_str());
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        return "cannot replace " + path;
    }
    return {};
#else
    const std::size_t slash = path.rfind('/');
    const std::string dir = slash == std::string::npos ? std::string(".") : slash == 0 ? std::string("/") : path.substr(0, slash);
    const std::string base = slash == std::string::npos ? path : path.substr(slash + 1);
    if (base.empty() || base == "." || base == "..") return "cannot write " + path + ": not a file name";
    // Beside the target, so the rename stays on one filesystem and is atomic; hidden; created with
    // O_EXCL and O_NOFOLLOW, so nothing that already stands at the name (a planted link) is written
    // through; the mode set with fchmod, whatever the umask took from it.
    std::string tmp;
    int fd = -1;
    for (unsigned n = 0; n < 100 && fd < 0; ++n) {
        tmp = dir + "/." + base + ".agensio-" + std::to_string(::getpid()) + "-" + std::to_string(n);
        fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, static_cast<mode_t>(mode & 07777));
        if (fd < 0 && errno != EEXIST) return "cannot write " + path + ": " + std::strerror(errno);
    }
    if (fd < 0) return "cannot write " + path + ": no free temporary name beside it";
    auto fail = [&](const char* step) {
        const std::string why = "cannot write " + path + ": " + step + ": " + std::strerror(errno);
        if (fd >= 0) ::close(fd);
        ::unlink(tmp.c_str());
        return why;
    };
    if (::fchmod(fd, static_cast<mode_t>(mode & 07777)) != 0) return fail("chmod");
    for (std::size_t done = 0; done < text.size();) {
        const ssize_t n = ::write(fd, text.data() + done, text.size() - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return fail("write");
        }
        done += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0) return fail("fsync");
    const int closed = ::close(fd);
    fd = -1;
    if (closed != 0) return fail("close");
    if (::rename(tmp.c_str(), path.c_str()) != 0) return fail("rename");
    // The directory entry too, so the new file is the one found after a crash.
    if (const int d = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC); d >= 0) {
        ::fsync(d);
        ::close(d);
    }
    return {};
#endif
}

}  // namespace agensio
