#include "file.hpp"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
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

void File::close() noexcept {
    if (fd_ >= 0) { _close(fd_); fd_ = -1; }
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

void File::close() noexcept {
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
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
    if (errno == EAGAIN || errno == EINTR) { r.would_block = true; return r; }
    r.sent = -1;
    return r;
#elif defined(__linux__)
    if (header_count > 0) { r.headers_unsupported = true; return r; }
    off_t off = static_cast<off_t>(offset);
    std::size_t chunk = static_cast<std::size_t>(count > 0x7ffff000u ? 0x7ffff000u : count);
    ssize_t n = ::sendfile(socket_fd, file.native_handle(), &off, chunk);
    if (n >= 0) { r.sent = n; return r; }
    if (errno == EAGAIN || errno == EINTR) { r.would_block = true; return r; }
    r.sent = -1;
    return r;
#else
    (void)socket_fd; (void)file; (void)offset; (void)count; (void)headers; (void)header_count;
    r.unsupported = true;
    return r;
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

}  // namespace agensio
