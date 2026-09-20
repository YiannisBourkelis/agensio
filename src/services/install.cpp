#include "services/install.hpp"

#include <cctype>
#include <cstring>
#include <string_view>
#include <vector>

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifdef AGENSIO_HAS_TLS
#include <openssl/evp.h>
#endif

#include "services/archive.hpp"
#include "services/fetch.hpp"

namespace agensio::install {

bool valid_upload_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > 128 || name.front() == '.') return false;
    for (unsigned char c : name)
        if (!(std::isalnum(c) || c == '.' || c == '_' || c == '-')) return false;
    return true;
}

bool valid_sha256(std::string_view hex) noexcept {
    if (hex.size() != 64) return false;
    for (unsigned char c : hex)
        if (!std::isxdigit(c)) return false;
    return true;
}

#ifndef _WIN32

namespace {

json::Value failure(const std::string& what) { return json::Value::object().set("ok", false).set("error", what); }

// The digest of a descriptor's whole content, hex; "" without OpenSSL.
std::string digest_of(int fd) {
#ifdef AGENSIO_HAS_TLS
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        if (ctx) EVP_MD_CTX_free(ctx);
        return "";
    }
    std::vector<char> buf(64 * 1024);
    off_t off = 0;
    for (;;) {
        const ssize_t n = ::pread(fd, buf.data(), buf.size(), off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        EVP_DigestUpdate(ctx, buf.data(), static_cast<std::size_t>(n));
        off += n;
    }
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned len = 0;
    EVP_DigestFinal_ex(ctx, out, &len);
    EVP_MD_CTX_free(ctx);
    static const char hex[] = "0123456789abcdef";
    std::string s;
    for (unsigned i = 0; i < len; ++i) {
        s.push_back(hex[out[i] >> 4]);
        s.push_back(hex[out[i] & 15]);
    }
    return s;
#else
    (void)fd;
    return "";
#endif
}

// Removes everything below an open directory (not the directory itself), never following
// a symlink: what a failed extraction left behind.
void clear_directory(int dir_fd) {
    const int dup = ::dup(dir_fd);
    if (dup < 0) return;
    DIR* d = ::fdopendir(dup);
    if (!d) {
        ::close(dup);
        return;
    }
    ::rewinddir(d);
    std::vector<std::string> names;
    while (const struct dirent* e = ::readdir(d)) {
        const std::string_view n = e->d_name;
        if (n != "." && n != "..") names.emplace_back(n);
    }
    for (const auto& n : names) {
        struct stat st {};
        if (::fstatat(dir_fd, n.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            const int child = ::openat(dir_fd, n.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child >= 0) {
                clear_directory(child);
                ::close(child);
            }
            ::unlinkat(dir_fd, n.c_str(), AT_REMOVEDIR);
        } else {
            ::unlinkat(dir_fd, n.c_str(), 0);
        }
    }
    ::closedir(d);  // closes dup
}

bool directory_empty(int dir_fd, bool& empty) {
    const int dup = ::dup(dir_fd);
    if (dup < 0) return false;
    DIR* d = ::fdopendir(dup);
    if (!d) {
        ::close(dup);
        return false;
    }
    ::rewinddir(d);
    empty = true;
    while (const struct dirent* e = ::readdir(d)) {
        const std::string_view n = e->d_name;
        if (n != "." && n != "..") {
            empty = false;
            break;
        }
    }
    ::closedir(d);
    return true;
}

// Moves the children of `top` up into the target and removes `top`; false, with nothing
// moved, when a child carries the same name as `top`.
bool unwrap(int dir_fd, const std::string& top, std::string& error) {
    const int tfd = ::openat(dir_fd, top.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (tfd < 0) {
        error = top + ": " + std::strerror(errno);
        return false;
    }
    DIR* d = ::fdopendir(::dup(tfd));
    std::vector<std::string> names;
    if (d) {
        ::rewinddir(d);
        while (const struct dirent* e = ::readdir(d)) {
            const std::string_view n = e->d_name;
            if (n != "." && n != "..") names.emplace_back(n);
        }
        ::closedir(d);
    }
    for (const auto& n : names)
        if (n == top) {
            ::close(tfd);
            error = "the top directory holds an entry of its own name";
            return false;
        }
    for (const auto& n : names) {
        if (::renameat(tfd, n.c_str(), dir_fd, n.c_str()) != 0) {
            error = "moving " + top + "/" + n + " up: " + std::strerror(errno);
            ::close(tfd);
            return false;
        }
    }
    ::close(tfd);
    if (::unlinkat(dir_fd, top.c_str(), AT_REMOVEDIR) != 0) {
        error = "removing the unwrapped " + top + ": " + std::strerror(errno);
        return false;
    }
    return true;
}

}  // namespace

json::Value execute(const Request& req) {
    if (req.url.empty() == (req.upload_fd < 0)) return failure("give exactly one source: a url or an uploaded file");
    if (!req.sha256.empty() && !valid_sha256(req.sha256)) return failure("sha256 must be 64 hex digits");
    const int dir_fd = ::open(req.target.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir_fd < 0) {
        // O_NOFOLLOW on a symlink is ELOOP, or ENOTDIR when O_DIRECTORY is set as well (Linux).
        struct stat ls {};
        const bool link = (errno == ELOOP || errno == ENOTDIR) && ::lstat(req.target.c_str(), &ls) == 0 && S_ISLNK(ls.st_mode);
        return failure("target " + req.target + ": " + (link ? "is a symlink; refused" : std::strerror(errno)));
    }
    struct stat st {};
    if (::fstat(dir_fd, &st) != 0) {
        ::close(dir_fd);
        return failure("target " + req.target + ": " + std::strerror(errno));
    }
    if (st.st_uid != ::geteuid()) {
        ::close(dir_fd);
        return failure("target " + req.target + " belongs to uid " + std::to_string(st.st_uid) + ", not to the account installing (uid " +
                       std::to_string(::geteuid()) + "); refused");
    }
    bool empty = false;
    if (!directory_empty(dir_fd, empty)) {
        ::close(dir_fd);
        return failure("target " + req.target + ": cannot list it");
    }
    if (!empty) {
        ::close(dir_fd);
        return failure("target " + req.target + " is not empty; an application is installed only into an empty directory");
    }
    // The archive: the upload as given, or a download into an unlinked temporary file in
    // the target itself (same filesystem, the account's own space, gone with the descriptor).
    int archive_fd = req.upload_fd;
    std::uint64_t downloaded = 0;
    std::string final_url;
    if (!req.url.empty()) {
        archive_fd = ::openat(dir_fd, ".agensio-download", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (archive_fd < 0) {
            const std::string why = std::strerror(errno);
            ::close(dir_fd);
            return failure("cannot create a temporary file in " + req.target + ": " + why);
        }
        ::unlinkat(dir_fd, ".agensio-download", 0);
        fetch::Options opts;
        opts.max_bytes = req.max_download;
        opts.allow_private = req.allow_private;
        opts.ca_file = req.ca_file;
        fetch::Result r;
        std::string error;
        const bool ok = fetch::https_get(req.url, opts, [&](const char* p, std::size_t n, std::string& err) {
            while (n > 0) {
                const ssize_t w = ::write(archive_fd, p, n);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    err = std::string("writing the download: ") + std::strerror(errno);
                    return false;
                }
                p += w;
                n -= static_cast<std::size_t>(w);
            }
            return true;
        }, r, error);
        if (!ok) {
            ::close(archive_fd);
            ::close(dir_fd);
            return failure("download: " + error);
        }
        downloaded = r.bytes;
        final_url = r.final_url;
    }
    const std::string digest = digest_of(archive_fd);
    if (!req.sha256.empty()) {
        std::string want = req.sha256;
        for (auto& c : want) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (digest.empty()) {
            if (archive_fd != req.upload_fd) ::close(archive_fd);
            ::close(dir_fd);
            return failure("this build cannot compute sha256 (no OpenSSL); drop the check or use a build with TLS");
        }
        if (digest != want) {
            if (archive_fd != req.upload_fd) ::close(archive_fd);
            ::close(dir_fd);
            return failure("sha256 mismatch: the archive is " + digest + ", expected " + want + "; nothing installed");
        }
    }
    archive::FdSource source(archive_fd);
    archive::DirectorySink sink(dir_fd, st.st_mode & 0777);
    archive::Limits limits;
    archive::Summary summary;
    std::string error;
    const bool ok = archive::extract(source, sink, limits, summary, error);
    if (archive_fd != req.upload_fd) ::close(archive_fd);
    if (!ok) {
        clear_directory(dir_fd);
        ::close(dir_fd);
        return failure("archive refused: " + error + "; the directory is empty again");
    }
    json::Value result = json::Value::object().set("ok", true)
                             .set("files", static_cast<double>(summary.files))
                             .set("directories", static_cast<double>(summary.directories))
                             .set("bytes", static_cast<double>(summary.bytes))
                             .set("downloaded", static_cast<double>(downloaded))
                             .set("sha256", digest);
    if (!final_url.empty()) result.set("url", final_url);
    const bool unwrap_it = req.strip == 1 || (req.strip < 0 && summary.single_top && summary.files > 0);
    if (unwrap_it && !summary.top.empty() && summary.single_top) {
        std::string why;
        if (unwrap(dir_fd, summary.top, why)) result.set("unwrapped", summary.top);
        else result.set("warning", "kept the top directory " + summary.top + ": " + why);
    } else if (req.strip == 1) {
        result.set("warning", "strip requested but the archive has no single top directory; kept as is");
    }
    ::close(dir_fd);
    return result;
}

#else
json::Value execute(const Request&) { return json::Value::object().set("ok", false).set("error", "not available on this platform"); }
#endif

}  // namespace agensio::install
