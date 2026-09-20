#include "services/install.hpp"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string_view>
#include <vector>

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
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

// The name of the executing account, for the answer.
std::string account_name() {
    if (const struct passwd* pw = ::getpwuid(::geteuid())) return pw->pw_name;
    return "uid " + std::to_string(::geteuid());
}

std::string mode_text(mode_t mode) {
    char buf[8];
    std::snprintf(buf, sizeof buf, "%04o", static_cast<unsigned>(mode & 07777));
    return buf;
}

std::string group_name(gid_t gid) {
    if (const struct group* gr = ::getgrgid(gid)) return gr->gr_name;
    return std::to_string(gid);
}

// Removes the directories a call created, deepest first; they are empty or were emptied.
void remove_created(const std::vector<std::string>& created) {
    for (auto it = created.rbegin(); it != created.rend(); ++it) ::rmdir(it->c_str());
}

// Why an openat(O_DIRECTORY | O_NOFOLLOW) failed, in words: a symlink is named as such.
std::string open_failure(int parent_fd, const std::string& name, const std::string& path) {
    const int e = errno;
    struct stat ls {};
    if ((e == ELOOP || e == ENOTDIR) && ::fstatat(parent_fd, name.c_str(), &ls, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(ls.st_mode))
        return path + " is a symlink; refused";
    return path + ": " + std::strerror(e);
}

}  // namespace

json::Value execute(const Request& req) {
    if (req.url.empty() == (req.upload_fd < 0)) return failure("give exactly one source: a url or an uploaded file");
    if (!req.sha256.empty() && !valid_sha256(req.sha256)) return failure("sha256 must be 64 hex digits");
    if (req.site_root.empty() || req.site_root.front() != '/') return failure("no site directory");
    if (!(req.target == req.site_root || (req.target.size() > req.site_root.size() && req.target.compare(0, req.site_root.size(), req.site_root) == 0 &&
                                          req.target[req.site_root.size()] == '/')))
        return failure("target " + req.target + " is not below the site's directory " + req.site_root);
    const uid_t me = ::geteuid();
    // The walk: the site's directory first, then every component of the target below it,
    // each opened without following symlinks and owned by this account. A missing one is
    // created with create_path (as this account, the parent's permission bits, the
    // set-gid bit and group handed down by the kernel) or ends the call.
    int cur = ::open(req.site_root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cur < 0) return failure("site directory " + open_failure(AT_FDCWD, req.site_root, req.site_root));
    struct stat st {};
    if (::fstat(cur, &st) != 0 || st.st_uid != me) {
        const std::string why = st.st_uid != me ? "belongs to uid " + std::to_string(st.st_uid) + ", not to the account installing (" + account_name() + "); refused" : std::strerror(errno);
        ::close(cur);
        return failure("site directory " + req.site_root + " " + why);
    }
    std::vector<std::string> created, would_create;
    std::string so_far = req.site_root;
    std::string rel = req.target.size() > req.site_root.size() ? req.target.substr(req.site_root.size() + 1) : "";
    auto fail_walk = [&](const std::string& what) {
        ::close(cur);
        remove_created(created);
        return failure(what);
    };
    std::size_t pos = 0;
    while (pos < rel.size()) {
        const std::size_t slash = rel.find('/', pos);
        const std::string part = rel.substr(pos, slash == std::string::npos ? std::string::npos : slash - pos);
        pos = slash == std::string::npos ? rel.size() : slash + 1;
        if (part.empty() || part == "." || part == "..") return fail_walk("target " + req.target + ": '" + part + "' in the path; refused");
        const std::string path = so_far + "/" + part;
        if (!would_create.empty()) {  // a dry run past the first missing component: the rest would be created too
            would_create.push_back(path);
            so_far = path;
            continue;
        }
        int child = ::openat(cur, part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0 && errno == ENOENT) {
            if (!req.create_path)
                return fail_walk("target " + path + " does not exist; send create_path: true to create it (as " + account_name() + ", below " + req.site_root + ")");
            if (req.dry_run) {
                would_create.push_back(path);
                so_far = path;
                continue;
            }
            struct stat parent {};
            ::fstat(cur, &parent);
            if (::mkdirat(cur, part.c_str(), parent.st_mode & 0777) != 0)
                return fail_walk(path + (errno == EEXIST ? " appeared meanwhile; refused (send the command again)" : std::string(": ") + std::strerror(errno)));
            created.push_back(path);
            child = ::openat(cur, part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0) return fail_walk(open_failure(cur, part, path));
            struct stat made {};
            if (::fstat(child, &made) != 0 || made.st_uid != me) {
                ::close(child);
                return fail_walk(path + " was not created by this account; refused");
            }
            if ((made.st_mode & 0777) != (parent.st_mode & 0777) && ::fchmod(child, (parent.st_mode & 0777) | (made.st_mode & 02000)) != 0) {
                ::close(child);
                return fail_walk(path + ": chmod: " + std::strerror(errno));
            }
        } else if (child < 0) {
            return fail_walk(open_failure(cur, part, path));
        } else {
            struct stat cs {};
            if (::fstat(child, &cs) != 0 || cs.st_uid != me) {
                const std::string why = cs.st_uid != me ? " belongs to uid " + std::to_string(cs.st_uid) + ", another account; refused" : std::string(": ") + std::strerror(errno);
                ::close(child);
                return fail_walk(path + why);
            }
        }
        ::close(cur);
        cur = child;
        so_far = path;
    }
    const int dir_fd = cur;
    if (would_create.empty()) {
        if (::fstat(dir_fd, &st) != 0) return fail_walk("target " + req.target + ": " + std::strerror(errno));
        bool empty = false;
        if (!directory_empty(dir_fd, empty)) return fail_walk("target " + req.target + ": cannot list it");
        if (!empty) return fail_walk("target " + req.target + " is not empty; an application is installed only into an empty directory");
    }
    json::Value created_json = json::Value::array();
    for (const auto& c : created) {
        struct stat cs {};
        ::stat(c.c_str(), &cs);
        created_json.push(json::Value::object().set("path", c).set("owner", account_name() + ":" + group_name(cs.st_gid)).set("mode", mode_text(cs.st_mode)));
    }
    if (req.dry_run) {
        ::close(dir_fd);
        json::Value wc = json::Value::array();
        for (const auto& w : would_create) wc.push(w);
        return json::Value::object().set("ok", true).set("dry_run", true).set("target", req.target).set("as", account_name()).set("would_create", wc);
    }
    // From here on, a failure empties the target and removes what was created.
    auto fail_install = [&](const std::string& what) {
        clear_directory(dir_fd);
        ::close(dir_fd);
        remove_created(created);
        return failure(what);
    };
    // The archive: the upload as given, or a download into an unlinked temporary file in
    // the target itself (same filesystem, the account's own space, gone with the descriptor).
    int archive_fd = req.upload_fd;
    std::uint64_t downloaded = 0;
    std::string final_url;
    if (!req.url.empty()) {
        archive_fd = ::openat(dir_fd, ".agensio-download", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (archive_fd < 0) return fail_install("cannot create a temporary file in " + req.target + ": " + std::strerror(errno));
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
            return fail_install("download: " + error);
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
            return fail_install("this build cannot compute sha256 (no OpenSSL); drop the check or use a build with TLS");
        }
        if (digest != want) {
            if (archive_fd != req.upload_fd) ::close(archive_fd);
            return fail_install("sha256 mismatch: the archive is " + digest + ", expected " + want + "; nothing installed");
        }
    }
    archive::FdSource source(archive_fd);
    archive::DirectorySink sink(dir_fd, st.st_mode & 0777);
    archive::Limits limits;
    archive::Summary summary;
    std::string error;
    const bool ok = archive::extract(source, sink, limits, summary, error);
    if (archive_fd != req.upload_fd) ::close(archive_fd);
    if (!ok) return fail_install("archive refused: " + error + "; " + (created.empty() ? "the directory is empty again" : "the directories created for it are gone again"));
    json::Value result = json::Value::object().set("ok", true).set("as", account_name()).set("target", req.target).set("created", created_json)
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

namespace {

// Opens the directory `rel` (cleaned, "" for the root itself) below an open site root,
// component by component, never through a symlink, every component the account's.
// -1 with `error`; `missing` says the failure was a component that does not exist.
int walk_dirs(int root_fd, const std::string& root_path, const std::string& rel, std::string& error, bool& missing) {
    missing = false;
    int cur = ::dup(root_fd);
    if (cur < 0) {
        error = std::strerror(errno);
        return -1;
    }
    std::string so_far = root_path;
    std::size_t pos = 0;
    while (pos < rel.size()) {
        const std::size_t slash = rel.find('/', pos);
        const std::string part = rel.substr(pos, slash == std::string::npos ? std::string::npos : slash - pos);
        pos = slash == std::string::npos ? rel.size() : slash + 1;
        if (part.empty()) continue;
        const std::string path = so_far + "/" + part;
        const int child = ::openat(cur, part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0) {
            missing = errno == ENOENT;
            error = missing ? path + " does not exist" : open_failure(cur, part, path);
            ::close(cur);
            return -1;
        }
        struct stat st {};
        if (::fstat(child, &st) != 0 || st.st_uid != ::geteuid()) {
            error = st.st_uid != ::geteuid() ? path + " belongs to uid " + std::to_string(st.st_uid) + ", another account; refused" : path + ": " + std::strerror(errno);
            ::close(child);
            ::close(cur);
            return -1;
        }
        ::close(cur);
        cur = child;
        so_far = path;
    }
    return cur;
}

void split_leaf(const std::string& rel, std::string& dir, std::string& leaf) {
    const std::size_t slash = rel.rfind('/');
    dir = slash == std::string::npos ? "" : rel.substr(0, slash);
    leaf = slash == std::string::npos ? rel : rel.substr(slash + 1);
}

}  // namespace

json::Value copy_file(const CopyRequest& req) {
    std::string cf, ct, why;
    if (!archive::clean_path(req.from, cf, why) || cf != req.from) return failure("from: " + (why.empty() ? "not a clean relative path" : why));
    if (!archive::clean_path(req.to, ct, why) || ct != req.to) return failure("to: " + (why.empty() ? "not a clean relative path" : why));
    if (cf == ct) return failure("from and to are the same path");
    if (req.site_root.empty() || req.site_root.front() != '/') return failure("no site directory");
    const uid_t me = ::geteuid();
    const int root_fd = ::open(req.site_root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root_fd < 0) return failure("site directory " + open_failure(AT_FDCWD, req.site_root, req.site_root));
    struct stat rs {};
    if (::fstat(root_fd, &rs) != 0 || rs.st_uid != me) {
        ::close(root_fd);
        return failure("site directory " + req.site_root + " belongs to uid " + std::to_string(rs.st_uid) + ", not to the account copying (" + account_name() + "); refused");
    }
    const std::string from_abs = req.site_root + "/" + cf, to_abs = req.site_root + "/" + ct;
    // The source: a regular file reached without following a symlink.
    std::string fdir, fleaf, tdir, tleaf, error;
    split_leaf(cf, fdir, fleaf);
    split_leaf(ct, tdir, tleaf);
    bool missing = false;
    const int from_dir = walk_dirs(root_fd, req.site_root, fdir, error, missing);
    if (from_dir < 0) {
        ::close(root_fd);
        return failure("from: " + error);
    }
    const int src = ::openat(from_dir, fleaf.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (src < 0) {
        const std::string what = errno == ENOENT ? from_abs + " does not exist" : open_failure(from_dir, fleaf, from_abs);
        ::close(from_dir);
        ::close(root_fd);
        return failure("from: " + what);
    }
    ::close(from_dir);
    struct stat ss {};
    if (::fstat(src, &ss) != 0 || !S_ISREG(ss.st_mode)) {
        ::close(src);
        ::close(root_fd);
        return failure("from: " + from_abs + (S_ISDIR(ss.st_mode) ? " is a directory; only a single regular file is copied" : " is not a regular file; refused"));
    }
    if (static_cast<std::uint64_t>(ss.st_size) > req.max_bytes) {
        ::close(src);
        ::close(root_fd);
        return failure("from: " + from_abs + " is " + std::to_string(ss.st_size) + " bytes, above the limit of " + std::to_string(req.max_bytes));
    }
    // The destination: its parent must exist (create_path is site-install's job), the
    // leaf must not, unless overwrite; a symlink or a directory there is refused outright.
    const int to_dir = walk_dirs(root_fd, req.site_root, tdir, error, missing);
    ::close(root_fd);
    if (to_dir < 0) {
        ::close(src);
        return failure("to: " + error + (missing ? " (create it first with site-install --create-path)" : ""));
    }
    struct stat ds {}, es {};
    ::fstat(to_dir, &ds);
    json::Value replaced;
    if (::fstatat(to_dir, tleaf.c_str(), &es, AT_SYMLINK_NOFOLLOW) == 0) {
        std::string what;
        if (S_ISLNK(es.st_mode)) what = to_abs + " is a symlink; refused";
        else if (S_ISDIR(es.st_mode)) what = to_abs + " is a directory; refused";
        else if (!S_ISREG(es.st_mode)) what = to_abs + " is not a regular file; refused";
        else if (es.st_dev == ss.st_dev && es.st_ino == ss.st_ino) what = to_abs + " is the same file as the source";
        else if (!req.overwrite) what = to_abs + " exists; send overwrite: true to replace it";
        if (!what.empty()) {
            ::close(to_dir);
            ::close(src);
            return failure("to: " + what);
        }
        char stamp[32];
        std::tm tm{};
        ::localtime_r(&es.st_mtime, &tm);
        std::strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%S", &tm);
        replaced = json::Value::object().set("bytes", static_cast<double>(es.st_size)).set("mtime", stamp);
    } else if (errno != ENOENT) {
        const std::string what = std::strerror(errno);
        ::close(to_dir);
        ::close(src);
        return failure("to: " + to_abs + ": " + what);
    }
    const unsigned mode = (ds.st_mode & 0666) | ((ss.st_mode & 0111) ? (ds.st_mode & 0111) : 0);
    if (req.dry_run) {
        ::close(to_dir);
        ::close(src);
        json::Value v = json::Value::object().set("ok", true).set("dry_run", true).set("as", account_name()).set("from", from_abs).set("to", to_abs)
                            .set("bytes", static_cast<double>(ss.st_size)).set("mode", mode_text(mode));
        if (!replaced.is_null()) v.set("would_replace", replaced);
        return v;
    }
    // Written under a temporary name, then linked (no overwrite: an EEXIST here is the
    // race the check could not see) or renamed (overwrite) into place.
    const std::string tmp = ".agensio-copy." + std::to_string(::getpid());
    const int dst = ::openat(to_dir, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (dst < 0) {
        const std::string what = std::strerror(errno);
        ::close(to_dir);
        ::close(src);
        return failure("to: cannot create a temporary file next to " + to_abs + ": " + what);
    }
    auto abort_copy = [&](const std::string& what) {
        ::close(dst);
        ::unlinkat(to_dir, tmp.c_str(), 0);
        ::close(to_dir);
        ::close(src);
        return failure(what);
    };
    std::vector<char> buf(64 * 1024);
    std::uint64_t copied = 0;
    for (;;) {
        const ssize_t n = ::read(src, buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            return abort_copy("reading " + from_abs + ": " + std::strerror(errno));
        }
        if (n == 0) break;
        copied += static_cast<std::uint64_t>(n);
        if (copied > req.max_bytes) return abort_copy(from_abs + " grew past the limit while copying");
        const char* p = buf.data();
        std::size_t left = static_cast<std::size_t>(n);
        while (left > 0) {
            const ssize_t w = ::write(dst, p, left);
            if (w < 0) {
                if (errno == EINTR) continue;
                return abort_copy("writing " + to_abs + ": " + std::strerror(errno));
            }
            p += w;
            left -= static_cast<std::size_t>(w);
        }
    }
    if (::fchmod(dst, mode) != 0 || ::fsync(dst) != 0) return abort_copy(to_abs + ": " + std::strerror(errno));
    ::close(dst);
    const bool placed = replaced.is_null() ? ::linkat(to_dir, tmp.c_str(), to_dir, tleaf.c_str(), 0) == 0 : ::renameat(to_dir, tmp.c_str(), to_dir, tleaf.c_str()) == 0;
    if (!placed) {
        const std::string what = errno == EEXIST ? to_abs + " appeared meanwhile; refused (send overwrite: true to replace it)" : to_abs + ": " + std::strerror(errno);
        ::unlinkat(to_dir, tmp.c_str(), 0);
        ::close(to_dir);
        ::close(src);
        return failure("to: " + what);
    }
    if (replaced.is_null()) ::unlinkat(to_dir, tmp.c_str(), 0);
    ::close(to_dir);
    ::close(src);
    json::Value v = json::Value::object().set("ok", true).set("as", account_name()).set("from", from_abs).set("to", to_abs)
                        .set("bytes", static_cast<double>(copied)).set("mode", mode_text(mode));
    if (!replaced.is_null()) v.set("replaced", replaced);
    return v;
}

#else
json::Value execute(const Request&) { return json::Value::object().set("ok", false).set("error", "not available on this platform"); }
json::Value copy_file(const CopyRequest&) { return json::Value::object().set("ok", false).set("error", "not available on this platform"); }
#endif

}  // namespace agensio::install
