#include "services/files.hpp"

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <vector>

#ifdef AGENSIO_HAS_TLS
#include <openssl/evp.h>
#endif

#include "core/strings.hpp"
#include "services/archive.hpp"
#include "services/install.hpp"
#include "services/pools.hpp"

namespace agensio::files {

namespace {
constexpr char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}  // namespace

std::string base64_encode(std::string_view bytes) {
    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);
    std::size_t i = 0;
    for (; i + 2 < bytes.size(); i += 3) {
        const unsigned v = (static_cast<unsigned char>(bytes[i]) << 16) | (static_cast<unsigned char>(bytes[i + 1]) << 8) | static_cast<unsigned char>(bytes[i + 2]);
        out += {kB64[v >> 18], kB64[(v >> 12) & 63], kB64[(v >> 6) & 63], kB64[v & 63]};
    }
    if (i + 1 == bytes.size()) {
        const unsigned v = static_cast<unsigned char>(bytes[i]) << 16;
        out += {kB64[v >> 18], kB64[(v >> 12) & 63], '=', '='};
    } else if (i + 2 == bytes.size()) {
        const unsigned v = (static_cast<unsigned char>(bytes[i]) << 16) | (static_cast<unsigned char>(bytes[i + 1]) << 8);
        out += {kB64[v >> 18], kB64[(v >> 12) & 63], kB64[(v >> 6) & 63], '='};
    }
    return out;
}

std::optional<std::string> base64_decode(std::string_view text) {
    std::string out;
    unsigned buffer = 0;
    int bits = 0;
    std::size_t pad = 0;
    for (const char c : text) {
        if (c == '=') {
            ++pad;
            continue;
        }
        if (c == '\n' || c == '\r' || c == ' ') continue;
        if (pad) return std::nullopt;  // data after padding
        const char* at = std::strchr(kB64, c);
        if (!at || c == '\0') return std::nullopt;
        buffer = (buffer << 6) | static_cast<unsigned>(at - kB64);
        bits += 6;
        if (bits >= 8) {
            out.push_back(static_cast<char>((buffer >> (bits - 8)) & 0xff));
            bits -= 8;
        }
    }
    if (pad > 2) return std::nullopt;
    return out;
}

bool utf8_text(std::string_view bytes) noexcept {
    for (std::size_t i = 0; i < bytes.size();) {
        if (bytes[i] == '\0') return false;
        const std::size_t n = utf8_sequence(bytes, i);
        if (n == 0) return false;
        i += n;
    }
    return true;
}

std::string sha256_hex(std::string_view bytes) {
#ifdef AGENSIO_HAS_TLS
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned len = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), out, &len, EVP_sha256(), nullptr) != 1) return "";
    static constexpr char hex[] = "0123456789abcdef";
    std::string s;
    for (unsigned i = 0; i < len; ++i) {
        s.push_back(hex[out[i] >> 4]);
        s.push_back(hex[out[i] & 15]);
    }
    return s;
#else
    (void)bytes;
    return "";
#endif
}

bool secret_path(std::string_view rel, const std::vector<std::string>& secrets) noexcept {
    for (const auto& s : secrets)
        if (rel == s || (rel.size() > s.size() && rel.compare(0, s.size(), s) == 0 && (s.ends_with("/") || rel[s.size()] == '/'))) return true;
    std::size_t at = 0;
    while (at <= rel.size()) {
        const std::size_t end = std::min(rel.find('/', at), rel.size());
        const std::string_view part = rel.substr(at, end - at);
        if (part == ".git" || part.starts_with(".env")) return true;
        at = end + 1;
    }
    const std::size_t slash = rel.rfind('/');
    const std::string_view name = slash == std::string_view::npos ? rel : rel.substr(slash + 1);
    for (const std::string_view end : {".key", ".pem", ".sqlite", ".sqlite3", ".db"})
        if (name.size() > end.size() && name.ends_with(end)) return true;
    // SSH (2026-11-04, the grabloop.app report): anything below .ssh/, and the private keys' own names
    // (their .pub is public).
    for (std::size_t s = 0; s <= rel.size();) {
        const std::size_t e = std::min(rel.find('/', s), rel.size());
        if (rel.substr(s, e - s) == ".ssh") return true;
        s = e + 1;
    }
    for (const std::string_view key : {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk"})
        if (name == key) return true;
    return false;
}

bool private_key_head(std::string_view head) noexcept {
    if (head.starts_with("PuTTY-User-Key-File-")) return true;
    if (!head.starts_with("-----BEGIN ")) return false;
    const std::string_view first = head.substr(0, head.find('\n'));
    return first.find("PRIVATE KEY-----") != std::string_view::npos;
}

std::string parse(const json::Value& req, Op& out) {
    out = Op{};
    out.action = std::string(req.get("action"));
    static constexpr std::string_view kActions[] = {"list", "read", "write", "edit", "mkdir", "move", "delete", "history", "restore"};
    if (std::find(std::begin(kActions), std::end(kActions), out.action) == std::end(kActions))
        return "action must be list, read, write, edit, mkdir, move, delete, history or restore";
    out.site_root = std::string(req.get("site_root"));
    if (out.site_root.empty() || out.site_root.front() != '/') return "no site directory";
    std::string why;
    const auto clean = [&](const char* key, std::string& into, bool may_be_root) -> std::string {
        const json::Value& v = req[key];
        if (!v.is_null() && !v.is_string()) return std::string(key) + " must be a path";
        const std::string raw(v.is_string() ? v.str() : std::string());
        if (raw.empty() || raw == "." || raw == "/") {
            if (may_be_root) return into.clear(), std::string();
            return std::string(key) + " must name a path below the site's directory";
        }
        std::string c;
        const std::string_view r = raw.front() == '/' ? std::string_view(raw).substr(1) : std::string_view(raw);
        if (!archive::clean_path(r, c, why) || c.empty()) return std::string(key) + " must be a relative path below the site's directory, without '..': " + (why.empty() ? "not normalised" : why);
        into = c;
        return std::string();
    };
    if (std::string bad = clean("path", out.path, out.action == "list"); !bad.empty()) return bad;
    if (out.action == "move") {
        if (std::string bad = clean("to", out.to, false); !bad.empty()) return bad;
        if (out.to == out.path) return "from and to are the same path";
        if (out.to.size() > out.path.size() && out.to.compare(0, out.path.size(), out.path) == 0 && out.to[out.path.size()] == '/')
            return "to is inside from: a directory cannot move into itself";
    }
    for (const char* flag : {"overwrite", "executable", "parents", "recursive", "dry_run", "base64"}) {
        const json::Value& v = req[flag];
        if (!v.is_null() && v.type() != json::Value::Type::boolean) return std::string(flag) + " must be true or false";
    }
    out.overwrite = req["overwrite"].boolean();
    out.executable = req["executable"].boolean();
    out.parents = req["parents"].boolean();
    out.recursive = req["recursive"].boolean();
    out.dry_run = req["dry_run"].boolean();
    out.as_base64 = req["base64"].boolean();
    for (const char* n : {"offset", "tail"}) {
        const json::Value& v = req[n];
        if (v.is_null()) continue;
        if (v.type() != json::Value::Type::number || v.num() < 0 || v.num() > 1e15) return std::string(n) + " must be a number of bytes";
    }
    out.offset = static_cast<std::uint64_t>(req["offset"].num());
    out.tail = static_cast<std::uint64_t>(req["tail"].num());
    if (out.action == "write") {
        const json::Value& c = req["content"];
        if (!c.is_string()) return "content is the file's bytes, base64 between the server and the helper";
        const auto bytes = base64_decode(c.str());
        if (!bytes) return "content is not base64";
        if (bytes->size() > kContentMax) return "content is " + std::to_string(bytes->size()) + " bytes; at most " + std::to_string(kContentMax / 1024) + " KB a call (a larger file goes up with an upload and site_install)";
        out.content = *bytes;
    }
    if (out.action == "edit") {
        if (!req["old"].is_string() || req["old"].str().empty()) return "old is the text to replace, not empty";
        if (!req["new"].is_string()) return "new is the text that replaces it";
        out.old_text = req["old"].str();
        out.new_text = req["new"].str();
        if (out.old_text.size() > kContentMax || out.new_text.size() > kContentMax) return "old and new are at most " + std::to_string(kContentMax / 1024) + " KB";
    }
    out.if_sha256 = std::string(req.get("if_sha256"));
    if (!out.if_sha256.empty() && out.if_sha256 != "absent" && !install::valid_sha256(out.if_sha256)) return "if_sha256 is 64 hex digits, or \"absent\"";
    out.version = std::string(req.get("version"));
    if (out.action == "restore" && !history::valid_version(out.version)) return "version must be one site_file_history lists";
    for (const auto& s : req["secrets"].items()) {
        std::string c;
        if (!s.is_string() || !archive::clean_path(s.str(), c, why) || c != s.str()) return "secrets must be clean relative paths";
        out.secrets.push_back(c);
    }
    return "";
}

#ifndef _WIN32

namespace {

json::Value fail(const std::string& why) { return json::Value::object().set("ok", false).set("error", why); }

std::string iso(std::time_t t) {
    char buf[32];
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// The site's directory, the executing account's, opened without following a symlink.
int open_root(const Op& op, std::string& why) {
    const int fd = ::open(op.site_root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        why = "site directory " + op.site_root + ": " + std::strerror(errno);
        return -1;
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || st.st_uid != ::geteuid()) {
        ::close(fd);
        why = "site directory " + op.site_root + " belongs to uid " + std::to_string(st.st_uid) + ", not to " + install::executing_account() + "; refused";
        return -1;
    }
    return fd;
}

// The open parent directory of `rel`, and its leaf.
int open_parent(const Op& op, const std::string& rel, std::string& leaf, std::string& why, bool& missing) {
    const int root = open_root(op, why);
    if (root < 0) return -1;
    std::string dir;
    install::split_leaf(rel, dir, leaf);
    const int fd = install::walk_dirs(root, op.site_root, dir, why, missing);
    ::close(root);
    return fd;
}

// The whole content of a regular file, at most `max` bytes; false with why when larger or unreadable.
bool read_all(int fd, std::uint64_t max, std::string& out, std::string& why) {
    out.clear();
    char buf[65536];
    off_t at = 0;
    for (;;) {
        const ssize_t n = ::pread(fd, buf, sizeof buf, at);
        if (n < 0) {
            if (errno == EINTR) continue;
            why = std::strerror(errno);
            return false;
        }
        if (n == 0) return true;
        out.append(buf, static_cast<std::size_t>(n));
        at += n;
        if (out.size() > max) {
            why = "larger than " + std::to_string(max) + " bytes";
            return false;
        }
    }
}

std::string kind_of(const struct stat& st) {
    return S_ISREG(st.st_mode) ? "file" : S_ISDIR(st.st_mode) ? "directory" : S_ISLNK(st.st_mode) ? "symlink" : "other";
}

json::Value do_list(const Op& op) {
    std::string why;
    bool missing = false;
    const int root = open_root(op, why);
    if (root < 0) return fail(why);
    const int dfd = install::walk_dirs(root, op.site_root, op.path, why, missing);
    ::close(root);
    if (dfd < 0) return fail(why);
    DIR* d = ::fdopendir(dfd);
    if (!d) {
        ::close(dfd);
        return fail(std::strerror(errno));
    }
    struct Entry {
        std::string name;
        struct stat st;
    };
    std::vector<Entry> all;
    while (const struct dirent* e = ::readdir(d)) {
        const std::string_view n = e->d_name;
        if (n == "." || n == "..") continue;
        Entry en{std::string(n), {}};
        if (::fstatat(::dirfd(d), e->d_name, &en.st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        all.push_back(std::move(en));
    }
    std::sort(all.begin(), all.end(), [](const Entry& a, const Entry& b) { return a.name < b.name; });
    json::Value entries = json::Value::array();
    const uid_t me = ::geteuid();
    for (std::size_t i = 0; i < all.size() && i < kListMax; ++i) {
        const Entry& en = all[i];
        json::Value v = json::Value::object().set("name", en.name).set("type", kind_of(en.st)).set("size", static_cast<double>(en.st.st_size))
                            .set("mode", install::mode_string(en.st.st_mode & 07777)).set("mtime", iso(en.st.st_mtime)).set("owner_is_site", en.st.st_uid == me);
        if (S_ISLNK(en.st.st_mode)) {
            char target[4096];
            const ssize_t n = ::readlinkat(::dirfd(d), en.name.c_str(), target, sizeof target - 1);
            if (n > 0) v.set("target", std::string(target, static_cast<std::size_t>(n)));  // shown, never followed
        }
        if (secret_path(op.path.empty() ? en.name : op.path + "/" + en.name, op.secrets)) v.set("credentials", true);
        entries.push(std::move(v));
    }
    ::closedir(d);
    return json::Value::object().set("ok", true).set("as", install::executing_account()).set("path", op.site_root + (op.path.empty() ? "" : "/" + op.path))
        .set("entries", std::move(entries)).set("count", static_cast<double>(all.size())).set("truncated", all.size() > kListMax);
}

json::Value do_read(const Op& op) {
    std::string leaf, why;
    bool missing = false;
    const int dfd = open_parent(op, op.path, leaf, why, missing);
    if (dfd < 0) return fail(why);
    const std::string abs = op.site_root + "/" + op.path;
    const int fd = ::openat(dfd, leaf.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    const int e = errno;
    ::close(dfd);
    if (fd < 0) return fail(e == ENOENT ? abs + " does not exist" : e == ELOOP ? abs + " is a symlink; never followed" : abs + ": " + std::strerror(e));
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ::close(fd);
        return fail(abs + (S_ISDIR(st.st_mode) ? " is a directory: site_files_list lists it" : " is not a regular file"));
    }
    const std::uint64_t size = static_cast<std::uint64_t>(st.st_size);
    if (op.dry_run) {  // what a read would reveal, without its content (a secret's read waits for approval)
        ::close(fd);
        return json::Value::object().set("ok", true).set("dry_run", true).set("as", install::executing_account()).set("path", abs).set("size", static_cast<double>(size))
            .set("mode", install::mode_string(st.st_mode & 07777)).set("credentials", secret_path(op.path, op.secrets));
    }
    const std::uint64_t start = op.tail ? (op.tail >= size ? 0 : size - op.tail) : std::min(op.offset, size);
    const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(kContentMax, size - start));
    std::string part(want, '\0');
    std::size_t got = 0;
    while (got < want) {
        const ssize_t n = ::pread(fd, part.data() + got, want - got, static_cast<off_t>(start + got));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        got += static_cast<std::size_t>(n);
    }
    part.resize(got);
    std::string whole, digest;
    if (size <= kDigestMax && read_all(fd, kDigestMax, whole, why)) digest = sha256_hex(whole);
    char head[64];  // the first line says whether the file is a private key, whatever its name and the offset read
    const ssize_t head_n = ::pread(fd, head, sizeof head, 0);
    const bool key_file = head_n > 0 && private_key_head(std::string_view(head, static_cast<std::size_t>(head_n)));
    ::close(fd);
    const bool text = !op.as_base64 && utf8_text(part);
    return json::Value::object().set("ok", true).set("as", install::executing_account()).set("path", abs).set("size", static_cast<double>(size))
        .set("mode", install::mode_string(st.st_mode & 07777)).set("mtime", iso(st.st_mtime)).set("sha256", digest)
        .set("offset", static_cast<double>(start)).set("length", static_cast<double>(got)).set("more", static_cast<double>(size - start - got))
        .set("encoding", text ? "text" : "base64").set("content", text ? part : base64_encode(part))
        .set("credentials", secret_path(op.path, op.secrets) || key_file)
        .set("untrusted", true);
}

// The current file at dfd/leaf for a write: whether it is there, what it is, its content when small.
struct Current {
    bool exists = false;
    struct stat st {};
    std::string content;  // whole, when a regular file within kContentMax... read for the sha and the diff
    std::string sha256;
    bool content_known = false;
};

std::string current_of(int dfd, const std::string& leaf, const std::string& abs, Current& c) {
    if (::fstatat(dfd, leaf.c_str(), &c.st, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return "";
        return abs + ": " + std::strerror(errno);
    }
    c.exists = true;
    if (S_ISLNK(c.st.st_mode)) return abs + " is a symlink; refused (never followed)";
    if (S_ISDIR(c.st.st_mode)) return abs + " is a directory; refused";
    if (!S_ISREG(c.st.st_mode)) return abs + " is not a regular file; refused";
    if (c.st.st_uid != ::geteuid()) return abs + " belongs to another account; refused";
    const int fd = ::openat(dfd, leaf.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return abs + ": " + std::strerror(errno);
    std::string why;
    if (static_cast<std::uint64_t>(c.st.st_size) <= kDigestMax && read_all(fd, kDigestMax, c.content, why)) {
        c.sha256 = sha256_hex(c.content);
        c.content_known = true;
    }
    ::close(fd);
    return "";
}

json::Value current_json(const Current& c) {
    if (!c.exists) return json::Value::object().set("exists", false);
    json::Value v = json::Value::object().set("exists", true).set("bytes", static_cast<double>(c.st.st_size)).set("sha256", c.sha256)
                        .set("mode", install::mode_string(c.st.st_mode & 07777));
    if (c.content_known && c.content.size() <= kContentMax && utf8_text(c.content)) v.set("text", c.content);
    return v;
}

// Writes `content` to dfd/leaf through a temporary name: linked when the leaf is new, renamed over
// it otherwise. The mode follows the directory; a credential file is 0600 and checked as written.
json::Value place(int dfd, const std::string& leaf, const std::string& abs, const std::string& content, unsigned mode, bool replace, bool secret) {
    const std::string tmp = ".agensio-write." + std::to_string(::getpid());
    ::unlinkat(dfd, tmp.c_str(), 0);
    const int fd = ::openat(dfd, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return fail("cannot create a temporary file next to " + abs + ": " + std::strerror(errno));
    std::size_t off = 0;
    bool ok = true;
    while (off < content.size()) {
        const ssize_t w = ::write(fd, content.data() + off, content.size() - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        off += static_cast<std::size_t>(w);
    }
    ok = ok && ::fchmod(fd, mode) == 0 && ::fsync(fd) == 0;
    if (ok && secret) {
        struct stat ws {};
        ok = ::fstat(fd, &ws) == 0 && !secret_exposed(ws.st_mode & 07777, ws.st_gid, ::getegid());
    }
    const int e = errno;
    ::close(fd);
    if (!ok) {
        ::unlinkat(dfd, tmp.c_str(), 0);
        return fail("writing " + abs + ": " + (secret ? std::string("a credential file would be readable by others; refused") : std::strerror(e)));
    }
    const bool placed = replace ? ::renameat(dfd, tmp.c_str(), dfd, leaf.c_str()) == 0 : ::linkat(dfd, tmp.c_str(), dfd, leaf.c_str(), 0) == 0;
    const int pe = errno;
    if (!replace || !placed) ::unlinkat(dfd, tmp.c_str(), 0);
    if (!placed) return fail(pe == EEXIST ? abs + " appeared meanwhile; refused" : abs + ": " + std::strerror(pe));
    return json::Value::object().set("ok", true);
}

json::Value do_write(const Op& op, bool edit) {
    std::string leaf, why;
    bool missing = false;
    const int dfd = open_parent(op, op.path, leaf, why, missing);
    if (dfd < 0) return fail(why + (missing ? " (site_dir_create makes it)" : ""));
    const std::string abs = op.site_root + "/" + op.path;
    Current cur;
    if (const std::string bad = current_of(dfd, leaf, abs, cur); !bad.empty()) {
        ::close(dfd);
        return fail(bad);
    }
    auto done = [&](json::Value v) {
        ::close(dfd);
        return v;
    };
    if (!op.if_sha256.empty()) {
        // A credential file's digest is never answered (the alpha.124 report, problem B).
        const bool secret_now = secret_path(op.path, op.secrets) || (cur.content_known && private_key_head(cur.content));
        if (op.if_sha256 == "absent" ? cur.exists : (!cur.exists || cur.sha256 != op.if_sha256))
            return done(fail(abs + (op.if_sha256 == "absent" ? " exists now"
                                    : cur.exists              ? " changed since it was read" + (secret_now ? std::string() : " (its sha256 is " + cur.sha256 + ")")
                                                              : " no longer exists") +
                             "; read it again and send the change again"));
    }
    std::string content = op.content;
    if (edit) {
        if (!cur.exists) return done(fail(abs + " does not exist; site_file_write creates it"));
        if (!cur.content_known || cur.content.size() > kContentMax || !utf8_text(cur.content))
            return done(fail(abs + " is not UTF-8 text within " + std::to_string(kContentMax / 1024) + " KB; site_file_write replaces it whole"));
        std::size_t count = 0, at = 0, first = std::string::npos;
        while ((at = cur.content.find(op.old_text, at)) != std::string::npos) {
            if (first == std::string::npos) first = at;
            ++count;
            at += op.old_text.size();
        }
        if (count != 1)
            return done(fail(count == 0 ? "old does not occur in " + abs + " (site_file_read shows the file as it is)"
                                        : "old occurs " + std::to_string(count) + " times in " + abs + "; give more of the surrounding text so it occurs once"));
        content = cur.content.substr(0, first) + op.new_text + cur.content.substr(first + op.old_text.size());
        if (content.size() > kContentMax) return done(fail("the edited file would be larger than " + std::to_string(kContentMax / 1024) + " KB"));
    } else if (cur.exists && !op.overwrite) {
        return done(fail(abs + " exists; overwrite: true replaces it (the one there is kept in the history)"));
    }
    // A credential by its path, or a private key by its first line, the new text's or the one there
    // (2026-11-04: a deploy key under any name is made 0600 and its previews show no line of it).
    const bool secret = secret_path(op.path, op.secrets) || private_key_head(content) || (cur.content_known && private_key_head(cur.content));
    if (cur.exists && cur.content_known && content == cur.content) {
        // The file holds this text already: nothing written, nothing kept in the history, and the
        // handler queues nothing for approval (the alpha.121 report).
        return done(json::Value::object().set("ok", true).set("unchanged", true).set("dry_run", op.dry_run).set("as", install::executing_account()).set("path", abs)
                        .set("bytes", static_cast<double>(content.size())).set("mode", install::mode_string(cur.st.st_mode & 07777)).set("sha256", cur.sha256)
                        .set("secured", secret).set("current", current_json(cur)).set("note", abs + " already holds this text; nothing to change"));
    }
    struct stat ds {};
    ::fstat(dfd, &ds);
    // An existing file keeps its mode; a new one takes the directory's pattern, its execute bits only
    // when asked. No set-uid or set-gid bit is ever made.
    unsigned mode = cur.exists ? (cur.st.st_mode & 0777) : (ds.st_mode & 0666);
    if (op.executable) mode |= ds.st_mode & 0111;
    if (secret) mode = 0600;
    json::Value answer = json::Value::object().set("as", install::executing_account()).set("path", abs).set("bytes", static_cast<double>(content.size()))
                             .set("mode", install::mode_string(mode)).set("sha256", sha256_hex(content)).set("secured", secret).set("current", current_json(cur));
    if (op.dry_run) {
        answer.set("ok", true).set("dry_run", true);
        if (edit) answer.set("new_text", content);
        return done(answer);
    }
    json::Value r = place(dfd, leaf, abs, content, mode, cur.exists, secret);
    if (!r["ok"].boolean()) return done(r);
    answer.set("ok", true);
    if (cur.exists) answer.set("replaced", json::Value::object().set("bytes", static_cast<double>(cur.st.st_size)).set("sha256", cur.sha256));
    return done(answer);
}

json::Value do_mkdir(const Op& op) {
    std::string why;
    const int root = open_root(op, why);
    if (root < 0) return fail(why);
    int cur = ::dup(root);
    ::close(root);
    std::string so_far = op.site_root;
    json::Value created = json::Value::array();
    std::size_t pos = 0;
    while (pos < op.path.size()) {
        const std::size_t slash = op.path.find('/', pos);
        const std::string part = op.path.substr(pos, slash == std::string::npos ? std::string::npos : slash - pos);
        const bool last = slash == std::string::npos;
        pos = last ? op.path.size() : slash + 1;
        const std::string path = so_far + "/" + part;
        struct stat ps {};
        ::fstat(cur, &ps);
        int child = ::openat(cur, part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child >= 0 && last) {
            ::close(child);
            ::close(cur);
            return fail(path + " exists");
        }
        if (child < 0) {
            if (errno != ENOENT) {
                const std::string what = errno == ELOOP || errno == ENOTDIR ? path + " is a symlink or not a directory; refused" : path + ": " + std::strerror(errno);
                ::close(cur);
                return fail(what);
            }
            if (!last && !op.parents) {
                ::close(cur);
                return fail(path + " does not exist; parents: true creates the missing levels");
            }
            if (!op.dry_run) {
                if (::mkdirat(cur, part.c_str(), 0700) != 0) {
                    const std::string what = path + ": " + std::strerror(errno);
                    ::close(cur);
                    return fail(what);
                }
                child = ::openat(cur, part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                if (child >= 0) (void)::fchmod(child, ps.st_mode & 07777 & ~static_cast<unsigned>(S_ISUID));  // the parent's pattern, set-gid kept
            }
            created.push(path);
            if (op.dry_run) {  // nothing more can be walked
                ::close(cur);
                return json::Value::object().set("ok", true).set("dry_run", true).set("as", install::executing_account()).set("would_create", created)
                    .set("path", op.site_root + "/" + op.path);
            }
        } else {
            struct stat cs {};
            if (::fstat(child, &cs) != 0 || cs.st_uid != ::geteuid()) {
                ::close(child);
                ::close(cur);
                return fail(path + " belongs to another account; refused");
            }
        }
        ::close(cur);
        cur = child;
        so_far = path;
        if (cur < 0) return fail(path + ": " + std::strerror(errno));
    }
    ::close(cur);
    return json::Value::object().set("ok", true).set("as", install::executing_account()).set("path", op.site_root + "/" + op.path).set("created", created)
        .set("dry_run", op.dry_run);
}

json::Value do_move(const Op& op) {
    std::string fleaf, tleaf, why;
    bool missing = false;
    const int fdir = open_parent(op, op.path, fleaf, why, missing);
    if (fdir < 0) return fail("from: " + why);
    const int tdir = open_parent(op, op.to, tleaf, why, missing);
    if (tdir < 0) {
        ::close(fdir);
        return fail("to: " + why + (missing ? " (site_dir_create makes it)" : ""));
    }
    const std::string fabs = op.site_root + "/" + op.path, tabs = op.site_root + "/" + op.to;
    auto done = [&](json::Value v) {
        ::close(fdir);
        ::close(tdir);
        return v;
    };
    struct stat fs {}, ts {};
    if (::fstatat(fdir, fleaf.c_str(), &fs, AT_SYMLINK_NOFOLLOW) != 0) return done(fail(fabs + (errno == ENOENT ? " does not exist" : ": " + std::string(std::strerror(errno)))));
    if (fs.st_uid != ::geteuid()) return done(fail(fabs + " belongs to another account; refused"));
    const bool dest = ::fstatat(tdir, tleaf.c_str(), &ts, AT_SYMLINK_NOFOLLOW) == 0;
    if (dest && !op.overwrite) return done(fail(tabs + " exists; overwrite: true replaces it (the one there is kept in the history)"));
    if (dest && S_ISDIR(ts.st_mode)) return done(fail(tabs + " is a directory; a move replaces a file, never a directory"));
    json::Value answer = json::Value::object().set("ok", true).set("as", install::executing_account()).set("from", fabs).set("to", tabs).set("kind", kind_of(fs))
                             .set("would_replace", dest);
    if (op.dry_run) return done(answer.set("dry_run", true));
    if (::renameat(fdir, fleaf.c_str(), tdir, tleaf.c_str()) != 0) return done(fail("moving " + fabs + " to " + tabs + ": " + std::strerror(errno)));
    return done(answer);
}

// Entries below dir_fd/name, counted up to `limit` + 1.
std::size_t count_tree(int dir_fd, const std::string& name, std::size_t limit, int depth = 0) {
    struct stat st {};
    if (::fstatat(dir_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) return 0;
    if (!S_ISDIR(st.st_mode) || depth > 64) return 1;
    const int fd = ::openat(dir_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 1;
    DIR* d = ::fdopendir(fd);
    if (!d) {
        ::close(fd);
        return 1;
    }
    std::size_t n = 1;
    std::vector<std::string> children;
    while (const struct dirent* e = ::readdir(d))
        if (std::string_view(e->d_name) != "." && std::string_view(e->d_name) != "..") children.emplace_back(e->d_name);
    for (const auto& c : children) {
        if (n > limit) break;
        n += count_tree(::dirfd(d), c, limit - n, depth + 1);
    }
    ::closedir(d);
    return n;
}

bool remove_tree(int dir_fd, const std::string& name, std::string& why, int depth = 0) {
    struct stat st {};
    if (::fstatat(dir_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) return errno == ENOENT || (why = name + ": " + std::strerror(errno), false);
    if (!S_ISDIR(st.st_mode)) return ::unlinkat(dir_fd, name.c_str(), 0) == 0 || errno == ENOENT || (why = name + ": " + std::strerror(errno), false);
    if (depth > 256) return why = name + ": too deep", false;
    const int fd = ::openat(dir_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return why = name + ": " + std::strerror(errno), false;
    DIR* d = ::fdopendir(fd);
    if (!d) {
        ::close(fd);
        return why = name + ": " + std::strerror(errno), false;
    }
    std::vector<std::string> children;
    while (const struct dirent* e = ::readdir(d))
        if (std::string_view(e->d_name) != "." && std::string_view(e->d_name) != "..") children.emplace_back(e->d_name);
    for (const auto& c : children)
        if (!remove_tree(::dirfd(d), c, why, depth + 1)) {
            ::closedir(d);
            return false;
        }
    ::closedir(d);
    return ::unlinkat(dir_fd, name.c_str(), AT_REMOVEDIR) == 0 || errno == ENOENT || (why = name + ": " + std::strerror(errno), false);
}

// A delete as the account: what is there is checked (and, without a history, removed).
json::Value do_delete(const Op& op, bool remove) {
    std::string leaf, why;
    bool missing = false;
    const int dfd = open_parent(op, op.path, leaf, why, missing);
    if (dfd < 0) return fail(why);
    const std::string abs = op.site_root + "/" + op.path;
    auto done = [&](json::Value v) {
        ::close(dfd);
        return v;
    };
    struct stat st {};
    if (::fstatat(dfd, leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) return done(fail(abs + (errno == ENOENT ? " does not exist" : ": " + std::string(std::strerror(errno)))));
    if (st.st_uid != ::geteuid()) return done(fail(abs + " belongs to another account; refused"));
    const std::size_t entries = S_ISDIR(st.st_mode) ? count_tree(dfd, leaf, kTreeMax) : 1;
    if (S_ISDIR(st.st_mode) && entries > 1 && !op.recursive)
        return done(fail(abs + " is a directory that is not empty; recursive: true removes it with everything in it"));
    if (!op.if_sha256.empty() && S_ISREG(st.st_mode)) {
        Current cur;
        current_of(dfd, leaf, abs, cur);
        if (cur.sha256 != op.if_sha256) return done(fail(abs + " changed since it was read; read it again and send the delete again"));
    }
    json::Value answer = json::Value::object().set("ok", true).set("as", install::executing_account()).set("path", abs).set("kind", kind_of(st))
                             .set("bytes", static_cast<double>(st.st_size)).set("entries", static_cast<double>(entries));
    if (S_ISREG(st.st_mode)) {
        Current cur;
        current_of(dfd, leaf, abs, cur);
        answer.set("sha256", cur.sha256);
    }
    if (op.dry_run || !remove) return done(answer.set("dry_run", op.dry_run));
    if (entries > kTreeMax)
        return done(fail(abs + " holds more than " + std::to_string(kTreeMax) + " entries; without the history ([control] file_history versions = 0) a delete removes at most that many"));
    if (!remove_tree(dfd, leaf, why)) return done(fail("removing " + abs + ": " + why));
    return done(answer.set("history", "off: removed for good"));
}

}  // namespace

json::Value execute(const Op& op) {
    if (op.action == "list") return do_list(op);
    if (op.action == "read") return do_read(op);
    if (op.action == "write") return do_write(op, false);
    if (op.action == "edit") return do_write(op, true);
    if (op.action == "mkdir") return do_mkdir(op);
    if (op.action == "move") return do_move(op);
    if (op.action == "delete") return do_delete(op, true);
    return fail("not an action of the site's account: " + op.action);
}

json::Value run(const Op& op, const Context& ctx, const AsSite& as_site) {
    const history::Place& place = ctx.place;
    const bool keeping = place.settings.versions > 0;
    // A change that went through: what it replaced is the newest version, and the oldest beyond the count
    // go now, never before (a refused change must leave every version as it was).
    auto settled = [&](json::Value r, const std::string& rel, const std::string& entry, bool moved) {
        if (!r["ok"].boolean()) {
            if (!entry.empty()) history::undo(place, rel, entry, moved);
            return r;
        }
        if (!entry.empty()) {
            history::prune(place, rel);
            r.set("history", json::Value::object().set("version", entry).set("kept_for_days", place.settings.days));
        }
        return r;
    };
    if (op.action == "history") return history::list(place, op.path);
    if (op.action == "restore") return history::restore(place, op.path, op.version, op.overwrite, op.dry_run);
    if (op.action == "list" || op.action == "read" || op.action == "mkdir" || op.dry_run || !keeping)
        return as_site([&] { return execute(op); });
    if (op.action == "write" || op.action == "edit") {
        // The file there now is linked into the history, then the account renames the new one over it.
        // A check of the account's that refuses (the file changed, it is not text) drops the link.
        const json::Value k = history::keep(place, op.path, false, op.action == "edit" ? "replaced by an edit" : "replaced by a write");
        if (!k["ok"].boolean() && !std::string(k.get("error")).ends_with("is not a regular file; refused")) return k;
        const std::string entry = k["ok"].boolean() ? std::string(k.get("entry")) : std::string();
        return settled(as_site([&] { return execute(op); }), op.path, entry, false);
    }
    if (op.action == "move") {
        // A file the move replaces leaves the site into the history first; the account then renames.
        Op check = op;
        check.dry_run = true;
        const json::Value c = as_site([&] { return execute(check); });
        if (!c["ok"].boolean()) return c;
        std::string entry;
        if (c["would_replace"].boolean()) {
            const json::Value k = history::keep(place, op.to, true, "replaced by a move from " + op.path);
            if (!k["ok"].boolean()) return k;
            entry = std::string(k.get("entry"));
        }
        return settled(as_site([&] { return execute(op); }), op.to, entry, true);
    }
    if (op.action == "delete") {
        // The account checks what is there; the history takes it out of the site whole: a delete is a
        // rename into the history, whatever its size.
        Op check = op;
        check.dry_run = true;
        json::Value c = as_site([&] { return execute(check); });
        if (!c["ok"].boolean()) return c;
        const json::Value k = history::keep(place, op.path, true, "deleted");
        if (!k["ok"].boolean()) return k;
        if (std::string(k.get("entry")).empty()) return fail(op.site_root + "/" + op.path + " does not exist");
        c.set("dry_run", false);
        return settled(c, op.path, std::string(k.get("entry")), true);
    }
    return fail("unknown action " + op.action);
}

#else

json::Value execute(const Op&) { return json::Value::object().set("ok", false).set("error", "not available on this platform"); }
json::Value run(const Op&, const Context&, const AsSite&) { return json::Value::object().set("ok", false).set("error", "not available on this platform"); }

#endif

}  // namespace agensio::files
