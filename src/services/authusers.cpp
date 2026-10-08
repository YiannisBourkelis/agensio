#include "services/authusers.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <mutex>

#include <openssl/rand.h>

#include "config.hpp"
#include "services/appenv.hpp"

namespace agensio::authusers {

namespace {

bool control(unsigned char c) noexcept { return c < 0x20 || c == 0x7f; }
bool alnum(char c) noexcept { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'); }

const char* kNoPassword =
    "a password is never sent to the server: generate: true makes one, answered once and kept nowhere; for one the user "
    "chooses, they run `agensio ctl site-auth-user-set SITE USER --prompt` on the server, which asks on their terminal and "
    "sends only its hash";

std::string day_text(std::int64_t t) {
    const std::time_t tt = static_cast<std::time_t>(t);
    std::tm tm{};
    ::gmtime_r(&tt, &tm);
    char buf[16];
    return std::string(buf, std::strftime(buf, sizeof buf, "%Y-%m-%d", &tm));
}

std::string whose(unsigned owner) { return owner == 0 ? "root's" : "uid " + std::to_string(owner) + "'s"; }

// A line that is neither blank nor a comment: the loader refuses a file with none, the tools
// read it as no users.
bool has_entries(std::string_view text) {
    while (!text.empty()) {
        const std::size_t nl = text.find('\n');
        std::string_view line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view() : text.substr(nl + 1);
        const std::size_t first = line.find_first_not_of(" \t\r");
        if (first != std::string_view::npos && line[first] != '#') return true;
    }
    return false;
}

// The directory: -2 when missing (and not to be made), -1 with `error`, else open. A writer makes
// it and brings it to owner:group 0750, the shape the server's reader needs; a reader only
// refuses one another account owns or the group or others may write.
int open_dir(const std::string& dir, unsigned owner, unsigned group, bool writer, std::string& error) {
    if (writer && ::mkdir(dir.c_str(), 0750) != 0 && errno != EEXIST) {
        error = "mkdir " + dir + ": " + std::strerror(errno);
        return -1;
    }
    const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT && !writer) return -2;
        error = dir + ": " + (errno == ELOOP || errno == ENOTDIR ? std::string("a symlink or not a directory; refused") : std::strerror(errno));
        return -1;
    }
    struct stat sb {};
    if (::fstat(fd, &sb) != 0 || sb.st_uid != owner) {
        error = dir + " must be " + whose(owner) + "; it is uid " + std::to_string(sb.st_uid) + "'s; refused";
        ::close(fd);
        return -1;
    }
    if (writer) {
        if ((sb.st_gid != group && ::fchown(fd, owner, group) != 0) || ((sb.st_mode & 07777) != 0750 && ::fchmod(fd, 0750) != 0)) {
            error = dir + ": cannot make it " + whose(owner) + ", group " + std::to_string(group) + ", 0750: " + std::strerror(errno);
            ::close(fd);
            return -1;
        }
    } else if ((sb.st_mode & 022) != 0) {
        error = dir + " is writable by its group or others; refused";
        ::close(fd);
        return -1;
    }
    return fd;
}

// The users in the file, checked as the loader checks it: a regular file of the owner's, one
// link, not writable by group or others, at most 1 MB, every line parsed. `exists` false when
// there is none.
bool read_users(int dfd, const std::string& path, const std::string& leaf, unsigned owner, std::vector<auth::User>& out, bool& exists, std::string& error) {
    out.clear();
    exists = false;
    const int fd = ::openat(dfd, leaf.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return true;
        error = path + ": " + (errno == ELOOP ? std::string("a symlink; refused (remove it: rm " + path + ")") : std::strerror(errno));
        return false;
    }
    struct stat sb {};
    std::string why;
    if (::fstat(fd, &sb) != 0) why = std::strerror(errno);
    else if (!S_ISREG(sb.st_mode)) why = "not a regular file; refused";
    else if (sb.st_uid != owner) why = "must be " + whose(owner) + "; it is uid " + std::to_string(sb.st_uid) + "'s; refused";
    else if ((sb.st_mode & 022) != 0) why = "writable by its group or others; refused";
    else if (sb.st_nlink != 1) why = "has another link; refused";
    else if (sb.st_size > 1024 * 1024) why = "larger than 1 MB; refused";
    std::string text;
    if (why.empty()) {
        text.resize(static_cast<std::size_t>(sb.st_size));
        std::size_t got = 0;
        while (got < text.size()) {
            const ssize_t n = ::read(fd, text.data() + got, text.size() - got);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            got += static_cast<std::size_t>(n);
        }
        text.resize(got);
    }
    ::close(fd);
    if (!why.empty()) {
        error = path + ": " + why;
        return false;
    }
    exists = true;
    if (!has_entries(text)) return true;
    if (const std::string bad = auth::parse_users(text, out); !bad.empty()) {
        error = path + ", " + bad;
        return false;
    }
    return true;
}

json::Value fail(std::string why) { return json::Value::object().set("ok", false).set("error", std::move(why)); }

}  // namespace

std::string check_user(std::string_view n) {
    if (n.empty() || n.size() > 64) return "a user name of 1 to 64 characters";
    if (!alnum(n.front())) return "a user name starts with a letter or a digit";
    for (const char c : n)
        if (!alnum(c) && c != '.' && c != '_' && c != '@' && c != '+' && c != '-')
            return "a user name of letters, digits and . _ @ + - (ASCII), so every client can send it";
    return "";
}

std::string check_hash(std::string_view h) {
    if (h.empty() || h.size() > 255) return "a hash of 1 to 255 characters";
    for (const char c : h)
        if (control(static_cast<unsigned char>(c)) || c == ':' || c == ' ') return "a hash without ':' or blanks";
    if (h.front() == '!' || h.front() == '*') return "a lock is not a hash: locked: true locks a user and keeps the password";
    return auth::refused_hash(h);
}

std::string parse_change(const json::Value& body, Change& out) {
    out = Change{};
    if (!body.is_object()) return "a change is an object: {\"user\": NAME, ...}";
    for (const auto& m : body.members()) {
        const std::string& k = m.first;
        if (k == "password") return kNoPassword;
        if (k != "op" && k != "site" && k != "confirm" && k != "reason" && k != "user" && k != "delete" && k != "generate" && k != "hash" &&
            k != "expires" && k != "note" && k != "locked")
            return "unknown key '" + k + "' (user with generate, hash, expires, note, locked; or user with delete)";
    }
    if (!body["user"].is_string()) return "user: the name to add, change or delete";
    out.user = std::string(body["user"].str());
    if (const std::string why = check_user(out.user); !why.empty()) return "user: " + why;
    auto boolean = [&](const char* k, bool& v) {
        if (body[k].is_null()) return true;
        if (body[k].type() != json::Value::Type::boolean) return false;
        v = body[k].boolean();
        return true;
    };
    if (!boolean("delete", out.remove) || !boolean("generate", out.generate)) return "delete and generate are true or false";
    if (!body["locked"].is_null()) {
        bool v = false;
        if (!boolean("locked", v)) return "locked is true or false";
        out.locked = v;
    }
    if (!body["hash"].is_null()) {
        if (!body["hash"].is_string()) return "hash: a crypt hash, as `agensio ctl --prompt` sends it";
        out.hash = std::string(body["hash"].str());
        if (const std::string why = check_hash(out.hash); !why.empty()) return "hash: " + why;
    }
    if (!body["expires"].is_null()) {
        if (!body["expires"].is_string()) return "expires: a date, YYYY-MM-DD, or \"\" for none";
        std::int64_t t = 0;
        const std::string v(body["expires"].str());
        if (!v.empty() && !auth::parse_date(v, t)) return "expires: a date, YYYY-MM-DD (from that day, UTC, the login is refused), or \"\" for none";
        out.expires = v;
    }
    if (!body["note"].is_null()) {
        if (!body["note"].is_string()) return "note: a line of text, or \"\" for none";
        const std::string v(body["note"].str());
        if (v.size() > kMaxNote) return "note: at most " + std::to_string(kMaxNote) + " bytes";
        for (const char c : v)
            if (control(static_cast<unsigned char>(c))) return "note: one line, without control characters";
        out.note = v;
    }
    if (out.remove) {
        if (out.generate || !out.hash.empty() || out.expires || out.note || out.locked) return "delete takes the user alone";
        return "";
    }
    if (out.generate && !out.hash.empty()) return "generate or hash, not both";
    if (!out.generate && out.hash.empty() && !out.expires && !out.note && !out.locked)
        return "nothing to change: generate: true (a new password; a new user needs one), expires, note or locked; delete removes the user";
    return "";
}

std::string generate_password() {
    static constexpr char kAlphabet[] = "abcdefghijkmnpqrstuvwxyz23456789";  // 32: no 0, 1, l, o
    static_assert(sizeof kAlphabet - 1 == 32);
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof bytes) != 1) return "";
    std::string out;
    out.reserve(19);
    for (std::size_t i = 0; i < sizeof bytes; ++i) {
        if (i && i % 4 == 0) out.push_back('-');
        out.push_back(kAlphabet[bytes[i] & 31]);  // 256 is a multiple of 32: no bias
    }
    ::OPENSSL_cleanse(bytes, sizeof bytes);
    return out;
}

std::string method_of(std::string_view h) {
    if (!h.empty() && h.front() == '!') h.remove_prefix(1);
    if (h.starts_with("$y$")) return "yescrypt";
    if (h.starts_with("$gy$")) return "gost-yescrypt";
    if (h.starts_with("$7$")) return "scrypt";
    if (h.starts_with("$2b$") || h.starts_with("$2y$") || h.starts_with("$2a$")) return "bcrypt";
    if (h.starts_with("$6$")) return "sha512crypt";
    if (h.starts_with("$5$")) return "sha256crypt";
    return "";
}

std::string render(const std::vector<auth::User>& users, std::string_view site) {
    std::string s = "# The users of " + std::string(site) + "'s rules.auth (docs/configuration.md 19b), written by agensio's control plane\n"
                    "# (agensio ctl site-auth-user-set, MCP site_auth_user_set); a comment added here is not kept.\n";
    for (const auto& u : users) {
        s += u.name + ":" + u.hash;
        if (u.expires) s += ":expires=" + day_text(u.expires);
        if (!u.note.empty()) s += ":note=" + u.note;
        s += "\n";
    }
    return s;
}

std::string dir_of(const std::filesystem::path& config_path) {
    const std::filesystem::path parent = config_path.parent_path();
    return ((parent.empty() ? std::filesystem::path(".") : parent) / "auth").string();
}

std::string file_of(const std::string& dir, std::string_view site) { return dir + "/" + std::string(site) + ".users"; }

bool used_by(const Config& cfg, const std::string& file) {
    std::error_code ec;
    const std::filesystem::path want = std::filesystem::absolute(file, ec).lexically_normal();
    for (const auto& s : cfg.sites)
        for (const auto& r : s.auth)
            if (!r.users_path.empty() && std::filesystem::absolute(r.users_path, ec).lexically_normal() == want) return true;
    return false;
}

json::Value describe(const std::string& dir, std::string_view site, unsigned owner, std::int64_t now) {
    if (!appenv::valid_site(site)) return fail("'" + std::string(site) + "' is not a site's host name");
    const std::string file = file_of(dir, site);
    json::Value out = json::Value::object().set("ok", true).set("site", std::string(site)).set("file", file);
    std::string error;
    const int dfd = open_dir(dir, owner, 0, false, error);
    if (dfd == -2) return out.set("exists", false).set("users", json::Value::array());
    if (dfd < 0) return fail(error);
    std::vector<auth::User> users;
    bool exists = false;
    const bool ok = read_users(dfd, file, std::string(site) + ".users", owner, users, exists, error);
    ::close(dfd);
    if (!ok) return fail(error);
    json::Value list = json::Value::array();
    for (const auto& u : users) {
        json::Value v = json::Value::object().set("name", u.name).set("method", method_of(u.hash));
        v.set("expires", u.expires ? json::Value(day_text(u.expires)) : json::Value(nullptr)).set("expired", u.expires != 0 && now >= u.expires);
        v.set("note", u.note.empty() ? json::Value(nullptr) : json::Value(u.note)).set("locked", u.locked);
        list.push(std::move(v));
    }
    return out.set("exists", exists).set("users", std::move(list));
}

json::Value apply(const std::string& dir, std::string_view site, unsigned owner, unsigned group, const Change& change, bool keep_one) {
    static std::mutex serial;  // two writers in one process never interleave a read and a rename
    const std::lock_guard lock(serial);
    if (!appenv::valid_site(site)) return fail("'" + std::string(site) + "' is not a site's host name");
    if (::geteuid() != owner) return fail("the users files are " + whose(owner) + "; this process is not");
    const std::string leaf = std::string(site) + ".users", file = file_of(dir, site);
    std::string error;
    const int dfd = open_dir(dir, owner, group, true, error);
    if (dfd < 0) return fail(error);
    struct Closer {
        int fd;
        ~Closer() { ::close(fd); }
    } closer{dfd};
    std::vector<auth::User> users;
    bool exists = false;
    if (!read_users(dfd, file, leaf, owner, users, exists, error)) return fail(error);
    auto it = std::find_if(users.begin(), users.end(), [&](const auth::User& u) { return u.name == change.user; });
    std::string action, password;
    if (change.remove) {
        if (it == users.end()) {
            action = "unchanged";
        } else {
            if (keep_one && users.size() == 1)
                return fail("the last user of a file a rule uses is kept: lock it (locked: true) to refuse every login, or remove the rule first");
            users.erase(it);
            action = "deleted";
        }
    } else {
        const bool created = it == users.end();
        if (created) {
            if (!change.generate && change.hash.empty())
                return fail("a new user needs a password: generate: true makes one (answered once), or the user runs `agensio ctl site-auth-user-set " +
                            std::string(site) + " " + change.user + " --prompt` on the server");
            if (users.size() >= kMaxUsers) return fail("at most " + std::to_string(kMaxUsers) + " users in a site's file");
            users.emplace_back();
            users.back().name = change.user;
            it = users.end() - 1;
        }
        auth::User& u = *it;
        const auth::User before = u;
        if (change.generate) {
            password = generate_password();
            if (password.empty()) return fail("no random bytes from the system");
            std::string err;
            u.hash = auth::make_hash(password, "yescrypt", 0, err);
            if (u.hash.empty()) return fail("the password could not be hashed: " + err);
        } else if (!change.hash.empty()) {
            u.hash = change.hash;  // a new password unlocks, unless this change locks again
        }
        if (change.locked && *change.locked && u.hash.front() != '!' && u.hash != "*") u.hash.insert(0, 1, '!');
        if (change.locked && !*change.locked && (u.hash.front() == '!' || u.hash == "*")) {
            if (u.hash.size() == 1) return fail("user " + u.name + " has no password behind the lock: generate: true sets one");
            u.hash.erase(0, 1);
        }
        if (change.expires) {
            u.expires = 0;
            if (!change.expires->empty()) auth::parse_date(*change.expires, u.expires);
        }
        if (change.note) u.note = *change.note;
        u.locked = u.hash.front() == '!' || u.hash == "*";
        action = created ? "created" : (u.hash == before.hash && u.expires == before.expires && u.note == before.note) ? "unchanged" : "changed";
    }
    bool removed = false;
    if (action != "unchanged") {
        if (users.empty()) {
            if (::unlinkat(dfd, leaf.c_str(), 0) != 0 && errno != ENOENT) return fail("remove " + file + ": " + std::strerror(errno));
            removed = exists;
        } else {
            const std::string text = render(users, site);
            if (text.size() > 1024 * 1024) return fail("the file would pass 1 MB");
            const std::string tmp = leaf + ".tmp";
            ::unlinkat(dfd, tmp.c_str(), 0);  // left by a write that died
            const int f = ::openat(dfd, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            bool ok = f >= 0 && ::fchown(f, owner, group) == 0 && ::fchmod(f, 0640) == 0;
            for (std::size_t off = 0; ok && off < text.size();) {
                const ssize_t n = ::write(f, text.data() + off, text.size() - off);
                if (n < 0 && errno == EINTR) continue;
                ok = n > 0;
                if (ok) off += static_cast<std::size_t>(n);
            }
            ok = ok && ::fsync(f) == 0;
            const int err = errno;
            if (f >= 0) ::close(f);
            if (!ok || ::renameat(dfd, tmp.c_str(), dfd, leaf.c_str()) != 0) {
                const int e = ok ? errno : err;
                ::unlinkat(dfd, tmp.c_str(), 0);
                return fail("write " + file + ": " + std::strerror(e));
            }
            ::fsync(dfd);
        }
    }
    json::Value out = json::Value::object().set("ok", true).set("site", std::string(site)).set("file", file).set("user", change.user).set("action", action);
    out.set("users", static_cast<double>(users.size()));
    if (!password.empty()) out.set("password", password);
    if (removed) out.set("removed", file);
    return out;
}

}  // namespace agensio::authusers
