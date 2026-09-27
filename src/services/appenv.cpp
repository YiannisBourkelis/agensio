#include "services/appenv.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>

#ifdef AGENSIO_HAS_TLS
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace agensio::appenv {

namespace {

bool upper_name_char(unsigned char c, bool first) noexcept {
    return (c >= 'A' && c <= 'Z') || c == '_' || (!first && c >= '0' && c <= '9');
}

// systemd's own rule for a name in an environment file: letters, digits and '_', not
// starting with a digit. Our write rule (check_name) is narrower.
bool env_name(std::string_view n) noexcept {
    if (n.empty() || (n[0] >= '0' && n[0] <= '9')) return false;
    for (unsigned char c : n)
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
    return true;
}

std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
    return s;
}

bool blank(std::string_view s) noexcept { return trim(s).empty(); }

void put(std::vector<Var>& vars, std::string name, std::string value) {
    for (auto& v : vars)
        if (v.name == name) {
            v.value = std::move(value);
            return;
        }
    vars.push_back({std::move(name), std::move(value)});
}

}  // namespace

bool reserved(std::string_view n) noexcept {
    // What a task's environment already holds (tasks::build and the preset's family), and the
    // names that choose or load a program: the audit line says which program ran, and it
    // must stay true.
    static constexpr std::string_view exact[] = {
        "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LANGUAGE", "SHELL", "USER", "LOGNAME", "IFS", "ENV", "BASH_ENV", "CDPATH",
        "RAILS_ENV", "SECRET_KEY_BASE_DUMMY", "RUBYOPT", "RUBYLIB", "RUBYSHELL", "NODE_OPTIONS", "NODE_PATH", "PERL5LIB", "PERL5OPT",
        "PERLLIB", "GCONV_PATH", "LOCPATH", "HOSTALIASES", "GLIBC_TUNABLES", "EDITOR", "VISUAL", "PAGER", "SSH_ASKPASS", "SUDO_ASKPASS",
        "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "NOTIFY_SOCKET", "LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES"};
    for (std::string_view e : exact)
        if (n == e) return true;
    static constexpr std::string_view prefixes[] = {"LD_", "DYLD_", "GEM_", "PYTHON", "MALLOC_", "GIT_"};
    for (std::string_view p : prefixes)
        if (n.starts_with(p)) return true;
    // Bundler's settings choose what is loaded (BUNDLE_PATH, BUNDLE_GEMFILE, BUNDLE_BUILD__*);
    // a private gem source's credentials (BUNDLE_GEMS__CONTRIBSYS__COM for Sidekiq Pro) are
    // the one kind an application needs, and they name a host with double underscores.
    if (n.starts_with("BUNDLE_")) {
        const std::string_view rest = n.substr(7);
        return rest.find("__") == std::string_view::npos || rest.starts_with("BUILD__");
    }
    return false;
}

std::string check_name(std::string_view n) {
    if (n.empty() || n.size() > 64) return "a variable's name is 1 to 64 characters";
    for (std::size_t i = 0; i < n.size(); ++i)
        if (!upper_name_char(static_cast<unsigned char>(n[i]), i == 0))
            return "'" + std::string(n) + "' is not a variable name: upper-case letters, digits and '_', not starting with a digit";
    if (reserved(n))
        return std::string(n) + " is agensio's own or changes which program runs (PATH, HOME, RAILS_ENV, GEM_*, BUNDLE_* other than a gem "
                                "source's credentials, LD_*, RUBYOPT, NODE_OPTIONS, GIT_*, ...); the site's environment cannot set it";
    return "";
}

std::string check_value(std::string_view v) {
    if (v.size() > kMaxValue) return "a value is at most " + std::to_string(kMaxValue) + " bytes";
    for (std::size_t i = 0; i < v.size();) {
        const unsigned char c = static_cast<unsigned char>(v[i]);
        if (c < 0x20 || c == 0x7f) return "a value is one line of text: no control characters (newline, tab, NUL)";
        std::size_t len = c < 0x80 ? 1 : (c & 0xe0) == 0xc0 ? 2 : (c & 0xf0) == 0xe0 ? 3 : (c & 0xf8) == 0xf0 ? 4 : 0;
        if (len == 0 || i + len > v.size() || (len == 2 && c < 0xc2)) return "a value must be UTF-8 text";
        for (std::size_t k = 1; k < len; ++k)
            if ((static_cast<unsigned char>(v[i + k]) & 0xc0) != 0x80) return "a value must be UTF-8 text";
        i += len;
    }
    return "";
}

bool valid_site(std::string_view s) noexcept {
    if (s.empty() || s.size() > 253 || s.front() == '.' || s.front() == '-' || s.back() == '.') return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c == '.' && s[i - 1] == '.') return false;
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) return false;
    }
    return true;
}

std::string render(const std::vector<Var>& vars, std::string_view site) {
    std::string out = "# The application environment of site " + std::string(site) +
                      ", written by agensio (site_env_set).\n"
                      "# Read by the site's tasks and by its application service (EnvironmentFile=). root's, 0600.\n";
    for (const auto& v : vars) {
        out += v.name + "=\"";
        for (char c : v.value) {
            if (c == '\\' || c == '"' || c == '$' || c == '`') out.push_back('\\');
            out.push_back(c);
        }
        out += "\"\n";
    }
    return out;
}

bool parse(std::string_view text, std::vector<Var>& out, std::string& why) {
    std::size_t line_no = 0;
    while (!text.empty()) {
        const std::size_t nl = text.find('\n');
        std::string_view line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view() : text.substr(nl + 1);
        ++line_no;
        line = trim(line);
        if (line.empty() || line.front() == '#' || line.front() == ';') continue;
        const std::size_t eq = line.find('=');
        if (eq == std::string_view::npos) continue;  // systemd ignores such a line
        const std::string_view name = trim(line.substr(0, eq));
        const std::string at = "line " + std::to_string(line_no) + ": ";
        if (!env_name(name)) {
            why = at + "'" + std::string(name.substr(0, 64)) + "' is not a variable name";
            return false;
        }
        std::string_view rest = trim(line.substr(eq + 1));
        std::string value;
        if (!rest.empty() && rest.front() == '\'') {
            const std::size_t close = rest.find('\'', 1);
            if (close == std::string_view::npos) {
                why = at + std::string(name) + "'s single-quoted value does not close on its line";
                return false;
            }
            value.assign(rest.substr(1, close - 1));
            rest = rest.substr(close + 1);
        } else if (!rest.empty() && rest.front() == '"') {
            std::size_t i = 1;
            bool closed = false;
            while (i < rest.size()) {
                const char c = rest[i];
                if (c == '\\') {
                    if (i + 1 >= rest.size()) break;  // a continuation line
                    const char n = rest[i + 1];
                    if (n == '"' || n == '\\' || n == '`' || n == '$') value.push_back(n);
                    else {
                        value.push_back('\\');
                        value.push_back(n);
                    }
                    i += 2;
                } else if (c == '"') {
                    closed = true;
                    ++i;
                    break;
                } else {
                    value.push_back(c);
                    ++i;
                }
            }
            if (!closed) {
                why = at + std::string(name) + "'s double-quoted value does not close on its line";
                return false;
            }
            rest = rest.substr(i);
        } else {
            for (std::size_t i = 0; i < rest.size(); ++i) {
                if (rest[i] == '\\') {
                    if (i + 1 >= rest.size()) {
                        why = at + std::string(name) + "'s value ends with a backslash, which continues it on the next line";
                        return false;
                    }
                    value.push_back(rest[++i]);
                } else {
                    value.push_back(rest[i]);
                }
            }
            rest = {};
        }
        if (!blank(rest)) {
            why = at + "text after " + std::string(name) + "'s quoted value";
            return false;
        }
        put(out, std::string(name), std::move(value));
    }
    return true;
}

std::string dir_of(const std::filesystem::path& config_path) {
    const std::filesystem::path parent = config_path.parent_path();
    return ((parent.empty() ? std::filesystem::path(".") : parent) / "env").string();
}

std::string parse_change(const json::Value& body, Change& out) {
    out = Change{};
    const json::Value& set = body["set"];
    const json::Value& unset = body["unset"];
    const json::Value& gen = body["generate"];
    if (!set.is_null() && !set.is_object()) return "set must be an object of NAME: value strings";
    if (!unset.is_null() && unset.type() != json::Value::Type::array) return "unset must be an array of names";
    if (!gen.is_null() && gen.type() != json::Value::Type::array) return "generate must be an array of names";
    // A name once per list, and never both set and removed or generated; unset and generate
    // together is how a secret is rotated (unset runs first).
    std::vector<std::string> seen_set, seen_unset, seen_gen;
    std::size_t count = 0;
    auto in = [](const std::vector<std::string>& v, const std::string& n) { return std::find(v.begin(), v.end(), n) != v.end(); };
    auto once = [&](std::vector<std::string>& list, const std::string& n) -> std::string {
        if (in(list, n)) return n + " appears twice in one list";
        if (&list != &seen_set && in(seen_set, n)) return n + " is both set and " + (&list == &seen_unset ? "unset" : "generated");
        if (&list == &seen_set && (in(seen_unset, n) || in(seen_gen, n))) return n + " is both set and unset or generated";
        list.push_back(n);
        ++count;
        return "";
    };
    for (const auto& m : set.members()) {
        if (std::string bad = check_name(m.first); !bad.empty()) return "set: " + bad;
        if (!m.second.is_string()) return "set: " + m.first + "'s value must be a string";
        if (std::string bad = check_value(m.second.str()); !bad.empty()) return "set: " + m.first + ": " + bad;
        if (std::string bad = once(seen_set, m.first); !bad.empty()) return bad;
        out.set.push_back({m.first, std::string(m.second.str())});
    }
    for (const auto& u : unset.items()) {
        // Any name systemd would read can be removed, a reserved one written by hand included.
        if (!u.is_string() || !env_name(u.str()) || u.str().size() > 64) return "unset: names are variable names";
        if (std::string bad = once(seen_unset, std::string(u.str())); !bad.empty()) return bad;
        out.unset.emplace_back(u.str());
    }
    for (const auto& g : gen.items()) {
        if (!g.is_string()) return "generate: names are strings";
        if (std::string bad = check_name(g.str()); !bad.empty()) return "generate: " + bad;
        if (std::string bad = once(seen_gen, std::string(g.str())); !bad.empty()) return bad;
        out.generate.emplace_back(g.str());
    }
    if (out.set.empty() && out.unset.empty() && out.generate.empty()) return "nothing to change: give set, unset or generate";
    if (count > 64) return "at most 64 names in one change";
    return "";
}

std::string fingerprint(std::string_view key, std::string_view value) {
#ifdef AGENSIO_HAS_TLS
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (!::HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char*>(value.data()), value.size(), mac, &len) || len < 8)
        return "";
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(hex[mac[i] >> 4]);
        out.push_back(hex[mac[i] & 15]);
    }
    return out;
#else
    (void)key;
    (void)value;
    return "";
#endif
}

std::string random_secret() {
    unsigned char bytes[64];
#ifndef _WIN32
    if (::getentropy(bytes, sizeof bytes) != 0) return "";
#else
    return "";
#endif
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(128);
    for (unsigned char b : bytes) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 15]);
    }
    return out;
}

#ifndef _WIN32

namespace {

std::string whose(unsigned owner) { return owner == 0 ? "root's" : "uid " + std::to_string(owner) + "'s"; }
std::string mode_text(mode_t m) {
    return std::to_string((m >> 6) & 7) + std::to_string((m >> 3) & 7) + std::to_string(m & 7);
}
// The command that makes a path its owner's alone, for the refusal's run_as_root.
std::string own_command(const std::string& path, unsigned owner, const char* mode) {
    return (owner == 0 ? "chown root:root " + path + " && " : std::string()) + "chmod " + mode + " " + path;
}

bool fingerprint_key(int dfd, unsigned owner, std::string& key, bool create = true);

// ---- the exposure ledger ----
// `.exposed` beside the key: one line per variable whose value others could read (its
// site, its name, the value's fingerprint, when), so a warning to rotate outlives the
// moment the directory was closed (2026-09-27 report: a routine task on another site
// closed it, and health went from "rotate what it holds" to "nothing to rotate"). An entry
// stays until that variable's value changes or goes; no value is ever written here.
struct Exposure {
    std::string site, name, fp;
    long long at = 0;
};
constexpr const char* kLedger = ".exposed";

std::vector<Exposure> ledger_read(int dfd, unsigned owner) {
    std::vector<Exposure> out;
    const int fd = ::openat(dfd, kLedger, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return out;
    struct stat sb {};
    if (::fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_uid != owner || sb.st_nlink != 1 || (sb.st_mode & 077) != 0 || sb.st_size > 256 * 1024) {
        ::close(fd);
        return out;
    }
    std::string text(static_cast<std::size_t>(sb.st_size), '\0');
    const ssize_t n = ::read(fd, text.data(), text.size());
    ::close(fd);
    text.resize(n > 0 ? static_cast<std::size_t>(n) : 0);
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) nl = text.size();
        const std::string line = text.substr(pos, nl - pos);
        pos = nl + 1;
        if (line.empty() || line[0] == '#') continue;
        Exposure e;
        std::size_t a = line.find(' '), b = a == std::string::npos ? a : line.find(' ', a + 1), c = b == std::string::npos ? b : line.find(' ', b + 1);
        if (c == std::string::npos) continue;
        e.site = line.substr(0, a);
        e.name = line.substr(a + 1, b - a - 1);
        e.fp = line.substr(b + 1, c - b - 1);
        e.at = std::atoll(line.c_str() + c + 1);
        if (valid_site(e.site) && env_name(e.name) && e.fp.size() == 16) out.push_back(std::move(e));
    }
    return out;
}

void ledger_write(int dfd, unsigned owner, const std::vector<Exposure>& entries) {
    if (::geteuid() != owner) return;
    if (entries.empty()) {
        ::unlinkat(dfd, kLedger, 0);
        return;
    }
    std::string text = "# values of the sites' environments others could read: site NAME fingerprint unix-time (agensio; no value is kept here)\n";
    for (const auto& e : entries) text += e.site + " " + e.name + " " + e.fp + " " + std::to_string(e.at) + "\n";
    const char* tmp = ".exposed.tmp";
    ::unlinkat(dfd, tmp, 0);
    const int f = ::openat(dfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (f < 0) return;
    const bool ok = ::fchmod(f, 0600) == 0 && ::write(f, text.data(), text.size()) == static_cast<ssize_t>(text.size()) && ::fsync(f) == 0;
    ::close(f);
    if (!ok || ::renameat(dfd, tmp, dfd, kLedger) != 0) ::unlinkat(dfd, tmp, 0);
}

// Records every variable of `site` as readable by others, once per value.
void ledger_record(int dfd, unsigned owner, std::string_view site, const std::vector<Var>& vars) {
    std::string key;
    if (vars.empty() || ::geteuid() != owner || !fingerprint_key(dfd, owner, key, true)) return;
    std::vector<Exposure> led = ledger_read(dfd, owner);
    bool changed = false;
    for (const auto& v : vars) {
        const std::string fp = fingerprint(key, v.value);
        if (fp.empty()) continue;
        if (std::none_of(led.begin(), led.end(), [&](const Exposure& e) { return e.site == site && e.name == v.name && e.fp == fp; })) {
            led.push_back({std::string(site), v.name, fp, static_cast<long long>(std::time(nullptr))});
            changed = true;
        }
    }
    if (changed) ledger_write(dfd, owner, led);
}

// The recorded entries of `site` whose value is still the one others could read; with
// `prune`, the entries of values that changed or went are dropped from the ledger.
std::vector<Exposure> ledger_current(int dfd, unsigned owner, std::string_view site, const std::vector<Var>& vars, bool prune) {
    std::vector<Exposure> led = ledger_read(dfd, owner), still, keep;
    std::string key;
    if (led.empty() || !fingerprint_key(dfd, owner, key, false)) return still;
    for (auto& e : led) {
        if (e.site != site) {
            keep.push_back(std::move(e));
            continue;
        }
        const auto it = std::find_if(vars.begin(), vars.end(), [&](const Var& v) { return v.name == e.name; });
        if (it == vars.end() || fingerprint(key, it->value) != e.fp) continue;  // rotated or removed: nothing left to warn about
        still.push_back(e);
        keep.push_back(std::move(e));
    }
    if (prune && keep.size() != led.size()) ledger_write(dfd, owner, keep);
    return still;
}

std::string when_text(long long at) {
    const std::time_t t = static_cast<std::time_t>(at);
    std::tm tm {};
    ::gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M UTC", &tm);
    return buf;
}

// The directory was open to others until this pass closed it: every file in it that others
// could read may have leaked. Each is recorded in the ledger and, unless others could also
// write it (then refused until replaced), made 0600 now, in the same pass.
void expose_scan(int dfd, const std::string& dir, unsigned owner, Status& st) {
    std::vector<std::string> leaves;
    if (DIR* d = ::fdopendir(::dup(dfd))) {
        while (const struct dirent* e = ::readdir(d)) {
            const std::string_view name = e->d_name;
            if (name.size() > 4 && name.ends_with(".env") && name.front() != '.') leaves.emplace_back(name);
        }
        ::closedir(d);
    }
    for (const auto& leaf : leaves) {
        const int fd = ::openat(dfd, leaf.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) continue;
        struct stat sb {};
        if (::fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_uid != owner || sb.st_nlink != 1 || (sb.st_mode & 044) == 0 ||
            static_cast<std::size_t>(sb.st_size) > kMaxFile) {
            ::close(fd);
            continue;
        }
        std::string text(static_cast<std::size_t>(sb.st_size), '\0');
        const ssize_t n = ::read(fd, text.data(), text.size());
        text.resize(n > 0 ? static_cast<std::size_t>(n) : 0);
        std::vector<Var> vars;
        std::string why;
        const std::string site = leaf.substr(0, leaf.size() - 4);
        if (valid_site(site) && parse(text, vars, why)) ledger_record(dfd, owner, site, vars);
        const std::string path = dir + "/" + leaf;
        if ((sb.st_mode & 022) == 0 && ::fchmod(fd, 0600) == 0)
            st.notes.push_back(path + " was mode " + mode_text(sb.st_mode) + " while its directory was open to others, so others could read it; made 0600: "
                               "rotate what it holds (health warns for " + site + " until the values change)");
        else
            st.notes.push_back(path + " was readable and writable by others while its directory was open: replace it and rotate what it held (it is refused until then)");
        ::close(fd);
    }
}

// The open directory, checked: -1 with `st.error` (and `st.fix`), or -2 when it does not
// exist. A directory that is the owner's but open to its group or others is tightened to
// 0700 when this process is that owner (2026-09-27 report: a `mkdir -p` under a lax umask
// left it 0775 and every task of every Rails site on the host stopped); nothing inside is
// trusted for it, as every file is checked on its own (owner, mode, one link).
int open_dir(const std::string& dir, unsigned owner, Status& st) {
    const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return -2;
        st.error = dir + ": " + (errno == ELOOP || errno == ENOTDIR ? std::string("a symlink or not a directory; refused") : std::strerror(errno));
        if (errno == ELOOP || errno == ENOTDIR) st.fix = "mv " + dir + " " + dir + ".refused && mkdir -m 0700 " + dir;
        return -1;
    }
    struct stat sb {};
    if (::fstat(fd, &sb) != 0 || sb.st_uid != owner) {
        st.error = dir + " must be " + whose(owner) + " alone (0700); it is uid " + std::to_string(sb.st_uid) + "'s, mode " + mode_text(sb.st_mode) + "; refused";
        st.fix = own_command(dir, owner, "0700");
        ::close(fd);
        return -1;
    }
    if ((sb.st_mode & 077) != 0) {
        if (::geteuid() != owner || ::fchmod(fd, 0700) != 0) {
            st.error = dir + " must be " + whose(owner) + " alone (0700); it is mode " + mode_text(sb.st_mode) + "; refused";
            st.fix = own_command(dir, owner, "0700");
            ::close(fd);
            return -1;
        }
        st.notes.push_back(dir + " was mode " + mode_text(sb.st_mode) + ", open to its group or others; made 0700");
        st.dir_was_open = true;
        expose_scan(fd, dir, owner, st);  // every file others could read, now, before this pass forgets the directory was open
    }
    return fd;
}

bool read_at(int dfd, const std::string& dir, std::string_view site, unsigned owner, std::vector<Var>& out, Status& st) {
    const std::string leaf = std::string(site) + ".env";
    const std::string path = dir + "/" + leaf;
    const int fd = ::openat(dfd, leaf.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return true;
        st.error = path + ": " + (errno == ELOOP ? std::string("a symlink; refused") : std::strerror(errno));
        st.fix = "rm " + path;
        return false;
    }
    st.exists = true;
    struct stat sb {};
    // One link only: with fs.protected_hardlinks off, a link to another root file planted in
    // a directory that was open to others would be read as this site's environment.
    if (::fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_uid != owner || sb.st_nlink != 1 || (sb.st_mode & 022) != 0 ||
        static_cast<std::size_t>(sb.st_size) > kMaxFile) {
        st.error = path + " must be a regular file with one link, " + whose(owner) + ", mode 0600, at most 64 KB; refused";
        st.fix = sb.st_uid == owner && S_ISREG(sb.st_mode) && sb.st_nlink == 1 ? own_command(path, owner, "0600") + "   # after checking its content" : "rm " + path;
        ::close(fd);
        return false;
    }
    if ((sb.st_mode & 077) != 0) {  // readable by others, never writable (above): tightened
        if (::geteuid() != owner || ::fchmod(fd, 0600) != 0) {
            st.error = path + " must be mode 0600; it is " + mode_text(sb.st_mode) + "; refused";
            st.fix = own_command(path, owner, "0600");
            ::close(fd);
            return false;
        }
        // Rotation is advice only when others could have reached the file: through a
        // directory that was open too (2026-09-27 report: advised under a 0700 directory).
        st.notes.push_back(path + " was mode " + mode_text(sb.st_mode) + "; made 0600" +
                           (st.dir_was_open ? " (its directory was open to others as well: rotate what it holds)"
                                            : " (its directory was " + whose(owner) + " alone, so nobody else could reach it; nothing to rotate)"));
    }
    std::string text(static_cast<std::size_t>(sb.st_size), '\0');
    std::size_t got = 0;
    while (got < text.size()) {
        const ssize_t n = ::read(fd, text.data() + got, text.size() - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        got += static_cast<std::size_t>(n);
    }
    ::close(fd);
    text.resize(got);
    std::vector<Var> vars;
    std::string why;
    if (!parse(text, vars, why)) {
        st.error = path + ": " + why;
        return false;
    }
    for (const auto& v : vars) {
        std::string bad = check_name(v.name);
        if (bad.empty()) bad = check_value(v.value);
        if (!bad.empty()) {
            st.error = path + ": " + bad + " (remove that line, or site_env_set with unset)";
            return false;
        }
    }
    if (vars.size() > kMaxVars) {
        st.error = path + ": more than " + std::to_string(kMaxVars) + " variables";
        return false;
    }
    out = std::move(vars);
    return true;
}

json::Value names_of(const std::vector<std::string>& v) {
    json::Value a = json::Value::array();
    for (const auto& n : v) a.push(n);
    return a;
}

json::Value failure(const Status& st) {
    json::Value f = json::Value::object().set("ok", false).set("error", st.error);
    if (!st.fix.empty()) f.set("run_as_root", json::Value::array().push(st.fix));
    return f;
}

// The key of the fingerprints: 32 random bytes in `<dir>/.fingerprint.key`, the owner's,
// 0600, made on first use. Keyed so a fingerprint of a weak password cannot be looked up
// in a dictionary; kept so a value keeps its fingerprint across restarts and hosts' eyes.
bool fingerprint_key(int dfd, unsigned owner, std::string& key, bool create) {
    const char* leaf = ".fingerprint.key";
    int fd = ::openat(dfd, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT && create && ::geteuid() == owner) {
        unsigned char bytes[32];
        if (::getentropy(bytes, sizeof bytes) != 0) return false;
        const int w = ::openat(dfd, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (w >= 0) {
            const bool ok = ::write(w, bytes, sizeof bytes) == static_cast<ssize_t>(sizeof bytes) && ::fsync(w) == 0;
            ::close(w);
            if (!ok) {
                ::unlinkat(dfd, leaf, 0);
                return false;
            }
        }
        fd = ::openat(dfd, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);  // ours, or another writer's that won the race
    }
    if (fd < 0) return false;
    struct stat sb {};
    char buf[32];
    const bool ok = ::fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode) && sb.st_uid == owner && sb.st_nlink == 1 && (sb.st_mode & 077) == 0 &&
                    ::read(fd, buf, sizeof buf) == static_cast<ssize_t>(sizeof buf);
    ::close(fd);
    if (ok) key.assign(buf, sizeof buf);
    return ok;
}

}  // namespace

bool read(const std::string& dir, std::string_view site, unsigned owner, std::vector<Var>& out, Status& st) {
    out.clear();
    if (!valid_site(site)) {
        st.error = "'" + std::string(site) + "' is not a site's host name";
        return false;
    }
    const int dfd = open_dir(dir, owner, st);
    if (dfd == -2) return true;
    if (dfd < 0) return false;
    const bool ok = read_at(dfd, dir, site, owner, out, st);
    ::close(dfd);
    return ok;
}

json::Value describe(const std::string& dir, std::string_view site, unsigned owner, const std::vector<std::string>& reveal) {
    Status st;
    std::vector<Var> vars;
    if (!read(dir, site, owner, vars, st)) return failure(st);
    std::string key;
    if (!vars.empty()) {
        const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dfd >= 0) {
            fingerprint_key(dfd, owner, key);
            ::close(dfd);
        }
    }
    json::Value list = json::Value::array(), revealed = json::Value::array(), unknown = json::Value::array();
    for (const auto& v : vars) {
        json::Value item = json::Value::object().set("name", v.name).set("length", static_cast<double>(v.value.size()));
        if (!key.empty()) item.set("fingerprint", fingerprint(key, v.value));
        if (std::find(reveal.begin(), reveal.end(), v.name) != reveal.end()) {
            item.set("value", v.value);
            revealed.push(v.name);
        }
        list.push(std::move(item));
    }
    for (const auto& r : reveal)
        if (std::none_of(vars.begin(), vars.end(), [&](const Var& v) { return v.name == r; })) unknown.push(r);
    json::Value out = json::Value::object().set("ok", true).set("site", std::string(site)).set("file", dir + "/" + std::string(site) + ".env")
                          .set("exists", st.exists).set("variables", std::move(list)).set("revealed", std::move(revealed));
    if (!unknown.items().empty()) out.set("not_found", std::move(unknown));
    if (!st.notes.empty()) out.set("tightened", names_of(st.notes));
    return out;
}

json::Value apply(const std::string& dir, std::string_view site, unsigned owner, const Change& change) {
    static std::mutex serial;  // two writers in one process never interleave a read and a rename
    const std::lock_guard lock(serial);
    json::Value fail = json::Value::object().set("ok", false);
    if (!valid_site(site)) return fail.set("error", "'" + std::string(site) + "' is not a site's host name");
    if (::geteuid() != owner) return fail.set("error", "the environment files are " + whose(owner) + "; this process is not");
    Status st;
    if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) return fail.set("error", "mkdir " + dir + ": " + std::strerror(errno));
    const int dfd = open_dir(dir, owner, st);
    if (dfd < 0) {
        if (dfd == -2) st.error = dir + " vanished";
        return failure(st);
    }
    std::vector<Var> vars;
    if (!read_at(dfd, dir, site, owner, vars, st)) {
        ::close(dfd);
        return failure(st);
    }
    std::vector<std::string> set, unset, absent, generated, kept;
    for (const auto& name : change.unset) {
        const auto it = std::find_if(vars.begin(), vars.end(), [&](const Var& v) { return v.name == name; });
        if (it == vars.end()) {
            absent.push_back(name);
            continue;
        }
        vars.erase(it);
        unset.push_back(name);
    }
    for (const auto& v : change.set) {
        put(vars, v.name, v.value);
        set.push_back(v.name);
    }
    for (const auto& name : change.generate) {
        if (std::any_of(vars.begin(), vars.end(), [&](const Var& v) { return v.name == name; })) {
            kept.push_back(name);
            continue;
        }
        std::string secret = random_secret();
        if (secret.empty()) {
            ::close(dfd);
            return fail.set("error", std::string("no random bytes from the system: ") + std::strerror(errno));
        }
        vars.push_back({name, std::move(secret)});
        generated.push_back(name);
    }
    const std::string leaf = std::string(site) + ".env";
    const std::string path = dir + "/" + leaf;
    const std::string text = render(vars, site);
    if (vars.size() > kMaxVars || text.size() > kMaxFile) {
        ::close(dfd);
        return fail.set("error", "the environment would hold more than " + std::to_string(kMaxVars) + " variables or 64 KB");
    }
    const bool changed = !set.empty() || !unset.empty() || !generated.empty();
    bool removed = false;
    if (changed && vars.empty()) {
        if (::unlinkat(dfd, leaf.c_str(), 0) != 0 && errno != ENOENT) {
            ::close(dfd);
            return fail.set("error", "remove " + path + ": " + std::strerror(errno));
        }
        removed = st.exists;
    } else if (changed) {
        const std::string tmp = leaf + ".tmp";
        ::unlinkat(dfd, tmp.c_str(), 0);  // left by a write that died
        const int f = ::openat(dfd, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        bool ok = f >= 0 && ::fchmod(f, 0600) == 0;
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
            ::close(dfd);
            return fail.set("error", "write " + path + ": " + std::strerror(e));
        }
        ::fsync(dfd);
    }
    ::close(dfd);
    std::vector<std::string> names;
    for (const auto& v : vars) names.push_back(v.name);
    json::Value out = json::Value::object().set("ok", true).set("file", path).set("set", names_of(set)).set("unset", names_of(unset)).set("absent", names_of(absent))
        .set("generated", names_of(generated)).set("kept", names_of(kept)).set("names", names_of(names));
    if (!st.notes.empty()) out.set("tightened", names_of(st.notes));
    if (removed) out.set("removed", path);
    // A changed or removed value is no longer the one others could read: its ledger entry goes.
    if (const int ld = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); ld >= 0) {
        ledger_current(ld, owner, site, vars, true);
        ::close(ld);
    }  // no variable left: no file (2026-09-27 report: the answer said only names: [])
    return out;
}

json::Value inspect(const std::string& dir, unsigned owner, const std::vector<std::string>& sites) {
    json::Value found = json::Value::array(), orphans = json::Value::array(), present = json::Value::array();
    const json::Value none = json::Value::object().set("ok", true).set("sites", json::Value::array()).set("orphans", json::Value::array()).set("present", json::Value::array());
    const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) return none;  // absent, or health's own directory check names it
    // A directory open to others (or not the owner's) let others reach every file in it:
    // a file others can read there may have leaked, and says so (2026-09-27 report: it was
    // info beside a warn for the directory, while the helper's own note said to rotate).
    struct stat db {};
    const bool dir_open = ::fstat(dfd, &db) == 0 && (db.st_uid != owner || (db.st_mode & 077) != 0);
    const std::string leaked = "; the directory is open to others as well, so they could read it: rotate what it holds once both are fixed";
    for (const auto& site : sites) {
        if (!valid_site(site)) continue;
        const std::string leaf = site + ".env", path = dir + "/" + leaf;
        struct stat sb {};
        if (::fstatat(dfd, leaf.c_str(), &sb, AT_SYMLINK_NOFOLLOW) != 0) continue;  // no file: nothing to meet
        present.push(site);
        auto add = [&](const char* severity, std::string problem, std::string fix) {
            json::Value v = json::Value::object().set("site", site).set("severity", severity).set("problem", std::move(problem));
            if (!fix.empty()) v.set("fix", std::move(fix));
            found.push(std::move(v));
        };
        const bool readable = (sb.st_mode & 044) != 0;
        if (S_ISLNK(sb.st_mode) || !S_ISREG(sb.st_mode)) {
            add("warn", path + " is a symlink or not a regular file: every task of " + site + " is refused", "rm " + path);
            continue;
        }
        if (sb.st_uid != owner || sb.st_nlink != 1 || (sb.st_mode & 022) != 0 || static_cast<std::size_t>(sb.st_size) > kMaxFile) {
            add("warn", path + " is uid " + std::to_string(sb.st_uid) + "'s, mode " + mode_text(sb.st_mode) + ", " + std::to_string(sb.st_nlink) +
                            " link(s): it must be " + whose(owner) + ", 0600, one link; every task of " + site + " is refused" +
                            (dir_open && readable ? leaked : ""),
                sb.st_uid == owner && sb.st_nlink == 1 ? own_command(path, owner, "0600") + "   # after checking its content" : "rm " + path);
            continue;
        }
        // What a task would meet inside it: a line systemd reads otherwise, a refused name.
        const int fd = ::openat(dfd, leaf.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) continue;
        std::string text(static_cast<std::size_t>(sb.st_size), '\0');
        const ssize_t n = ::read(fd, text.data(), text.size());
        ::close(fd);
        text.resize(n > 0 ? static_cast<std::size_t>(n) : 0);
        std::vector<Var> vars;
        std::string why;
        if (!parse(text, vars, why)) {
            add("warn", path + ": " + why + "; every task of " + site + " is refused", "");
            continue;
        }
        bool refused = false;
        for (const auto& v : vars)
            if (std::string bad = check_name(v.name).empty() ? check_value(v.value) : check_name(v.name); !bad.empty()) {
                add("warn", path + ": " + bad + "; every task of " + site + " is refused", "site_env_set " + site + " with unset: [\"" + v.name + "\"]");
                refused = true;
                break;
            }
        if (refused) continue;
        if (dir_open && readable) {
            // Readable by others right now: recorded, so the warning outlives the directory's
            // closing (which the next task or site_env does, for any site).
            ledger_record(dfd, owner, site, vars);
            add("warn", path + " is mode " + mode_text(sb.st_mode) + ", readable by others" + leaked, own_command(path, owner, "0600"));
            continue;
        }
        const std::vector<Exposure> exposed = ledger_current(dfd, owner, site, vars, false);
        if (!exposed.empty()) {
            std::string names;
            long long first = exposed.front().at;
            for (const auto& e : exposed) {
                names += (names.empty() ? "" : ", ") + e.name;
                first = std::min(first, e.at);
            }
            add("warn", path + ": " + names + (exposed.size() == 1 ? " was" : " were") + " readable by others (seen " + when_text(first) +
                            ") and " + (exposed.size() == 1 ? "has" : "have") + " not changed since: rotate " + (exposed.size() == 1 ? "it" : "them"),
                "site_env_set " + site + " with unset and generate for a generated secret (SECRET_KEY_BASE), set with new values for the others, "
                "changed where they are used too (a database password in the database); the warning ends when every value has changed");
        }
        if ((sb.st_mode & 077) != 0)
            add("info", path + " is mode " + mode_text(sb.st_mode) + ", but its directory is " + whose(owner) +
                            " alone, so nobody else can reach it now: the next task or site_env makes it 0600", own_command(path, owner, "0600"));
    }
    // The files no configured site names: a deleted site's secrets, kept on purpose or forgotten.
    if (DIR* d = ::fdopendir(::dup(dfd))) {
        while (const struct dirent* e = ::readdir(d)) {
            const std::string_view name = e->d_name;
            if (name.size() <= 4 || !name.ends_with(".env") || name.front() == '.') continue;
            const std::string_view site = name.substr(0, name.size() - 4);
            if (std::find(sites.begin(), sites.end(), site) == sites.end()) orphans.push(dir + "/" + std::string(name));
        }
        ::closedir(d);
    }
    ::close(dfd);
    return json::Value::object().set("ok", true).set("sites", std::move(found)).set("orphans", std::move(orphans)).set("present", std::move(present));
}

#endif

}  // namespace agensio::appenv
