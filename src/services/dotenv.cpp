#include "services/dotenv.hpp"

#include "config.hpp"

#include "services/files.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace agensio::dotenv {

namespace {

bool name_char(char c, bool first) noexcept {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || (!first && ((c >= '0' && c <= '9') || c == '.'));
}

// The assignment a line starts, if it is one: its name, where its value starts, whether "export ".
bool assignment_head(std::string_view line, std::string& name, std::size_t& value_at) {
    std::size_t i = line.find_first_not_of(" \t");
    if (i == std::string_view::npos) return false;
    if (line.substr(i).starts_with("export ")) {
        i += 7;
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
    }
    const std::size_t start = i;
    if (i >= line.size() || !name_char(line[i], true)) return false;
    while (i < line.size() && name_char(line[i], false)) ++i;
    name = std::string(line.substr(start, i - start));
    while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
    if (i >= line.size() || line[i] != '=') return false;
    ++i;
    while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
    value_at = i;
    return name.size() <= 64;
}

}  // namespace

std::vector<Line> parse(std::string_view text) {
    std::vector<std::string_view> raw;
    for (std::size_t at = 0; at < text.size();) {
        const std::size_t end = std::min(text.find('\n', at), text.size());
        raw.push_back(text.substr(at, end - at));
        at = end + 1;
    }
    std::vector<Line> out;
    for (std::size_t k = 0; k < raw.size(); ++k) {
        Line l;
        l.raw = std::string(raw[k]);
        std::size_t v = 0;
        if (!assignment_head(raw[k], l.name, v)) {
            l.name.clear();
            out.push_back(std::move(l));
            continue;
        }
        l.assignment = true;
        const std::string_view rest = raw[k].substr(v);
        if (!rest.empty() && (rest.front() == '\'' || rest.front() == '"')) {
            const char q = rest.front();
            std::string value;
            bool closed = false;
            for (std::size_t i = 1; i < rest.size(); ++i) {
                if (q == '"' && rest[i] == '\\' && i + 1 < rest.size() && (rest[i + 1] == '"' || rest[i + 1] == '\\')) {
                    value.push_back(rest[++i]);
                    continue;
                }
                if (rest[i] == q) {
                    closed = true;
                    break;
                }
                value.push_back(rest[i]);
            }
            if (!closed) {
                // A value over several lines: kept whole, never read or rewritten.
                l.readable = false;
                while (k + 1 < raw.size()) {
                    l.raw += "\n" + std::string(raw[++k]);
                    if (raw[k].find(q) != std::string_view::npos) break;
                }
            } else {
                l.value = std::move(value);
            }
        } else {
            // Unquoted: up to a " #" comment, the blanks at its end left out.
            std::size_t end = rest.size();
            for (std::size_t i = 0; i < rest.size(); ++i)
                if (rest[i] == '#' && i > 0 && (rest[i - 1] == ' ' || rest[i - 1] == '\t')) {
                    end = i;
                    break;
                }
            std::string_view val = rest.substr(0, end);
            while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r')) val.remove_suffix(1);
            l.value = std::string(val);
        }
        out.push_back(std::move(l));
    }
    return out;
}

std::string check_name(std::string_view name) {
    if (name.empty() || name.size() > 64 || !name_char(name.front(), true) ||
        !std::all_of(name.begin() + 1, name.end(), [](char c) { return name_char(c, false); }))
        return "'" + std::string(name.substr(0, 64)) + "' is not a variable name of a .env (letters, digits, '_' and '.', not starting with a digit)";
    return "";
}

std::string render_value(std::string_view value, std::string& out) {
    if (std::string why = appenv::check_value(value); !why.empty()) return why;
    const bool plain = std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || std::string_view("_./:@+=,-").find(c) != std::string_view::npos;
    });
    if (plain) {
        out = std::string(value);
    } else if (value.find('\'') == std::string_view::npos) {
        out = "'" + std::string(value) + "'";  // literal: phpdotenv reads a single-quoted value as it stands
    } else if (value.find_first_of("\"\\$") == std::string_view::npos) {
        out = "\"" + std::string(value) + "\"";
    } else {
        return "a value holding a single quote and a double quote, a backslash or a dollar sign cannot be written so phpdotenv reads it back the same";
    }
    return "";
}

std::string laravel_key() {
    unsigned char bytes[32];
#ifndef _WIN32
    if (::getentropy(bytes, sizeof bytes) != 0) return "";
#else
    return "";
#endif
    return "base64:" + files::base64_encode(std::string_view(reinterpret_cast<const char*>(bytes), sizeof bytes));
}

Result apply(std::string_view text, const appenv::Change& change) {
    Result r;
    std::vector<Line> lines = parse(text);
    auto lines_of = [&](const std::string& name) {
        std::vector<std::size_t> at;
        for (std::size_t i = 0; i < lines.size(); ++i)
            if (lines[i].assignment && lines[i].name == name) at.push_back(i);
        return at;
    };
    auto refuse_unreadable = [&](const std::string& name) {
        for (std::size_t i : lines_of(name))
            if (!lines[i].readable) {
                r.error = name + "'s value goes on over several lines in the file, which this does not rewrite: change it with site_file_edit";
                return true;
            }
        return false;
    };
    std::vector<bool> drop(lines.size(), false);
    std::vector<std::string> appended;
    auto put = [&](const std::string& name, const std::string& value) {
        std::string rendered;
        if (std::string why = render_value(value, rendered); !why.empty()) {
            r.error = name + ": " + why;
            return false;
        }
        const auto at = lines_of(name);
        if (at.empty()) {
            appended.push_back(name + "=" + rendered);
        } else {
            const bool exported = lines[at.front()].raw.find("export ") != std::string::npos &&
                                  lines[at.front()].raw.find("export ") < lines[at.front()].raw.find(name);
            lines[at.front()].raw = (exported ? "export " : "") + name + "=" + rendered;
            for (std::size_t k = 1; k < at.size(); ++k) drop[at[k]] = true;
        }
        return true;
    };
    for (const auto& v : change.set) {
        if (std::string why = check_name(v.name); !why.empty()) return r.error = why, r;
        if (refuse_unreadable(v.name) || !put(v.name, v.value)) return r;
        r.set.push_back(v.name);
    }
    for (const auto& n : change.unset) {
        if (std::string why = check_name(n); !why.empty()) return r.error = why, r;
        const auto at = lines_of(n);
        if (at.empty()) r.absent.push_back(n);
        else r.unset.push_back(n);
        for (std::size_t i : at) drop[i] = true;
    }
    for (const auto& n : change.generate) {
        if (std::string why = check_name(n); !why.empty()) return r.error = why, r;
        if (refuse_unreadable(n)) return r;
        const auto at = lines_of(n);
        if (!at.empty() && !lines[at.front()].value.empty()) {
            r.kept.push_back(n);
            continue;
        }
        const std::string value = n == "APP_KEY" ? laravel_key() : appenv::random_secret();
        if (value.empty()) return r.error = "no random bytes could be read for " + n, r;
        if (!put(n, value)) return r;
        r.generated.push_back(n);
    }
    // The text: every line kept but those dropped, the new ones at the end (before trailing blanks).
    std::vector<std::string> out;
    for (std::size_t i = 0; i < lines.size(); ++i)
        if (!drop[i]) out.push_back(lines[i].raw);
    std::size_t tail = out.size();
    while (tail > 0 && out[tail - 1].find_first_not_of(" \t\r") == std::string::npos) --tail;
    out.insert(out.begin() + static_cast<std::ptrdiff_t>(tail), appended.begin(), appended.end());
    for (const auto& l : out) r.text += l + "\n";
    return r;
}

json::Value describe(std::string_view text, std::string_view key, const std::vector<std::string>& reveal) {
    json::Value vars = json::Value::array(), revealed = json::Value::array(), not_found = json::Value::array();
    std::vector<std::string> seen;
    for (const auto& l : parse(text)) {
        if (!l.assignment) continue;
        seen.push_back(l.name);
        json::Value v = json::Value::object().set("name", l.name);
        if (!l.readable) {
            v.set("length", nullptr).set("note", "its value goes on over several lines");
        } else {
            v.set("length", static_cast<double>(l.value.size())).set("fingerprint", l.value.empty() ? std::string() : appenv::fingerprint(key, l.value));
            if (std::find(reveal.begin(), reveal.end(), l.name) != reveal.end()) {
                v.set("value", l.value);
                revealed.push(l.name);
            }
        }
        vars.push(std::move(v));
    }
    for (const auto& n : reveal)
        if (std::find(seen.begin(), seen.end(), n) == seen.end()) not_found.push(n);
    json::Value out = json::Value::object().set("variables", std::move(vars)).set("revealed", std::move(revealed));
    if (!not_found.items().empty()) out.set("not_found", std::move(not_found));
    return out;
}

#ifndef _WIN32

namespace {

json::Value fail(std::string why) { return json::Value::object().set("ok", false).set("error", std::move(why)); }

// The directory that holds the file: the project and every directory below it on the way, each opened
// without following a symlink, a directory of `account` or root, writable by no other. The descriptor,
// with `leaf` the file's name, or -1 with `why`.
int open_parent(const std::string& project, const std::string& rel, unsigned account, std::string& leaf, std::string& why) {
    if (const std::string bad = check_env_file(rel); !bad.empty()) {
        why = bad;
        return -1;
    }
    int fd = ::open(project.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    std::string path = project;
    auto check = [&](int d) {
        struct stat st {};
        if (::fstat(d, &st) != 0) return std::string(std::strerror(errno));
        if (st.st_uid != account && st.st_uid != 0) return path + " belongs to uid " + std::to_string(st.st_uid) + ", neither the site's account nor root; refused";
        if (st.st_mode & 002) return path + " is writable by others; refused";
        return std::string();
    };
    if (fd < 0) {
        why = project + ": " + (errno == ELOOP || errno == ENOTDIR ? std::string("a symlink or not a directory; refused") : std::strerror(errno));
        return -1;
    }
    if (std::string bad = check(fd); !bad.empty()) {
        ::close(fd);
        why = bad;
        return -1;
    }
    std::size_t at = 0;
    while (true) {
        const std::size_t slash = rel.find('/', at);
        if (slash == std::string::npos) break;
        const std::string seg = rel.substr(at, slash - at);
        path += "/" + seg;
        const int next = ::openat(fd, seg.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        const int e = errno;
        ::close(fd);
        if (next < 0) {
            why = path + ": " + (e == ENOENT ? std::string("does not exist (site_dir_create makes it)")
                                 : e == ELOOP || e == ENOTDIR ? std::string("a symlink or not a directory; refused")
                                                              : std::strerror(e));
            return -1;
        }
        fd = next;
        if (std::string bad = check(fd); !bad.empty()) {
            ::close(fd);
            why = bad;
            return -1;
        }
        at = slash + 1;
    }
    leaf = rel.substr(at);
    return fd;
}

// The file's text when it is there: regular, one link, root's or the account's, at most 64 KB.
bool read_leaf(int dfd, const std::string& leaf, const std::string& abs, unsigned account, std::string& text, bool& exists, std::string& why) {
    exists = false;
    const int fd = ::openat(dfd, leaf.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT) return true;
        why = abs + ": " + (errno == ELOOP ? std::string("a symlink; refused") : std::strerror(errno));
        return false;
    }
    struct stat st {};
    bool ok = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1 && (st.st_uid == 0 || st.st_uid == account) &&
              static_cast<std::uint64_t>(st.st_size) <= appenv::kMaxFile;
    if (!ok) {
        ::close(fd);
        why = abs + " must be a regular file with one link, root's or the site's account's, of at most 64 KB; refused";
        return false;
    }
    text.resize(static_cast<std::size_t>(st.st_size));
    std::size_t got = 0;
    while (got < text.size()) {
        const ssize_t n = ::read(fd, text.data() + got, text.size() - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        got += static_cast<std::size_t>(n);
    }
    text.resize(got);
    ::close(fd);
    exists = true;
    return true;
}

json::Value names(const std::vector<std::string>& v) {
    json::Value a = json::Value::array();
    for (const auto& n : v) a.push(n);
    return a;
}

}  // namespace

json::Value read_file(const std::string& project, const std::string& rel, std::string_view key, const std::vector<std::string>& reveal, unsigned account) {
    std::string leaf, why, text;
    const int dfd = open_parent(project, rel, account, leaf, why);
    if (dfd < 0) return fail(std::move(why));
    const std::string abs = project + "/" + rel;
    bool exists = false;
    const bool ok = read_leaf(dfd, leaf, abs, account, text, exists, why);
    ::close(dfd);
    if (!ok) return fail(std::move(why));
    json::Value v = describe(text, key, reveal);
    return v.set("ok", true).set("file", abs).set("exists", exists);
}

json::Value write_file(const std::string& project, const std::string& rel, unsigned owner, unsigned group, const appenv::Change& change, unsigned account) {
    std::string leaf, why, text;
    const int dfd = open_parent(project, rel, account, leaf, why);
    if (dfd < 0) return fail(std::move(why));
    const std::string abs = project + "/" + rel;
    bool exists = false;
    if (!read_leaf(dfd, leaf, abs, account, text, exists, why)) {
        ::close(dfd);
        return fail(std::move(why));
    }
    const Result r = dotenv::apply(text, change);
    if (!r.error.empty()) {
        ::close(dfd);
        return fail(r.error);
    }
    const std::string tmp = ".agensio-env." + std::to_string(::getpid());
    ::unlinkat(dfd, tmp.c_str(), 0);
    const int fd = ::openat(dfd, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        const int e = errno;
        ::close(dfd);
        return fail("cannot write beside " + abs + ": " + std::strerror(e));
    }
    bool ok = ::fchown(fd, owner, group) == 0 && ::fchmod(fd, 0640) == 0;
    for (std::size_t off = 0; ok && off < r.text.size();) {
        const ssize_t w = ::write(fd, r.text.data() + off, r.text.size() - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) ok = false;
        else off += static_cast<std::size_t>(w);
    }
    ok = ok && ::fsync(fd) == 0;
    const int e = errno;
    ::close(fd);
    if (!ok || ::renameat(dfd, tmp.c_str(), dfd, leaf.c_str()) != 0) {
        const int re = ok ? errno : e;
        ::unlinkat(dfd, tmp.c_str(), 0);
        ::close(dfd);
        return fail("writing " + abs + ": " + std::strerror(re));
    }
    ::close(dfd);
    return json::Value::object().set("ok", true).set("file", abs).set("mode", "0640").set("set", names(r.set)).set("unset", names(r.unset))
        .set("generated", names(r.generated)).set("kept", names(r.kept)).set("absent", names(r.absent)).set("created", !exists);
}

#endif

}  // namespace agensio::dotenv
