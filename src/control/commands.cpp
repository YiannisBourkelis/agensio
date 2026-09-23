#include "control/commands.hpp"

#include "control/settings.hpp"
#include "control/sites.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>

#include "services/acme.hpp"
#include "services/pools.hpp"

namespace agensio::control {

namespace fs = std::filesystem;

namespace {

int month_of(std::string_view m) {
    static const char* names[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    for (int i = 0; i < 12; ++i)
        if (m == names[i]) return i;
    return -1;
}

bool digits(std::string_view s, std::size_t pos, std::size_t n, int& out) {
    if (pos + n > s.size()) return false;
    out = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const char c = s[pos + i];
        if (c < '0' || c > '9') return false;
        out = out * 10 + (c - '0');
    }
    return true;
}

std::time_t local_to_time(int y, int mo, int d, int h, int mi, int s) {
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = s;
    tm.tm_isdst = -1;
    return std::mktime(&tm);
}

std::time_t utc_to_time(int y, int mo, int d, int h, int mi, int s) {
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = s;
#ifdef _WIN32
    return _mkgmtime(&tm);
#else
    return timegm(&tm);
#endif
}

// "+0300" or "+03:00" -> seconds east of UTC.
bool zone_offset(std::string_view z, long& out) {
    if (z.size() < 5 || (z[0] != '+' && z[0] != '-')) return false;
    int h = 0, m = 0;
    if (!digits(z, 1, 2, h)) return false;
    const std::size_t mpos = z[3] == ':' ? 4 : 3;
    if (!digits(z, mpos, 2, m)) return false;
    out = (h * 3600 + m * 60) * (z[0] == '-' ? -1 : 1);
    return true;
}

std::string lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

}  // namespace

// ---- log lines ----

bool parse_log_line(std::string_view line, LogLine& out) {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.remove_suffix(1);
    if (line.empty()) return false;
    out = LogLine{};
    out.text = std::string(line);
    int y, mo, d, h, mi, s;
    // Error log: "2026/09/18 21:44:39 [warn] message"
    if (line.size() > 22 && line[4] == '/' && line[7] == '/' && line[10] == ' ' && line[13] == ':' && line[16] == ':' &&
        digits(line, 0, 4, y) && digits(line, 5, 2, mo) && digits(line, 8, 2, d) && digits(line, 11, 2, h) &&
        digits(line, 14, 2, mi) && digits(line, 17, 2, s) && line.substr(20, 1) == "[") {
        const std::size_t close = line.find(']', 21);
        if (close == std::string_view::npos) return false;
        out.time = local_to_time(y, mo - 1, d, h, mi, s);
        out.level = std::string(line.substr(21, close - 21));
        out.source = "error";
        return true;
    }
    // JSON access log: {"time":"2026-09-18T21:44:39+03:00",...,"status":404,...}
    if (line.front() == '{') {
        json::Value v;
        std::string err;
        if (!json::parse(line, v, err)) return false;
        const std::string_view t = v.get("time");
        long off = 0;
        if (t.size() < 19 || !digits(t, 0, 4, y) || !digits(t, 5, 2, mo) || !digits(t, 8, 2, d) ||
            !digits(t, 11, 2, h) || !digits(t, 14, 2, mi) || !digits(t, 17, 2, s) || !zone_offset(t.substr(19), off))
            return false;
        out.time = utc_to_time(y, mo - 1, d, h, mi, s) - off;
        out.status = static_cast<int>(v["status"].num());
        return true;
    }
    // Combined: remote - - [18/Sep/2026:21:44:39 +0300] "GET / HTTP/1.1" 404 153 "-" "-"
    const std::size_t open = line.find(" [");
    if (open == std::string_view::npos) return false;
    const std::string_view stamp = line.substr(open + 2);
    long off = 0;
    if (stamp.size() < 26 || !digits(stamp, 0, 2, d) || stamp[2] != '/' || stamp[6] != '/' || !digits(stamp, 7, 4, y) ||
        !digits(stamp, 12, 2, h) || !digits(stamp, 15, 2, mi) || !digits(stamp, 18, 2, s) ||
        (mo = month_of(stamp.substr(3, 3))) < 0 || !zone_offset(stamp.substr(21, 5), off))
        return false;
    out.time = utc_to_time(y, mo, d, h, mi, s) - off;
    // The status is the first number after the closing quote of the request.
    const std::size_t q1 = line.find('"', open);
    const std::size_t q2 = q1 == std::string_view::npos ? q1 : line.find('"', q1 + 1);
    if (q2 == std::string_view::npos || q2 + 2 >= line.size() || !digits(line, q2 + 2, 3, out.status)) return false;
    return true;
}

bool parse_since(std::string_view text, std::time_t now, std::time_t& out) {
    if (text.empty()) return false;
    if (text.size() >= 19 && text[4] == '-' && text[10] == 'T') {
        int y, mo, d, h, mi, s;
        if (!digits(text, 0, 4, y) || !digits(text, 5, 2, mo) || !digits(text, 8, 2, d) || !digits(text, 11, 2, h) ||
            !digits(text, 14, 2, mi) || !digits(text, 17, 2, s))
            return false;
        out = local_to_time(y, mo - 1, d, h, mi, s);
        return true;
    }
    long n = 0;
    std::size_t i = 0;
    for (; i < text.size() && text[i] >= '0' && text[i] <= '9'; ++i) n = n * 10 + (text[i] - '0');
    if (i == 0) return false;
    long unit = 1;
    if (i < text.size()) {
        if (i + 1 != text.size()) return false;
        switch (text[i]) {
            case 's': unit = 1; break;
            case 'm': unit = 60; break;
            case 'h': unit = 3600; break;
            case 'd': unit = 86400; break;
            case 'w': unit = 7 * 86400; break;
            default: return false;
        }
    }
    out = now - n * unit;
    return true;
}

void scan_log(const fs::path& file, std::string_view source, const LogQuery& q, std::vector<LogLine>& out,
              bool& truncated) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return;
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    std::streamoff start = 0;
    if (size > static_cast<std::streamoff>(q.max_bytes)) {
        start = size - static_cast<std::streamoff>(q.max_bytes);
        truncated = true;
    }
    in.seekg(start);
    std::string buf(static_cast<std::size_t>(size - start), '\0');
    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    buf.resize(static_cast<std::size_t>(in.gcount()));
    std::size_t end = buf.size();
    if (start > 0) {  // drop the partial first line
        const std::size_t nl = buf.find('\n');
        if (nl == std::string::npos) return;
        buf.erase(0, nl + 1);
        end = buf.size();
    }
    std::vector<LogLine> found;
    int older = 0;
    while (end > 0 && found.size() < q.limit) {
        if (buf[end - 1] == '\n') {  // the terminator of the line before
            --end;
            continue;
        }
        const std::size_t nl = buf.rfind('\n', end - 1);
        const std::size_t begin = nl == std::string::npos ? 0 : nl + 1;
        const std::string_view line(buf.data() + begin, end - begin);
        end = begin;
        LogLine l;
        if (line.empty() || !parse_log_line(line, l)) continue;
        if (q.since && l.time < q.since) {  // buffers of several workers may interleave a little
            if (++older > 50) break;
            continue;
        }
        older = 0;
        if (l.source == "error") {
            const bool keep = q.level == "info" || l.level == "error" || (q.level != "error" && l.level == "warn");
            if (!keep) continue;
        } else {
            l.source = std::string(source);
            if (l.status < q.status_min) continue;
        }
        found.push_back(std::move(l));
    }
    std::reverse(found.begin(), found.end());
    out.insert(out.end(), found.begin(), found.end());
}

json::Value logs(const Config& cfg, const LogQuery& q) {
    std::vector<LogLine> lines;
    bool truncated = false;
    json::Value files = json::Value::array();
    std::vector<std::string> seen;
    auto scan = [&](const std::string& path, std::string_view source) {
        if (path.empty() || path == "stderr" || path == "off") return;
        if (std::find(seen.begin(), seen.end(), path) != seen.end()) return;
        seen.push_back(path);
        files.push(path);
        scan_log(path, source, q, lines, truncated);
    };
    if (q.site.empty()) {
        scan(cfg.log.error, "error");
        for (const auto& s : cfg.sites) scan(s.access_log, s.server_names.front());
    } else {
        const SiteConfig* s = find_site(cfg, q.site);
        if (s) {
            scan(s->access_log, s->server_names.front());
            // The error log's lines about this site name.
            std::vector<LogLine> err;
            if (!cfg.log.error.empty() && cfg.log.error != "stderr") {
                files.push(cfg.log.error);
                scan_log(cfg.log.error, "error", q, err, truncated);
            }
            for (auto& l : err)
                if (l.text.find(s->server_names.front()) != std::string::npos) lines.push_back(std::move(l));
        }
    }
    std::stable_sort(lines.begin(), lines.end(), [](const LogLine& a, const LogLine& b) { return a.time < b.time; });
    if (lines.size() > q.limit) lines.erase(lines.begin(), lines.end() - static_cast<std::ptrdiff_t>(q.limit));
    json::Value out = json::Value::object();
    out.set("files", std::move(files));
    out.set("since", static_cast<double>(q.since));
    out.set("truncated", truncated);
    json::Value arr = json::Value::array();
    for (const auto& l : lines) {
        json::Value v = json::Value::object();
        v.set("time", static_cast<double>(l.time)).set("source", l.source);
        if (!l.level.empty()) v.set("level", l.level);
        if (l.status) v.set("status", l.status);
        v.set("text", l.text);
        arr.push(std::move(v));
    }
    out.set("count", static_cast<double>(lines.size()));
    out.set("lines", std::move(arr));
    return out;
}

// ---- sites ----

CertificateState certificate_state(const TlsConfig& tls, std::time_t now) {
    CertificateState st;
#ifdef AGENSIO_HAS_TLS
    acme::CertInfo info;
    if (!acme::certificate_info(tls.cert, info, st.error)) return st;
    st.present = true;
    st.placeholder = info.placeholder;
    st.issuer = info.issuer;
    st.names = info.names;
    st.not_after = std::chrono::system_clock::to_time_t(info.not_after);
    st.days_left = static_cast<long>((st.not_after - now) / 86400);
#else
    (void)tls;
    (void)now;
    st.error = "built without TLS";
#endif
    return st;
}

// Several sites may carry the name (the :80 redirect and the :443 site of an HTTPS-only
// setup): the one that serves content wins, then the TLS one, then the first.
bool is_catch_all(const SiteConfig& s) {
    return s.is_default || std::find(s.server_names.begin(), s.server_names.end(), "*") != s.server_names.end();
}

bool listener_has_catch_all(const Config& cfg, const std::string& address) {
    for (const auto& s : cfg.sites)
        if (is_catch_all(s) && std::find(s.listen.begin(), s.listen.end(), address) != s.listen.end()) return true;
    return false;
}

const SiteConfig* find_site(const Config& cfg, std::string_view name) {
    const std::string want = lower(name);
    const SiteConfig* best = nullptr;
    int best_score = -1;
    for (const auto& s : cfg.sites)
        for (const auto& n : s.server_names)
            if (n == want) {
                const int score = (s.redirect.empty() ? 2 : 0) + (s.tls ? 1 : 0);
                if (score > best_score) {
                    best = &s;
                    best_score = score;
                }
            }
    return best;
}

namespace {

json::Value strings(const std::vector<std::string>& v) {
    json::Value a = json::Value::array();
    for (const auto& s : v) a.push(s);
    return a;
}

json::Value tls_json(const SiteConfig& s, std::time_t now) {
    json::Value t = json::Value::object();
    if (!s.tls) return t.set("mode", "none");
    t.set("mode", s.tls->automatic ? "auto" : "manual").set("cert", s.tls->cert.string()).set("key", s.tls->key.string());
    const CertificateState st = certificate_state(*s.tls, now);
    t.set("present", st.present);
    if (!st.present) return t.set("error", st.error);
    t.set("placeholder", st.placeholder).set("issuer", st.issuer).set("names", strings(st.names));
    t.set("not_after", static_cast<double>(st.not_after)).set("days_left", static_cast<double>(st.days_left));
    return t;
}

json::Value site_summary(const SiteConfig& s, std::time_t now) {
    json::Value v = json::Value::object();
    v.set("server_name", strings(s.server_names)).set("listen", strings(s.listen));
    v.set("root", s.root).set("app", s.app).set("user", s.user).set("group", s.group);
    if (!s.redirect.empty()) v.set("redirect", s.redirect);
    v.set("catch_all", is_catch_all(s));
    v.set("access_log", s.access_log);
    v.set("tls", tls_json(s, now));
    return v;
}

json::Value upstream_json(const UpstreamConfig& u) {
    json::Value a = json::Value::array();
    for (const auto& addr : u.addresses) a.push(addr.key);
    if (u.addresses.empty() && u.configured) a.push(u.address.key);
    return a;
}

}  // namespace

json::Value sites(const Config& cfg, std::time_t now) {
    json::Value arr = json::Value::array();
    for (const auto& s : cfg.sites) arr.push(site_summary(s, now));
    return json::Value::object().set("count", static_cast<double>(cfg.sites.size())).set("sites", std::move(arr));
}

json::Value site(const Config& cfg, const SiteConfig& s, std::time_t now) {
    json::Value v = site_summary(s, now);
    v.set("index", strings(s.index));
    v.set("settings", effective_settings(s, cfg));  // each with its value and where it comes from
    if (s.php.configured) {
        json::Value php = json::Value::object().set("socket", s.php.address.key);
        if (s.pool.generated) php.set("pool", s.pool.name).set("state_dir", s.pool.state_dir);
        v.set("php", std::move(php));
    }
    if (s.proxy.configured) v.set("upstream", upstream_json(s.proxy));
    json::Value locs = json::Value::array();
    for (const auto& l : s.locations) {
        json::Value loc = json::Value::object().set("path", l.path);
        loc.set("match", l.exact ? "exact" : l.suffix ? "suffix" : "prefix").set("handler", l.handler);
        if (!l.deny_suffixes.empty()) loc.set("refuses", strings(l.deny_suffixes));  // endings answered 404 here
        if (!l.origin.empty()) loc.set("from", l.origin);
        if (!l.alias.empty()) loc.set("alias", l.alias);
        else if (l.root != s.root) loc.set("root", l.root);
        if (l.kind == HandlerKind::proxy) loc.set("upstream", upstream_json(l.proxy));
        if (l.kind == HandlerKind::fastcgi) loc.set("socket", l.fastcgi.address.key);
        if (!l.add_headers.empty()) {
            json::Value h = json::Value::object();
            for (const auto& [n, val] : l.add_headers) h.set(n, val);
            loc.set("add_headers", std::move(h));
        }
        locs.push(std::move(loc));
    }
    v.set("locations", std::move(locs));
    (void)cfg;
    return v;
}

// ---- validation and health ----

std::vector<std::string> restart_needed(const Config& fresh, const Config& running) {
    std::vector<std::string> out;
    if (fresh.workers != running.workers) out.push_back("workers");
    if (fresh.reuse_port != running.reuse_port) out.push_back("reuse_port");
    if (fresh.user != running.user) out.push_back("user");
    if (fresh.group != running.group) out.push_back("group");
    if (fresh.sendfile != running.sendfile) out.push_back("sendfile");
    if (fresh.cache_max_size != running.cache_max_size || fresh.cache_max_file_size != running.cache_max_file_size)
        out.push_back("cache sizes");
    if (fresh.control.enabled != running.control.enabled || fresh.control.socket != running.control.socket)
        out.push_back("control");
    return out;
}

json::Value validate(const fs::path& path, const Config& running) {
    json::Value v = json::Value::object().set("path", path.string());
    json::Value errors = json::Value::array();
    Config fresh;
    try {
        fresh = load_config(path);
    } catch (const std::exception& e) {
        errors.push(e.what());
        return v.set("ok", false).set("errors", std::move(errors));
    }
    for (const auto& e : check_hosting(fresh, system_facts())) errors.push(e);
    const bool ok = errors.items().empty();
    v.set("ok", ok).set("errors", std::move(errors)).set("sites", static_cast<double>(fresh.sites.size()));
    v.set("restart_needed", strings(restart_needed(fresh, running)));
    return v;
}

bool php_fpm_hard_reload(const Config& cfg, std::string& file) {
    const fs::path dir = pools_dir(cfg, "");
    if (dir.empty()) return false;
    std::error_code ec;
    for (const fs::path candidate : {dir.parent_path() / "php-fpm.conf", dir.parent_path().parent_path() / "php-fpm.conf"}) {
        if (!fs::is_regular_file(candidate, ec)) continue;
        file = candidate.string();
        std::ifstream in(candidate);
        std::string line;
        while (std::getline(in, line)) {
            const std::size_t start = line.find_first_not_of(" \t");
            if (start == std::string::npos || line[start] == ';' || line[start] == '#') continue;
            if (line.compare(start, 23, "process_control_timeout") != 0) continue;
            const std::size_t eq = line.find('=', start);
            if (eq == std::string::npos) continue;
            std::string value = line.substr(eq + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            const std::size_t end = value.find_first_of(" \t;#\r");
            if (end != std::string::npos) value.erase(end);
            return value.empty() || value == "0" || value == "0s";
        }
        return true;  // the file exists and never sets it: php-fpm's default of 0
    }
    return false;
}

// Files under a site's document root that the server's own account cannot open: they
// answer 404 with nothing in any log. Sampled with a budget, the application's upload
// directory first (the preset knows it), hidden entries and the preset's credential files
// left out (never served, 0600 by design). Runs as whoever the server runs as, so the
// answer is what a request would meet.
struct UnreadableFiles {
    std::size_t seen = 0, unreadable = 0;
    std::string example;
    FileFacts example_facts;
};

UnreadableFiles unreadable_files(const SiteConfig& site, const std::vector<std::string>& secrets, std::size_t budget) {
    UnreadableFiles r;
    if (site.root.empty()) return r;
    std::vector<fs::path> starts;
    const std::string up = preset_uploads(site.app);
    if (!up.empty()) starts.push_back(site.root + up);
    starts.push_back(site.root);
    std::error_code ec;
    for (const auto& start : starts) {
        if (!fs::is_directory(start, ec)) continue;
        for (fs::recursive_directory_iterator it(start, fs::directory_options::skip_permission_denied, ec), end; it != end && r.seen < budget; it.increment(ec)) {
            if (ec) break;
            const std::string name = it->path().filename().string();
            if (!name.empty() && name[0] == '.') {  // hidden: never served, so never a finding
                if (it->is_directory(ec)) it.disable_recursion_pending();
                continue;
            }
            if (it.depth() >= 8) it.disable_recursion_pending();
            if (!it->is_regular_file(ec)) continue;
            ++r.seen;
            const std::string path = it->path().string();
            if (std::find(secrets.begin(), secrets.end(), path) != secrets.end()) continue;
#ifndef _WIN32
            if (::access(path.c_str(), R_OK) == 0) continue;
#else
            continue;
#endif
            if (r.unreadable++ == 0) {
                r.example = path;
                system_facts().stat(path, r.example_facts);
            }
        }
    }
    return r;
}

// Backup archives and database dumps under a document root (2026-09-23 live report: a
// Grav site's backup/ held a 23 MB zip with the admin account and the salt, and the log
// that named it was served). Bounded like unreadable_files; hidden directories skipped.
ArchivesInRoot archives_in_root(const SiteConfig& site, std::size_t budget) {
    ArchivesInRoot r;
    if (site.root.empty()) return r;
    static const char* const kEndings[] = {".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".7z", ".rar", ".sql", ".sql.gz"};
    std::error_code ec;
    if (!fs::is_directory(site.root, ec)) return r;
    // Directories the preset never answers (Grav's backup/, logs/) are not one path away
    // from public; they are not searched.
    std::vector<std::string> skip;
    for (const auto& loc : site.locations)
        if (loc.handler == "deny" && !loc.exact && loc.path.size() > 1 && loc.path.back() == '/') skip.push_back(site.root + loc.path.substr(0, loc.path.size() - 1));
    for (fs::recursive_directory_iterator it(site.root, fs::directory_options::skip_permission_denied, ec), end; it != end && r.seen < budget; it.increment(ec)) {
        if (ec) break;
        const std::string name = it->path().filename().string();
        if (it->is_directory(ec)) {
            if ((!name.empty() && name[0] == '.') || it.depth() >= 8 || std::find(skip.begin(), skip.end(), it->path().string()) != skip.end())
                it.disable_recursion_pending();
            continue;
        }
        if (!name.empty() && name[0] == '.') continue;
        if (!it->is_regular_file(ec)) continue;
        ++r.seen;
        std::string lower = name;
        for (char& c : lower) c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
        bool hit = false;
        for (const char* e : kEndings) {
            const std::size_t n = std::strlen(e);
            if (lower.size() > n && lower.compare(lower.size() - n, n, e) == 0) { hit = true; break; }
        }
        if (!hit) continue;
        const std::uintmax_t size = it->file_size(ec);
        if (r.count++ == 0) {
            r.example = it->path().string();
            r.example_bytes = ec ? 0 : static_cast<std::uint64_t>(size);
        }
    }
    return r;
}

// The pm the pool file on disk says: php-fpm runs that one until `agensio pools` and a
// reload, whatever the configuration means to (2026-09-23 live report: two pools still
// static on disk held 681 MB while the configuration already said ondemand).
std::string pool_file_pm(const Config& cfg, const PhpPool& pool) {
    const fs::path dir = pools_dir(cfg, "");
    if (dir.empty()) return {};
    std::ifstream in(dir / (pool.name + ".conf"));
    for (std::string line; std::getline(in, line);) {
        if (line.rfind("pm = ", 0) == 0) return line.substr(5);
        if (line.rfind("pm=", 0) == 0) return line.substr(3);
    }
    return {};
}

// The PHP processes of one php-fpm pool, from /proc (Linux; elsewhere none are found):
// php-fpm titles each child "php-fpm: pool NAME", and /proc/PID/status gives VmRSS and
// RssAnon (the private part) for another account's process too. What a pool keeps
// resident is the number an administrator or an agent needs when the machine fills up.
PoolResidency pool_residency(const std::string& pool) {
    PoolResidency r;
#ifdef __linux__
    const std::string title = "php-fpm: pool " + pool;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator("/proc", ec)) {
        const std::string pid = e.path().filename().string();
        if (pid.empty() || !std::isdigit(static_cast<unsigned char>(pid[0]))) continue;
        std::ifstream cmd(e.path() / "cmdline", std::ios::binary);
        std::string line;
        std::getline(cmd, line, '\0');
        if (line.rfind(title, 0) != 0 || (line.size() > title.size() && line[title.size()] != ' ')) continue;
        ++r.processes;
        std::ifstream st(e.path() / "status");
        for (std::string l; std::getline(st, l);) {
            if (l.rfind("VmRSS:", 0) == 0) r.rss_kb += std::strtoull(l.c_str() + 6, nullptr, 10);
            else if (l.rfind("RssAnon:", 0) == 0) r.anon_kb += std::strtoull(l.c_str() + 8, nullptr, 10);
        }
    }
#else
    (void)pool;
#endif
    return r;
}

std::vector<Finding> health_findings(const Config& running, const Config& boot, bool as_root, std::time_t now) {
    std::vector<Finding> out;
    auto add = [&](std::string sev, std::string code, std::string site, std::string msg, std::string fix = "") {
        out.push_back(Finding{std::move(sev), std::move(code), std::move(site), std::move(msg), std::move(fix)});
    };
    // The file on disk.
    try {
        const Config fresh = load_config(running.config_path);
        for (const auto& e : check_hosting(fresh, system_facts()))
            add("error", "hosting_rule", "", e, "fix the ownership, then agensio -t");
        const auto restart = restart_needed(fresh, boot);
        if (!restart.empty()) {
            std::string keys;
            for (const auto& k : restart) keys += (keys.empty() ? "" : ", ") + k;
            add("warn", "restart_needed", "", "restart-only settings changed on disk: " + keys, "restart the service");
        }
    } catch (const std::exception& e) {
        add("error", "config_invalid", "", std::string("the configuration file does not load: ") + e.what(),
            "fix it and run agensio -t; the running server keeps its last good configuration");
    }
    if (as_root && boot.user.empty())
        add("error", "running_as_root", "", "the server runs as root", "set [server] user = \"agensio\" and restart");
    if (running.sites.empty()) add("info", "no_sites", "", "no site is configured", "add a [[site]]");

    // Certificates, redirects and port 80.
    auto has_plain = [&](const SiteConfig& tls_site, bool need_redirect, bool need_port_80) {
        for (const auto& p : running.sites) {
            if (p.tls) continue;
            if (need_redirect && p.redirect.empty()) continue;
            bool covers = true;
            for (const auto& n : tls_site.server_names)
                covers = covers && std::find(p.server_names.begin(), p.server_names.end(), n) != p.server_names.end();
            if (!covers) continue;
            if (need_port_80) {
                bool on_80 = false;
                for (const auto& a : p.listen) on_80 = on_80 || a.ends_with(":80");
                if (!on_80) continue;
            }
            return true;
        }
        return false;
    };
    for (const auto& s : running.sites) {
        if (!s.tls) continue;
        const std::string name = s.server_names.front();
        const CertificateState st = certificate_state(*s.tls, now);
        if (!st.present) {
            add("error", "certificate_unreadable", name, "certificate cannot be read: " + st.error, "check tls.cert");
        } else if (st.placeholder) {
            add("error", "certificate_not_issued", name,
                "still on the placeholder certificate; the ACME order has not succeeded",
                "make sure the names resolve here and port 80 is reachable, then read the acme lines in the error log");
        } else if (st.days_left < 0) {
            add("error", "certificate_expired", name, "certificate expired", s.tls->automatic ? "read the acme lines in the error log" : "install a new certificate and reload");
        } else if (!s.tls->automatic && st.days_left < 14) {
            add("warn", "certificate_expiring", name, "certificate expires in " + std::to_string(st.days_left) + " days",
                "renew it and reload, or switch to tls = \"auto\"");
        }
        if (s.tls->automatic && !has_plain(s, false, true))
            add("warn", "acme_needs_port_80", name, "tls = \"auto\" but no plain site on port 80 covers these names",
                "add a [[site]] on 0.0.0.0:80 with the same server_name (redirect = \"https\")");
        if (!has_plain(s, true, false))
            add("info", "no_http_redirect", name, "no plain site redirects these names to https",
                "add a [[site]] on port 80 with redirect = \"https\"");
    }

    // A per-site log the site user cannot read (created by a reload after the privilege
    // drop, which cannot chown): stands until a restart hands it over.
    {
        const HostFacts facts = system_facts();
        for (const auto& s : running.sites) {
            if (s.user.empty() || s.access_log.empty()) continue;
            unsigned uid = 0, gid = 0;
            if (!facts.user(s.user, uid, gid)) continue;
            if (!s.group.empty()) facts.group(s.group, gid);
            FileFacts f;
            if (facts.stat(s.access_log, f) && f.gid != gid)
                add("warn", "log_not_readable_by_user", s.server_names.front(),
                    s.access_log + " is not owned by group " + (s.group.empty() ? s.user : s.group) + " (gid " + std::to_string(f.gid) +
                        "), so " + s.user + " cannot read its own log",
                    "restart the service: at start the server owns per-site logs agensio:<site group> 0640, or chown it as root");
        }
    }
    // Shared account: several application sites without a user.
    std::size_t apps = 0, without_user = 0;
    for (const auto& s : running.sites) {
        bool app = s.php.configured || s.proxy.configured;
        for (const auto& l : s.locations) app = app || l.kind != HandlerKind::static_;
        if (!app) continue;
        ++apps;
        if (s.user.empty()) ++without_user;
    }
    if (apps >= 2 && without_user >= 2)
        add("info", "shared_account", "", std::to_string(without_user) + " application sites run under the server's own account",
            "give each site a user = \"...\" (docs/configuration.md section 11)");

    // Stale generated pools.
    bool any_generated = false;
    for (const auto& s : running.sites) any_generated = any_generated || s.pool.generated;
    if (any_generated) {
        const fs::path dir = pools_dir(running, "");
        if (dir.empty()) {
            add("warn", "pools_dir_unknown", "", "no php-fpm pool directory found for the generated pools", "set [server] pools");
        } else {
            std::ostringstream sink;
            if (write_pools(running, dir, true, sink) == 3)
                add("warn", "pools_stale", "", "generated php-fpm pool files differ from the configuration",
                    "run agensio pools, then reload php-fpm");
        }
        // PHP writes every upload to the pool's upload_tmp_dir and every session to its
        // save_path (tmp/ and sessions/ below the user's state directory) before an
        // application sees them; a missing or foreign directory fails both silently inside
        // PHP (no 413, no 502, nothing in our logs; 2026-09-20 report). The user's directory
        // is 0700, so the server can judge that directory, not what is inside it.
        const HostFacts facts = system_facts();
        for (const auto& s : running.sites) {
            if (!s.pool.generated) continue;
            unsigned uid = 0, gid = 0;
            const bool known = facts.user(s.user, uid, gid);
            const std::string d = s.pool.state_dir;
            FileFacts f;
            if (!facts.stat(d, f))
                add("error", "php_tmp_missing", s.server_names.front(), "PHP's private directory " + d + " (upload_tmp_dir and session.save_path live below it) does not exist: uploads and sessions fail inside PHP with no error from the server",
                    "agensio pools (creates it as " + s.user + " with tmp/ and sessions/)");
            else if (known && (f.uid != uid || !f.is_dir))
                add("error", "php_tmp_not_owned", s.server_names.front(), "PHP's private directory " + d + " is owned by uid " + std::to_string(f.uid) + ", not by " + s.user + ": PHP cannot write uploads or sessions there",
                    "chown -R " + s.user + " " + d + " && chmod 0700 " + d + " " + d + "/tmp " + d + "/sessions");
        }
        // What a pool keeps resident while its sites are idle (2026-09-21, a live host: 8
        // children per idle site, 150-200 MB each, a 4 GB machine full at 20 sites): static
        // keeps every child, dynamic half of them, ondemand none. One finding per pool.
        std::set<std::string> pools_seen;
        for (const auto& s : running.sites) {
            if (!s.pool.generated || !pools_seen.insert(s.pool.name).second) continue;
            // What php-fpm runs is the pool file on disk, not the configuration's intent.
            const std::string on_disk = pool_file_pm(running, s.pool);
            const std::string pm = on_disk.empty() ? s.pool.pm : on_disk;
            if (pm == "ondemand") continue;
            const bool stale = !on_disk.empty() && on_disk != s.pool.pm;
            const PoolResidency r = pool_residency(s.pool.name);
            const unsigned kept = pm == "static" ? s.pool.children : std::max(1u, s.pool.children / 2);
            std::string msg = "pool " + s.pool.name + " is pm = " + pm + (stale ? " on disk (the configuration says " + s.pool.pm + "; agensio pools has not run)" : "") +
                              ": " + (pm == "static" ? "all " : "at least ") + std::to_string(kept) + " PHP processes stay resident while the site is idle";
            if (r.processes)
                msg += " (now " + std::to_string(r.processes) + " processes, " + std::to_string((r.rss_kb + 512) / 1024) + " MB RSS, " +
                       std::to_string((r.anon_kb + 512) / 1024) + " MB private)";
            add(stale ? "warn" : "info", "php_pool_resident", s.server_names.front(), msg,
                stale ? "run agensio pools, then reload php-fpm: the pool becomes " + s.pool.pm + " as configured"
                      : "site-update " + s.server_names.front() + " --set pm=ondemand (a child starts on the first request and exits after 60 s idle), or keep " +
                            pm + " for a site that must not pay a fork on its first request");
        }
        std::string conf;
        if (php_fpm_hard_reload(running, conf))
            add("info", "php_fpm_hard_reload", "", "php-fpm.conf does not set process_control_timeout, so a php-fpm reload (site-create writing a pool, agensio pools) kills PHP requests in flight on every site",
                "set process_control_timeout = 10s in " + conf + " and reload php-fpm once");
    }

    // A document root whose files belong to another application than the preset says: the
    // borrowed preset's refusals do not fit, and what the application's own .htaccess would
    // have protected is served (2026-09-23: Grav on the drupal preset published its backup).
    for (const auto& s : running.sites) {
        if (s.root.empty() || !s.redirect.empty() || s.app.empty() || s.app == "static" || s.app == "proxy") continue;
        const std::string detected = detect_app(s.project_root.empty() ? s.root : s.project_root);
        if (detected.empty() || detected == s.app || detected == "static" || detected == "proxy" || detected == "php") continue;
        add("warn", "preset_mismatch", s.server_names.front(),
            "the files under " + (s.project_root.empty() ? s.root : s.project_root) + " look like " + detected + " (" + detect_app_marker(detected) +
                "), but app = \"" + s.app + "\": the " + s.app + " preset's refusals do not fit them, and what " + detected +
                "'s own .htaccess would protect may be served",
            "set app = \"" + detected + "\" (site-update " + s.server_names.front() + " with app: " + detected + " for a managed site)");
    }
    // Backup archives and database dumps inside a served tree are one path or one preset
    // away from being public, whatever the preset refuses today.
    for (const auto& s : running.sites) {
        if (s.root.empty() || !s.redirect.empty() || s.app.empty() || s.app == "static" || s.app == "proxy") continue;
        const ArchivesInRoot a = archives_in_root(s, 2000);
        if (a.count == 0) continue;
        const std::string size = a.example_bytes >= 1024 * 1024 ? std::to_string((a.example_bytes + 512 * 1024) / (1024 * 1024)) + " MB"
                                                                : std::to_string((a.example_bytes + 512) / 1024) + " KB";
        add("warn", "archives_in_root", s.server_names.front(),
            std::to_string(a.count) + " archive(s) or database dump(s) under the document root, e.g. " + a.example + " (" + size + ")" +
                (a.seen >= 2000 ? ", the first 2000 files looked at" : ""),
            "move backups and dumps out of the document root (a backup plugin's directory too) and delete stale ones; nothing served should hold a copy of the site");
    }
    // Files the server cannot read under a document root (2026-09-20: every upload of every
    // site with a user was 0640 user:user after move_uploaded_file, 404 with no log line).
    {
        const ServerAccount server = server_account(running, system_facts());
        for (const auto& s : running.sites) {
            if (s.root.empty() || !s.redirect.empty()) continue;
            const UnreadableFiles u = unreadable_files(s, secret_paths(s), 2000);
            if (u.unreadable == 0) continue;
            const FileFacts& f = u.example_facts;
            char mode[8];
            std::snprintf(mode, sizeof mode, "%04o", f.mode & 07777);
            const HostFacts facts = system_facts();
            std::string user = facts.user_name ? facts.user_name(f.uid) : "", group = facts.group_name ? facts.group_name(f.gid) : "";
            const std::string owner = (user.empty() ? std::to_string(f.uid) : user) + ":" + (group.empty() ? std::to_string(f.gid) : group) + " " + mode;
            // The remedy from the example's actual defect: the group, the group-read bit, or both.
            const std::string dir = fs::path(u.example).parent_path().string();
            const std::string sgroup = server.group.empty() ? std::to_string(server.gid) : server.group;
            const bool group_wrong = server.known && f.gid != server.gid, mode_wrong = !(f.mode & 0040);
            std::string fix;
            if (group_wrong && mode_wrong) fix = "chgrp -R " + sgroup + " " + dir + " && chmod -R g+r " + dir;
            else if (group_wrong) fix = "give them the server's group: chgrp -R " + sgroup + " " + dir;
            else if (mode_wrong) fix = "the group is right, the mode is not: chmod -R g+r " + dir;
            else fix = "make " + dir + " readable by " + (server.user.empty() ? "uid " + std::to_string(server.uid) : server.user) + " (a parent directory may lack the execute bit)";
            add("error", "files_unreadable", s.server_names.front(),
                std::to_string(u.unreadable) + " of " + std::to_string(u.seen) + " sampled files under " + s.root + " cannot be read by the server's account (" +
                    (server.user.empty() ? "uid " + std::to_string(server.uid) : server.user) + ") and answer 404 with no log line; for example " + u.example + " (" + owner + ")",
                fix + "; uploads made after agensio pools ran on this build carry the server's group already");
        }
    }

    // Recent errors.
    LogQuery q;
    q.level = "error";
    q.since = now - 24 * 3600;
    q.limit = 1000;
    std::vector<LogLine> lines;
    bool truncated = false;
    if (!running.log.error.empty() && running.log.error != "stderr") scan_log(running.log.error, "error", q, lines, truncated);
    if (!lines.empty())
        add("warn", "recent_errors", "", std::to_string(lines.size()) + (truncated ? "+" : "") + " error(s) in the last 24 hours; last: " + lines.back().text,
            "agensio ctl logs --since 24h --level error");
    return out;
}

json::Value health(const Config& running, const Config& boot, bool as_root, std::time_t now) {
    const auto findings = health_findings(running, boot, as_root, now);
    json::Value arr = json::Value::array();
    bool ok = true;
    for (const auto& f : findings) {
        if (f.severity != "info") ok = false;
        json::Value v = json::Value::object().set("severity", f.severity).set("code", f.code);
        if (!f.site.empty()) v.set("site", f.site);
        v.set("message", f.message);
        if (!f.fix.empty()) v.set("fix", f.fix);
        arr.push(std::move(v));
    }
    return json::Value::object().set("ok", ok).set("count", static_cast<double>(findings.size())).set("findings", std::move(arr));
}

std::string query_value(std::string_view target, std::string_view key) {
    const std::size_t qm = target.find('?');
    if (qm == std::string_view::npos) return {};
    std::string_view q = target.substr(qm + 1);
    while (!q.empty()) {
        const std::size_t amp = q.find('&');
        const std::string_view pair = q.substr(0, amp);
        q = amp == std::string_view::npos ? std::string_view() : q.substr(amp + 1);
        const std::size_t eq = pair.find('=');
        if (pair.substr(0, eq) != key) continue;
        std::string_view raw = eq == std::string_view::npos ? std::string_view() : pair.substr(eq + 1);
        std::string out;
        for (std::size_t i = 0; i < raw.size(); ++i) {
            if (raw[i] == '+') out.push_back(' ');
            else if (raw[i] == '%' && i + 2 < raw.size() && std::isxdigit(static_cast<unsigned char>(raw[i + 1])) &&
                     std::isxdigit(static_cast<unsigned char>(raw[i + 2]))) {
                out.push_back(static_cast<char>(std::stoi(std::string(raw.substr(i + 1, 2)), nullptr, 16)));
                i += 2;
            } else out.push_back(raw[i]);
        }
        return out;
    }
    return {};
}

}  // namespace agensio::control
