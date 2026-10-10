#include "control/commands.hpp"

#include "core/access.hpp"
#include "core/refuse.hpp"
#include "core/router.hpp"
#include "handlers/static.hpp"
#include "core/strings.hpp"

#include "control/settings.hpp"
#include "control/sites.hpp"

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>

#include "services/acme.hpp"
#include "services/appenv.hpp"
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
        out.host = lower(v.get("host"));
        if (const std::size_t colon = out.host.rfind(':'); colon != std::string::npos && out.host.find(']') == std::string::npos) out.host.erase(colon);
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

std::string utf8_escaped(std::string_view line) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(line.size());
    for (std::size_t i = 0; i < line.size();) {
        const unsigned char c = static_cast<unsigned char>(line[i]);
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
            ++i;
            continue;
        }
        const std::size_t n = utf8_sequence(line, i);
        if (n) {
            out.append(line.data() + i, n);
            i += n;
        } else {
            out.append("\\x");
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 15]);
            ++i;
        }
    }
    return out;
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
        l.text = utf8_escaped(l.text);  // older files and the error log may hold a client's raw bytes
        found.push_back(std::move(l));
    }
    std::reverse(found.begin(), found.end());
    out.insert(out.end(), found.begin(), found.end());
}

json::Value logs(const Config& cfg, const LogQuery& q) {
    std::vector<LogLine> lines;
    bool truncated = false;
    json::Value files = json::Value::array();
    json::Value sources = json::Value::array();
    std::vector<std::string> seen;
    // Who writes into which access log. The [log] access default is the server-wide file:
    // every site without an access_log of its own writes there (the catch-all, the redirects,
    // scanners hitting the bare address), so its lines carry the source "access", never a
    // site's name; a site is named only on a file it alone writes to (2026-10-02 report
    // against alpha.42: 292 lines of the port-80 catch-all were labelled with the first site
    // that shared the default, and a reader took that site for the one being scanned).
    std::vector<std::pair<std::string, std::vector<std::string>>> writers;
    for (const auto& s : cfg.sites) {
        if (s.access_log.empty() || s.server_names.empty()) continue;
        auto it = std::find_if(writers.begin(), writers.end(), [&](const auto& w) { return w.first == s.access_log; });
        if (it == writers.end()) writers.emplace_back(s.access_log, std::vector<std::string>{s.server_names.front()});
        else if (std::find(it->second.begin(), it->second.end(), s.server_names.front()) == it->second.end()) it->second.push_back(s.server_names.front());
    }
    auto sites_of = [&](const std::string& path) -> const std::vector<std::string>* {
        for (const auto& w : writers)
            if (w.first == path) return &w.second;
        return nullptr;
    };
    auto label = [&](const std::string& path) -> std::string {
        const auto* w = sites_of(path);
        if (path == cfg.log.access || !w || w->size() != 1) return "access";
        return w->front();
    };
    auto scan = [&](const std::string& path, std::string_view source) {
        if (path.empty() || path == "stderr" || path == "off") return;
        if (std::find(seen.begin(), seen.end(), path) != seen.end()) return;
        seen.push_back(path);
        files.push(path);
        json::Value src = json::Value::object().set("file", path).set("source", std::string(source));
        if (const auto* w = sites_of(path)) {
            json::Value names = json::Value::array();
            for (const auto& n : *w) names.push(n);
            src.set("sites", std::move(names));
        }
        sources.push(std::move(src));
        scan_log(path, source, q, lines, truncated);
    };
    json::Value out = json::Value::object();
    if (q.site.empty()) {
        scan(cfg.log.error, "error");
        scan(cfg.log.access, "access");
        for (const auto& s : cfg.sites) scan(s.access_log, label(s.access_log));
    } else {
        const SiteConfig* s = find_site(cfg, q.site);
        if (s) {
            const std::string source = label(s->access_log);
            scan(s->access_log, source);
            if (source == "access" && !s->access_log.empty()) {
                // A shared file: JSON lines carry the Host and are kept for this site's names
                // (a catch-all keeps what no other site's name claims); combined lines carry no
                // host, so they stay, labelled honestly, with the note.
                const std::vector<std::string>* w = sites_of(s->access_log);
                std::vector<std::string> others;
                if (w)
                    for (const auto& n : *w)
                        if (n != s->server_names.front()) others.push_back(n);
                std::vector<std::string> other_names;  // every name of every other site on the file
                for (const auto& o : cfg.sites)
                    if (&o != s && o.access_log == s->access_log)
                        for (const auto& n : o.server_names) other_names.push_back(n);
                const bool catch_all = is_catch_all(*s);
                const bool json_lines = std::any_of(lines.begin(), lines.end(), [](const LogLine& l) { return !l.host.empty(); });
                if (json_lines)
                    lines.erase(std::remove_if(lines.begin(), lines.end(),
                                               [&](const LogLine& l) {
                                                   if (l.host.empty()) return false;
                                                   const bool mine = std::find(s->server_names.begin(), s->server_names.end(), l.host) != s->server_names.end();
                                                   const bool theirs = std::find(other_names.begin(), other_names.end(), l.host) != other_names.end();
                                                   return !(mine || (catch_all && !theirs));
                                               }),
                                lines.end());
                json::Value shared = json::Value::array();
                for (const auto& o : others) shared.push(o);
                out.set("shared", true).set("shared_with", std::move(shared));
                out.set("note", s->server_names.front() + " has no access log of its own: it writes into the server-wide log " + s->access_log + " with " +
                                    std::to_string(others.size()) + " other site(s)" + (json_lines ? ", whose JSON lines carry the host, so these are the lines for its names" + std::string(catch_all ? " and for every host no other site claims" : "")
                                                                                                   : "; the combined format carries no host name, so these lines cannot be attributed to this site alone") +
                                    ". A site with its own access_log (site_update access_log, or the key in its file) is queried alone" + (json_lines ? "." : "; [log] format = \"json\" puts the host into every line."));
            }
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
    out.set("files", std::move(files));
    out.set("sources", std::move(sources));
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
    v.set("encoded_slashes", s.encoded_slashes_allow ? "allow" : "deny");
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

namespace {

json::Value access_rule_json(const AccessRule& r, const std::string& from) {
    json::Value allow = json::Value::array();
    for (const auto& a : r.allow_text) allow.push(a);
    json::Value v = json::Value::object().set("path", r.path).set("match", r.exact ? "exact" : "prefix").set("allow", std::move(allow));
    v.set("mode", r.report ? "report" : "enforce");
    if (!from.empty()) v.set("from", from);
    return v;
}

// "rules" when the managed site's rules.restricted wrote it, the preset's name when a preset
// added it, "" for a rule written by hand.
std::string access_rule_from(const AccessRule& r, const SiteSpec* managed) {
    if (!r.origin.empty()) return r.origin;
    if (managed && managed->rules.is_object()) {
        for (const auto& m : managed->rules["restricted"].items()) {
            std::string p(m.get("path"));
            if ((m.get("match") == "exact") == r.exact && p.size() == r.path.size() && access::iequal_prefix(p, r.path)) return "rules";
        }
        const json::Value admin = admin_rules(*managed);  // kept alive for the loop: items() refers into it
        for (const auto& m : admin.items()) {
            std::string p(m.get("path"));
            if ((m.get("match") == "exact") == r.exact && p.size() == r.path.size() && access::iequal_prefix(p, r.path)) return "rules.admin";
        }
    }
    return "";
}

std::string access_rule_text(const AccessRule& r) {
    std::string t = r.path + (r.exact ? " (exact)" : "") + " (allow ";
    for (std::size_t i = 0; i < r.allow_text.size(); ++i) t += (i ? ", " : "") + r.allow_text[i];
    return t + ")";
}

// A user who can log in at `now`: not locked, not past the day `expires` names.
bool usable(const auth::User& u, std::time_t now) { return !u.locked && (u.expires == 0 || now < u.expires); }

// A [[site.auth]] rule as site_show and path_check show it (2026-10-09): never a hash or a name,
// only the file and how many of its users can log in now (site_auth_users lists them, admin).
json::Value auth_rule_json(const AuthRule& r, const std::string& from, std::time_t now) {
    json::Value v = json::Value::object().set("path", r.path).set("match", r.exact ? "exact" : "prefix").set("open", r.open);
    if (!r.open) {
        v.set("realm", r.realm).set("users", r.users_path);
        std::size_t total = 0, can = 0;
        if (r.users)
            for (const auto& u : r.users->users) {
                ++total;
                if (usable(u, now)) ++can;
            }
        v.set("users_count", static_cast<double>(total)).set("usable", static_cast<double>(can));
        json::Value skip = json::Value::array();
        for (const auto& t : r.skip_text) skip.push(t);
        v.set("skip_for", std::move(skip)).set("plain_http", r.plain_http);
        v.set("credentials", r.credentials == AuthRule::Credentials::pass ? "pass" : "strip");
        if (!r.forward_user.empty()) v.set("forward_user", r.forward_user);
    }
    if (!from.empty()) v.set("from", from);
    return v;
}

// "rules" when a managed site's rules.auth wrote it, the preset's name for an opening a preset
// added (WordPress's admin-ajax.php below a protected /wp-admin), "" for one written by hand.
std::string auth_rule_from(const AuthRule& r, const SiteSpec* managed) {
    if (!r.origin.empty()) return r.origin;
    if (managed && managed->rules.is_object())
        for (const auto& m : managed->rules["auth"].items()) {
            const std::string p(m.get("path"));
            if ((m.get("match") == "exact") == r.exact && m["open"].boolean() == r.open && p.size() == r.path.size() && access::iequal_prefix(p, r.path))
                return "rules";
        }
    return "";
}

}  // namespace

json::Value access_check(const Config& cfg, const SiteConfig& site, std::string_view raw_path, std::string_view address_text, std::string& error) {
    std::string path;
    if (raw_path.empty() || !normalize_target(raw_path, path)) {
        error = "path must be a request path starting with '/', such as /wp-admin/post.php";
        return {};
    }
    asio::error_code ec;
    const asio::ip::address given = asio::ip::make_address(std::string(address_text), ec);
    if (ec || address_text.find('%') != std::string_view::npos) {
        error = "address must be an IPv4 or IPv6 address, such as 203.0.113.7 or 2001:db8::7";
        return {};
    }
    const asio::ip::address a = unmapped(given);
    SiteSpec managed;
    const bool is_managed = read_managed(site_file(cfg, site.server_names.front()), managed);
    std::string scratch;
    const access::Decision d = access::decide(site, path, [&]() -> const asio::ip::address& { return a; }, scratch);
    json::Value v = json::Value::object().set("site", site.server_names.front()).set("path", path).set("address", a.to_string());
    std::string summary;
    if (d.rule) {
        v.set("decision", d.refuse() ? "refused" : "report").set("rule", access_rule_json(*d.rule, access_rule_from(*d.rule, is_managed ? &managed : nullptr)));
        const bool other = !access::covers(*d.rule, path);  // the path as an origin may read it fell under the rule
        summary = std::string(d.refuse() ? "refused by " : "report (served, logged as refused) by ") + access_rule_text(*d.rule) + ": " + a.to_string() +
                  " is in none of its entries" + (other ? ", for the way an origin may read " + path + " (a ;parameter, a second decoding or the path after a script)" : "");
    } else if (const AccessRule* r = access::rule_for(site, path)) {
        v.set("decision", "allowed").set("rule", access_rule_json(*r, access_rule_from(*r, is_managed ? &managed : nullptr)));
        summary = "allowed by " + access_rule_text(*r) + (r->any ? ": open to anyone" : ": " + a.to_string() + " is in it");
    } else {
        v.set("decision", "allowed");
        summary = "allowed: no access rule covers " + path;
    }
    v.set("summary", summary);
    return v;
}

// path_check (2026-10-08, docs/configuration.md 6b): what a site does with one GET for a path,
// in the order a worker decides it, and why: the refuse patterns, the location, its refusals
// by name, try_files and the index, every internal redirect again, then the file served, the
// script run or the origin it goes to. A description, never a request: it reads the running
// configuration and stats files as the worker would, and contacts no upstream. The access rules
// depend on the client and are only named here (access_check decides them for an address).
json::Value path_check(const Config& cfg, const SiteConfig& site, std::string_view raw_path, std::string& error) {
    std::string path;
    bool encoded = false;
    if (raw_path.empty() || raw_path.front() != '/' || !normalize_target(raw_path, path, &encoded)) {
        error = "path must be a request path starting with '/', such as /typo3conf/ext/news/Configuration/setup.typoscript";
        return {};
    }
    SiteSpec managed;
    const bool is_managed = read_managed(site_file(cfg, site.server_names.front()), managed);
    std::vector<RuleLocation> ruled;
    if (is_managed) ruled = rule_locations(managed);
    json::Value v = json::Value::object().set("site", site.server_names.front()).set("path", path);
    json::Value steps = json::Value::array();
    auto from_of = [&](const LocationConfig& l) -> std::string {
        if (!l.origin.empty()) return l.origin;
        for (const RuleLocation& rl : ruled)
            if (rl.path == l.path && rl.exact == l.exact && rl.suffix == l.suffix) return "rules";
        return "";
    };
    auto describe = [&](const LocationConfig& l) {
        const std::string from = from_of(l);
        return "location " + l.path + " (" + (l.exact ? "exact" : l.suffix ? "suffix" : "prefix") + ", " + l.handler + (from.empty() ? "" : ", from " + from) + ")";
    };
    auto finish = [&](const char* decision, int status, const std::string& summary) {
        v.set("decision", decision);
        if (status) v.set("status", status);
        v.set("summary", summary).set("steps", std::move(steps));
        return v;
    };
    auto stat_is = [](const std::string& f, bool dir) {
        struct stat st {};
        return ::stat(f.c_str(), &st) == 0 && (dir ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode));
    };
    std::string scratch;
    for (int hop = 0; hop <= StaticHandler::kMaxInternalRedirects; ++hop) {
        if (const RefusePattern* p = refuse::decide(site.refuse, path, scratch)) {
            v.set("refused_by", p->text);
            const bool other = refuse::match(site.refuse, path) == nullptr;
            return finish("refused", 404, "404: " + path + " is refused by the site's refuse pattern '" + p->text + "'" +
                                              (other ? ", for the way an application may read it (a ;parameter, a second decoding or the path after a script)" : ""));
        }
        if (!site.refuse.empty()) steps.push(path + ": no refuse pattern matches");
        // The script the path runs, which an exact rule judges too (access::script_of, the alpha.58
        // report's finding 1): named, and a rule that covers it shown as the path's.
        std::string script;
        const bool scripted = access::script_of(site, path, script);
        if (scripted && v["script"].is_null()) {
            v.set("script", script);
            steps.push(path + ": runs the script " + script + ", which the access and password rules judge too");
        }
        const AccessRule* ar = access::rule_for(site, path);
        if ((!ar || ar->any) && scripted)
            if (const AccessRule* sr = access::rule_for(site, script); sr && !sr->any) ar = sr;
        if (ar && !ar->any && v["access"].is_null())
            v.set("access", access_rule_json(*ar, access_rule_from(*ar, is_managed ? &managed : nullptr)))
                .set("access_note", "an access rule covers " + path + ": clients outside it get 403 (access_check decides it for an address)");
        // Passwords (2026-10-09), checked after the access rules as the dispatcher does.
        const AuthRule* pr = access::auth_rule_for(site, path);
        if ((!pr || pr->open) && scripted)
            if (const AuthRule* sr = access::auth_rule_for(site, script); sr && !sr->open) pr = sr;
        if (const AuthRule* r = pr; r && v["auth"].is_null()) {
            v.set("auth", auth_rule_json(*r, auth_rule_from(*r, is_managed ? &managed : nullptr), std::time(nullptr)));
            v.set("auth_note", r->open ? path + " is open: the rule " + r->path + " frees it below a password rule, so nobody is asked"
                                       : "a password rule covers " + path + ": a request without the password of one of its users gets 401 (realm \"" + r->realm +
                                             "\")" + (r->skip_text.empty() ? std::string() : ", except from the addresses of skip_for") +
                                             (r->plain_http ? std::string() : "; over plain HTTP from another host it gets 403 and is never asked"));
        }
        const LocationConfig& loc = Router::location(site, path);
        steps.push(path + ": " + describe(loc));
        json::Value lj = json::Value::object().set("path", loc.path).set("match", loc.exact ? "exact" : loc.suffix ? "suffix" : "prefix").set("handler", loc.handler);
        if (const std::string from = from_of(loc); !from.empty()) lj.set("from", from);
        v.set("location", std::move(lj));
        if (encoded && loc.kind != HandlerKind::proxy && !site.encoded_slashes_allow)
            return finish("not_found", 404, "404: the path spells a separator as a percent escape (%2F, %5C), never a file here");
        auto fs_of = [&](const std::string& p) {
            return loc.alias.empty() ? loc.root + p : loc.alias + p.substr(std::min(p.size(), loc.path.size() - 1));
        };
        if (loc.kind == HandlerKind::proxy) {
            if (!loc.deny_suffixes.empty() && refused_suffix(path, loc.deny_suffixes))
                return finish("refused", 404, "404: " + path + " ends with an ending " + describe(loc) + " refuses before the application sees it");
            v.set("upstream", upstream_json(loc.proxy));
            return finish("proxied", 0, path + " goes to the application (" + describe(loc) + "), which answers it");
        }
        if (loc.kind == HandlerKind::fastcgi || loc.kind == HandlerKind::cgi) {
            if (!loc.deny_suffixes.empty() && refused_suffix(path, loc.deny_suffixes))
                return finish("refused", 404, "404: " + path + " ends with an ending " + describe(loc) + " refuses");
            std::string script = path, info;
            if (loc.kind == HandlerKind::fastcgi && loc.fastcgi.options.path_info)
                if (const std::size_t p = script.find(".php/"); p != std::string::npos) {
                    info = script.substr(p + 4);
                    script.resize(p + 4);
                }
            if (script.back() == '/') script += loc.index.empty() ? (loc.kind == HandlerKind::cgi ? "index.cgi" : "index.php") : loc.index.front();
            const std::string file = fs_of(script);
            v.set("file", file);
            if (!stat_is(file, false)) return finish("not_found", 404, "404: no script " + file + " for " + describe(loc) + ", answered before the application");
            return finish("runs", 0, "runs " + script + (info.empty() ? "" : " with PATH_INFO " + info) + " (" + describe(loc) + ")");
        }
        if (loc.kind != HandlerKind::static_) return finish("handled", 0, path + " is answered by the " + loc.handler + " handler (" + describe(loc) + ")");
        // The static handler: its refusals by name, then try_files or the plain rule.
        if (!loc.hidden_files && has_hidden_segment(path)) return finish("refused", 404, "404: " + path + " has a dot segment (a hidden file), which " + describe(loc) + " never serves");
        if (!loc.deny_suffixes.empty() && refused_suffix(path, loc.deny_suffixes))
            return finish("refused", 404, "404: " + path + " ends with an ending " + describe(loc) + " refuses (deny_suffixes)");
        if (!loc.allow_suffixes.empty() && !refused_suffix(path, loc.allow_suffixes))
            return finish("refused", 404, "404: " + describe(loc) + " serves certain endings only (allow_suffixes), and " + path + " has none of them");
        if (!loc.protects.empty() && backup_of_protected(path, loc.protects))
            return finish("refused", 404, "404: " + path + " is a backup spelling of a name the site never serves");
        const bool dir_uri = path.back() == '/';
        // The index of a directory, as StaticHandler::index_lookup decides it: one the site
        // refuses by name is passed over as if missing; another location's is routed there.
        auto index_of = [&](std::string& file) -> int {
            for (const auto& i : loc.index) {
                const std::string candidate = path + i;
                if (!stat_is(fs_of(candidate), false)) continue;
                const LocationConfig& owner = Router::location(site, candidate);
                if (refused_request(site, owner, candidate)) {
                    steps.push(path + ": its index " + i + " exists but the site refuses it by name, so it is passed over as if missing");
                    continue;
                }
                if (&owner != &loc) {
                    steps.push(path + ": its index " + i + " belongs to " + describe(owner) + ", routed there");
                    path = candidate;
                    return 2;
                }
                if (!site.access.empty() && access::rule_for(site, candidate) != access::rule_for(site, path)) {
                    steps.push(path + ": another access rule decides its index " + i + ", so it is routed as a request for " + candidate);
                    path = candidate;
                    return 2;
                }
                file = fs_of(candidate);
                return 1;
            }
            return 0;
        };
        std::string file;
        bool next = false;
        if (loc.try_files.empty()) {
            if (dir_uri) {
                const int r = index_of(file);
                if (r == 1) {
                    v.set("file", file);
                    return finish("static", 200, "200: the index " + file + " (" + describe(loc) + ")");
                }
                if (r == 2) continue;
                if (stat_is(fs_of(path), true)) return finish("forbidden", 403, "403: a directory without an index file");
                return finish("not_found", 404, "404: no such directory");
            }
            file = fs_of(path);
            if (stat_is(file, false)) {
                v.set("file", file);
                return finish("static", 200, "200: the file " + file + " (" + describe(loc) + ")");
            }
            if (stat_is(file, true)) return finish("redirect", 301, "301 to " + path + "/: a directory");
            return finish("not_found", 404, "404: no file " + file);
        }
        for (const TryStep& step : loc.try_files) {
            switch (step.kind) {
                case TryStep::Kind::uri:
                    if (!dir_uri && stat_is(fs_of(path), false)) {
                        v.set("file", fs_of(path));
                        return finish("static", 200, "200: the file " + fs_of(path) + " (" + describe(loc) + ")");
                    }
                    break;
                case TryStep::Kind::uri_dir:
                    if (dir_uri) {
                        const int r = index_of(file);
                        if (r == 1) {
                            v.set("file", file);
                            return finish("static", 200, "200: the index " + file + " (" + describe(loc) + ")");
                        }
                        if (r == 2) next = true;
                    } else if (stat_is(fs_of(path), true)) {
                        return finish("redirect", 301, "301 to " + path + "/: a directory");
                    }
                    break;
                case TryStep::Kind::status:
                    return finish(step.status == 404 ? "not_found" : "status", step.status,
                                  std::to_string(step.status) + (loc.handler == "deny" ? ": " + describe(loc) + " answers 404 whatever exists"
                                                                                       : ": try_files of " + describe(loc) + " ends in =" + std::to_string(step.status)));
                case TryStep::Kind::fallback:
                    steps.push(path + ": no file or directory, so try_files sends it to " + step.target);
                    path = step.target;
                    next = true;
                    break;
            }
            if (next) break;
        }
        if (!next) return finish("not_found", 404, "404: try_files of " + describe(loc) + " found nothing");
    }
    return finish("error", 500, "500: more than " + std::to_string(StaticHandler::kMaxInternalRedirects) + " internal redirects");
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
    // The login paths the rendered fail2ban jail counts attempts on (docs/configuration.md 18):
    // the preset's known ones and the site's own `login_paths`.
    {
        std::vector<std::string> lp = preset_login_paths(s.app);
        for (const auto& p : s.login_paths)
            if (std::find(lp.begin(), lp.end(), p) == lp.end()) lp.push_back(p);
        if (!lp.empty()) v.set("login_paths", strings(lp));
    }
    // The locations a managed site's rules render are hand-written to the loader; labelled
    // "rules" here, beside preset:<app> and root:<file>, so an agent can tell them apart
    // (2026-10-02 report: 17 of a Kanboard site's 19 locations said nothing).
    std::vector<RuleLocation> ruled;
    SiteSpec managed;
    const bool is_managed = read_managed(site_file(cfg, s.server_names.front()), managed);
    if (is_managed) ruled = rule_locations(managed);
    json::Value locs = json::Value::array();
    for (const auto& l : s.locations) {
        json::Value loc = json::Value::object().set("path", l.path);
        loc.set("match", l.exact ? "exact" : l.suffix ? "suffix" : "prefix").set("handler", l.handler);
        if (!l.script_dir.empty()) loc.set("scripts_only_directly_in", l.script_dir);  // Drupal: PHP below any other directory refused
        if (!l.deny_suffixes.empty()) loc.set("refuses", strings(l.deny_suffixes));  // endings answered 404 here
        if (!l.allow_suffixes.empty()) loc.set("serves_only", strings(l.allow_suffixes));  // no other ending is
        if (!l.origin.empty()) loc.set("from", l.origin);
        else
            for (const RuleLocation& rl : ruled)
                if (rl.path == l.path && rl.exact == l.exact && rl.suffix == l.suffix) {
                    loc.set("from", "rules");
                    break;
                }
        if (!l.alias.empty()) loc.set("alias", l.alias);
        else if (l.root != s.root) loc.set("root", l.root);
        if (l.kind == HandlerKind::proxy) loc.set("upstream", upstream_json(l.proxy));
        if (l.kind == HandlerKind::fastcgi) loc.set("socket", l.fastcgi.address.key);
        if (!l.add_headers.empty()) {
            json::Value h = json::Value::object();
            for (const auto& [n, val] : l.add_headers) h.set(n, val);
            loc.set("add_headers", std::move(h));
        }
        if (!l.hashed_headers.empty()) {
            json::Value h = json::Value::object();
            for (const auto& [n, val] : l.hashed_headers) h.set(n, val);
            loc.set("add_headers_hashed_names", std::move(h));
        }
        locs.push(std::move(loc));
    }
    v.set("locations", std::move(locs));
    // Access by client address: the rules in force, longest path first, each with where it
    // comes from (rules = the managed site's rules.restricted, preset:<app>, or nothing for a
    // hand-written one).
    if (!s.access.empty()) {
        json::Value acc = json::Value::array();
        for (const auto& r : s.access) acc.push(access_rule_json(r, access_rule_from(r, is_managed ? &managed : nullptr)));
        v.set("access", std::move(acc));
    }
    // Passwords: the rules in force, longest first, each with where it comes from and how many of
    // its users can log in now; the names are site_auth_users' (admin).
    if (!s.auth.empty()) {
        json::Value list = json::Value::array();
        for (const auto& r : s.auth) list.push(auth_rule_json(r, auth_rule_from(r, is_managed ? &managed : nullptr), now));
        v.set("auth", std::move(list));
    }
    // `refuse`: the patterns in force, as written (a managed site's come from rules.refuse).
    if (!s.refuse.empty()) {
        json::Value list = json::Value::array();
        for (const auto& p : s.refuse.patterns) list.push(p.text);
        v.set("refuse", std::move(list));
    }
    (void)cfg;
    return v;
}

// ---- validation and health ----

// The restart-only keys the file changed, each by name: the reference rows whose `applies` is
// restart (2026-10-09, the cookbook's finding: the [cache] keys, stream_chunk_size,
// sendfile_max_chunk, tcp_nodelay and pid_file kept their start values on a reload while the
// reference said reload, and nothing said so). The reload's warning, validate and health read it.
std::vector<std::string> restart_needed(const Config& fresh, const Config& running) {
    std::vector<std::string> out;
    auto kept = [&](bool changed, const char* key) {
        if (changed) out.push_back(key);
    };
    kept(fresh.workers != running.workers, "workers");
    kept(fresh.reuse_port != running.reuse_port, "reuse_port");
    kept(fresh.user != running.user, "user");
    kept(fresh.group != running.group, "group");
    kept(fresh.sendfile != running.sendfile, "sendfile");
    kept(fresh.sendfile_max_chunk != running.sendfile_max_chunk, "sendfile_max_chunk");
    kept(fresh.tcp_nodelay != running.tcp_nodelay, "tcp_nodelay");
    kept(fresh.pid_file != running.pid_file, "pid_file");
    kept(fresh.cache_max_file_size != running.cache_max_file_size, "cache.max_file_size");
    kept(fresh.cache_max_size != running.cache_max_size, "cache.max_size");
    kept(fresh.cache_evict_fraction != running.cache_evict_fraction, "cache.evict_fraction");
    kept(fresh.cache_revalidate_s != running.cache_revalidate_s, "cache.revalidate_interval");
    kept(fresh.stream_chunk_size != running.stream_chunk_size, "cache.stream_chunk_size");
    kept(fresh.cache_sendfile_min_size != running.cache_sendfile_min_size, "cache.sendfile_min_size");
    kept(fresh.cache_max_open_files != running.cache_max_open_files, "cache.max_open_files");
    kept(fresh.cache_precompressed != running.cache_precompressed, "cache.precompressed");
    kept(fresh.control.enabled != running.control.enabled, "control");
    kept(fresh.control.enabled && running.control.enabled && fresh.control.socket != running.control.socket, "control.socket");
    kept(fresh.control.provision != running.control.provision, "control.provision");
    // Not the task keys (runtimes, task_limits, task_network): the helper reads them from
    // root's file for every task, and the server from the configuration it runs, so a
    // reload changes them (2026-09-27 Writebook report: a new Ruby cost every site a restart).
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
    for (const fs::path& candidate :
         {dir.parent_path() / "php-fpm.conf", dir.parent_path().parent_path() / "php-fpm.conf"}) {
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
#ifndef _WIN32
    // The site environments' directory (services/appenv.*): open to others, or not its
    // owner's, it stops the tasks of every rails and proxy site (2026-09-27 report: a mkdir
    // under a lax umask left it 0775, and no finding said why every task was refused). Its
    // owner is root when the server drops privileges (the helper writes it), else the server.
    if (std::any_of(running.sites.begin(), running.sites.end(), [](const SiteConfig& x) { return proxy_app(x.app); })) {
        const std::string dir = appenv::dir_of(running.config_path);
        const unsigned owner = boot.user.empty() ? ::geteuid() : 0u;
        struct stat sb {};
        const std::string own = owner == 0 ? "root" : "the server's account";
        if (::lstat(dir.c_str(), &sb) == 0 && !S_ISDIR(sb.st_mode)) {
            add("error", "site_env_unsafe", "", dir + " is not a directory (a symlink or a file): every task of a rails or proxy site is refused and no site environment can be written",
                "as root: mv " + dir + " " + dir + ".refused && mkdir -m 0700 " + dir);
        } else if (::lstat(dir.c_str(), &sb) == 0 && (sb.st_uid != owner || (sb.st_mode & 077) != 0)) {
            const std::string mode = std::to_string((sb.st_mode >> 6) & 7) + std::to_string((sb.st_mode >> 3) & 7) + std::to_string(sb.st_mode & 7);
            add("warn", "site_env_unsafe", "", dir + " is uid " + std::to_string(sb.st_uid) + "'s, mode " + mode + "; it must be " + own + "'s alone (0700): " +
                    (sb.st_uid == owner ? "the next task or site_env call tightens it to 0700 and says so" : "every task of a rails or proxy site is refused until it is"),
                std::string(owner == 0 ? "as root: chown root:root " + dir + " && " : "") + "chmod 0700 " + dir);
        }
    }
#endif

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
        if (s.root.empty() || !s.redirect.empty() || s.app.empty() || s.app == "static" || proxy_app(s.app)) continue;
        const std::string detected = detect_app(s.project_root.empty() ? s.root : s.project_root);
        if (detected.empty() || detected == s.app || detected == "static" || detected == "proxy" || detected == "node" || detected == "php") continue;
        add("warn", "preset_mismatch", s.server_names.front(),
            "the files under " + (s.project_root.empty() ? s.root : s.project_root) + " look like " + detected + " (" + detect_app_marker(detected) +
                "), but app = \"" + s.app + "\": the " + s.app + " preset's refusals do not fit them, and what " + detected +
                "'s own .htaccess would protect may be served",
            "set app = \"" + detected + "\" (site-update " + s.server_names.front() + " with app: " + detected + " for a managed site)");
    }
    // Backup archives and database dumps inside a served tree are one path or one preset
    // away from being public, whatever the preset refuses today.
    for (const auto& s : running.sites) {
        if (s.root.empty() || !s.redirect.empty() || s.app.empty() || s.app == "static" || proxy_app(s.app)) continue;
        const ArchivesInRoot a = archives_in_root(s, 2000);
        if (a.count == 0) continue;
        const std::string size = a.example_bytes >= 1024 * 1024 ? std::to_string((a.example_bytes + 512 * 1024) / (1024 * 1024)) + " MB"
                                                                : std::to_string((a.example_bytes + 512) / 1024) + " KB";
        add("warn", "archives_in_root", s.server_names.front(),
            std::to_string(a.count) + " archive(s) or database dump(s) under the document root, e.g. " + a.example + " (" + size + ")" +
                (a.seen >= 2000 ? ", the first 2000 files looked at" : ""),
            "move backups and dumps out of the document root (a backup plugin's directory too) and delete stale ones; nothing served should hold a copy of the site");
    }
    // Root additions whose site is gone (disabled or deleted, design section 20): the loader
    // keeps them with a warning; this says what to do.
    // Access by client address (docs/configuration.md 19): what the rules may not do as meant.
    for (const auto& n : access_notices(running)) {
        std::string fix;
        if (n.code == "access_allows_proxy") fix = "allow the clients' own addresses and ranges, not the proxy's: behind a trusted proxy the rule judges the X-Forwarded-For client";
        else if (n.code == "access_loopback") fix = "add the local proxy or tunnel to [server] trusted_proxies (127.0.0.1, ::1) so the client it carries is judged, or drop the loopback entry";
        else if (n.code == "access_ipv4_only") fix = "add the client's IPv6 range (its /64) to the rule or to its address set, if it has one";
        else if (n.code == "access_single_ipv6") fix = "allow the /64 the address belongs to";
        else if (n.code == "access_site_restricted") fix = "meant for a staging copy or an internal site; site_update with the rule on / removed when it goes public";
        else if (n.code == "exact_rule_proxied_script") fix = "if the application runs the script's path-info forms (/x.php/anything), make the rule a prefix rule (match = \"prefix\"); otherwise nothing to do";
        else if (n.code == "auth_plain_http") fix = "serve the site over https and drop plain_http from the rule, unless the network is one the user trusts (a LAN tool)";
        else if (n.code == "auth_users_mixed_methods") fix = "give every user of the file one method and cost: agensio passwd NAME writes yescrypt (a managed site's tools always do), then reload";
        add(n.severity == "warning" ? "warn" : "info", n.code, n.site, n.text, fix);
    }
    for (auto& f : auth_findings(running, now)) out.push_back(std::move(f));
    for (const auto& o : running.orphan_additions) {
        std::error_code ec;
        const fs::path f = o.file;
        const bool disabled = fs::exists(f.parent_path() / (o.site + ".toml.disabled"), ec);
        add("warn", "root_additions_orphan", o.site,
            o.file + " holds root additions for site " + o.site + ", which is " + (disabled ? "disabled" : "not in the configuration") + ": its locations are ignored",
            disabled ? "site-enable " + o.site + " brings the site back with its additions; or remove the file"
                     : "remove the file (rm " + o.file + "), or create the site again under that name");
    }
    // Files the server cannot read under a document root (2026-09-20: every upload of every
    // site with a user was 0640 user:user after move_uploaded_file, 404 with no log line).
    {
        const ServerAccount server = server_account(running, system_facts());
        for (const auto& s : running.sites) {
            // A proxy-family site serves nothing from its root (every request goes to the
            // upstream), so what the server cannot read there answers no 404.
            if (s.root.empty() || !s.redirect.empty() || proxy_app(s.app)) continue;
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

std::vector<Finding> auth_findings(const Config& cfg, std::time_t now) {
    std::vector<Finding> out;
    auto day = [](std::int64_t t) {
        const std::time_t tt = static_cast<std::time_t>(t);
        std::tm tm{};
        ::gmtime_r(&tt, &tm);
        char buf[16];
        return std::string(buf, std::strftime(buf, sizeof buf, "%Y-%m-%d", &tm));
    };
    auto joined = [](const std::vector<std::string>& v) {
        std::string t;
        for (const auto& x : v) t += (t.empty() ? "" : ", ") + x;
        return t;
    };
    const fs::path config_dir = cfg.config_path.parent_path().empty() ? fs::path(".") : cfg.config_path.parent_path();
    std::error_code ec;
    for (const auto& s : cfg.sites) {
        if (s.auth.empty() || s.server_names.empty()) continue;
        const std::string site = s.server_names.front();
        const std::string own = fs::absolute(config_dir / "auth" / (site + ".users"), ec).lexically_normal().string();
        std::vector<std::string> files;
        for (const auto& r : s.auth) {
            if (r.open || !r.users || std::find(files.begin(), files.end(), r.users_path) != files.end()) continue;
            files.push_back(r.users_path);
            std::vector<std::string> paths;
            for (const auto& q : s.auth)
                if (!q.open && q.users_path == r.users_path) paths.push_back(q.path);
            const std::string where = joined(paths);
            const bool managed = fs::absolute(r.users_path, ec).lexically_normal().string() == own;
            if (const std::string why = auth_users_problem(r.users_path, cfg); !why.empty()) {
                out.push_back(Finding{"error", "auth_users_unloadable", site,
                                      "the users file of " + where + " would be refused by the next load, so a reload is refused and a restart does not start "
                                      "the server: " + why + ". The running server still asks with the users it loaded",
                                      managed ? "put the file back (root keeps it under " + (config_dir / "auth").string() + "), or correct what the message names; "
                                                "`agensio -t` says when the next load accepts it"
                                              : "correct what the message names (root's file, chmod 640, `agensio passwd USER` for a line); `agensio -t` says when "
                                                "the next load accepts it"});
                continue;
            }
            std::vector<std::string> expired, locked;
            std::size_t can = 0;
            for (const auto& u : r.users->users) {
                if (u.locked) locked.push_back(u.name);
                else if (u.expires && now >= u.expires) expired.push_back(u.name + " (expired " + day(u.expires) + ")");
                else ++can;
            }
            if (can == 0) {
                std::vector<std::string> who = expired;
                for (const auto& l : locked) who.push_back(l + " (locked)");
                out.push_back(Finding{"warn", "auth_no_valid_user", site,
                                      "every login on " + where + " fails: no user of " + r.users_path + " can log in (" + joined(who) + "), so the browser asks and asks",
                                      managed ? "site_auth_user_set " + site + " USER with locked: false or a later expires, or a new user with generate: true; "
                                                "or site_update without the rule if the area is closed for good"
                                              : "unlock or extend a user in the file (`agensio passwd USER` for a new line), or remove the rule"});
                continue;
            }
            if (!expired.empty())
                out.push_back(Finding{"info", "auth_users_expired", site, joined(expired) + " can no longer log in on " + where,
                                      managed ? "site_auth_user_delete " + site + " for each one who is gone, or site_auth_user_set with a later expires"
                                              : "remove their lines from " + r.users_path + ", or change their :expires= field"});
        }
        // Plain HTTP on a listener the network reaches: config.cpp access_notices (auth_plain_http), so -t says it too.
    }
    // Users files no site owns: a deleted site's (site_delete without files leaves it). A site
    // created again under the name with a password rule would let those users in.
    const fs::path adir = config_dir / "auth";
    for (const auto& e : fs::directory_iterator(adir, ec)) {
        const std::string name = e.path().filename().string();
        if (!name.ends_with(".users") || !e.is_regular_file(ec)) continue;
        const std::string stem = name.substr(0, name.size() - 6);
        const std::string abs = fs::absolute(e.path(), ec).lexically_normal().string();
        bool used = false;
        for (const auto& s : cfg.sites) {
            used = used || (!s.server_names.empty() && s.server_names.front() == stem);
            for (const auto& r : s.auth) used = used || (!r.users_path.empty() && fs::absolute(r.users_path, ec).lexically_normal().string() == abs);
        }
        if (!used)
            out.push_back(Finding{"info", "auth_users_orphan", "",
                                  e.path().string() + " belongs to no configured site (a deleted site's password users): a site created again as " + stem +
                                      " with a password rule would let them in",
                                  "as root: rm " + e.path().string() + " (unless the site comes back; site_delete with files moves this file into the trash)"});
    }
    return out;
}

std::vector<Finding> env_findings(const json::Value& inspected) {
    std::vector<Finding> out;
    if (inspected["busy"].boolean()) {
        out.push_back(Finding{"info", "site_env_unchecked", "", "the sites' environment files were not checked: the provisioning helper is running a task", "run health_check again when it ends"});
        return out;
    }
    if (!inspected["ok"].boolean()) {
        out.push_back(Finding{"info", "site_env_unchecked", "", "the sites' environment files could not be checked: " + std::string(inspected.get("error")), ""});
        return out;
    }
    for (const auto& f : inspected["sites"].items()) {
        // A site_env_set call is the admin's tool, not a root command: "as root" goes with
        // the chown, chmod and rm lines only (2026-09-27 report: it steered an agent to hand
        // the user a terminal for a tool call).
        const std::string fix(f.get("fix"));
        out.push_back(Finding{std::string(f.get("severity")), "site_env_unsafe", std::string(f.get("site")), std::string(f.get("problem")),
                              fix.empty() ? std::string("fix the file as root, or remove it and set the variables again with site_env_set")
                              : fix.starts_with("site_env_set") ? fix : "as root: " + fix});
    }
    for (const auto& o : inspected["orphans"].items()) {
        const std::string file(o.is_string() ? o.str() : o.get("file"));
        std::string names;
        for (const auto& n : o["exposed"].items()) names += (names.empty() ? "" : ", ") + std::string(n.str());
        if (names.empty())
            out.push_back(Finding{"info", "site_env_orphan", "", file + " belongs to no configured site (a deleted site's environment: its secrets)",
                                  "as root, when the site is gone for good: rm -f " + file});
        else {
            const bool one = o["exposed"].items().size() == 1;  // "KEY_B in it was ... that value", as the other ledger texts agree
            out.push_back(Finding{"warn", "site_env_orphan", "", file + " belongs to no configured site, and " + names + " in it " + (one ? "was" : "were") +
                                      " readable by others and never rotated: bringing the site back with this file brings " + (one ? "that value" : "those values") + " back",
                                  std::string("rotate ") + (one ? "it" : "them") + " after bringing the site back (site_env_set), or as root, when the site is gone for good: rm -f " + file});
        }
    }
    return out;
}

std::vector<Finding> service_findings(const json::Value& check) {
    std::vector<Finding> out;
    if (!check["ok"].boolean()) return out;  // busy, or no systemctl: nothing to say about it
    for (const auto& r : check["services"].items()) {
        const std::string site(r.get("site")), unit(r.get("unit"));
        const json::Value& st = r["state"];
        const std::string load(st.get("LoadState")), active(st.get("ActiveState")), sub(st.get("SubState")), result(st.get("Result"));
        if (load == "not-found") {
            out.push_back(Finding{"info", "site_service_missing", site, "no unit " + unit + ": nothing runs the application, and every request to it answers 502",
                                  "site_service_unit " + site + " renders it; root installs it with the commands in its answer"});
        } else if (active == "failed") {
            out.push_back(Finding{"warn", "site_service_failed", site, unit + " failed (" + result + ", status " + std::string(st.get("ExecMainStatus")) + ", since " +
                                                                            std::string(st.get("InactiveEnterTimestamp")) + "): every request to the site answers 502",
                                  "site_service_logs " + site + " shows why; after the fix, as root: systemctl restart " + unit});
        } else if (active == "inactive") {
            out.push_back(Finding{"warn", "site_service_down", site, unit + " is stopped: every request to the site answers 502",
                                  "as root: systemctl enable --now " + unit + " (site_service_logs " + site + " shows its last run)"});
        } else if (active == "activating" && sub == "auto-restart") {
            out.push_back(Finding{"warn", "site_service_failed", site, unit + " keeps failing and systemd restarts it (" + std::string(st.get("NRestarts")) + " restarts)",
                                  "site_service_logs " + site + " shows why"});
        }
    }
    return out;
}

std::string ago_text(double s) {
    if (s < 60) return std::to_string(static_cast<long>(s)) + " s";
    if (s < 3600) return std::to_string(static_cast<long>(s / 60)) + " min";
    if (s < 86400) return std::to_string(static_cast<long>(s / 3600)) + " h";
    return std::to_string(static_cast<long>(s / 86400)) + " d";
}

Finding refusal_finding(const RefusalReport& r) {
    std::string from;
    for (std::size_t i = 0; i < r.addresses.size() && i < 3; ++i) from += (i ? ", " : "") + r.addresses[i].first + " x" + std::to_string(r.addresses[i].second);
    if (r.addresses.size() > 3) from += " and " + std::to_string(r.addresses.size() - 3) + " more address" + (r.addresses.size() > 4 ? "es" : "");
    else if (r.more_addresses) from += " and more addresses";
    std::string on;
    for (const auto& l : r.listeners) on += (on.empty() ? "" : ", ") + l.first + (r.listeners.size() > 1 ? " x" + std::to_string(l.second) : "");
    const std::uint64_t capacity = r.ceiling * r.workers;
    const std::string msg = std::to_string(r.refused) + " connection(s) refused at the ceiling since start (first " + ago_text(r.first_s_ago) + " ago, last " + ago_text(r.last_s_ago) +
                            " ago)" + (on.empty() ? "" : " on " + on) + (from.empty() ? "" : ", from " + from) + "; the workers hold " + std::to_string(r.connections) + " of " +
                            std::to_string(capacity) + " connections, " + std::to_string(r.idle) + " idle for 2 s or more (server.max_connections " + std::to_string(r.ceiling) +
                            " per worker)";
    const std::uint64_t top = r.addresses.empty() ? 0 : r.addresses.front().second;
    std::string fix;
    if (r.refused >= 2 && top * 2 >= r.refused)
        fix = "most refusals came from " + r.addresses.front().first + ": the ceiling did its job; limit that address in the firewall (the per-address limits protection_show renders: "
              "nftables, ct count per source) and let fail2ban ban repeat offenders from the access log; nothing to raise (docs/configuration.md 18)";
    else if (capacity && r.connections * 10 >= capacity * 9 && r.idle * 2 >= r.connections)
        fix = "the workers are full of idle connections: slow or stuck clients, or a client keeping connections open; compare with the request rate (logs_query on the access log), "
              "lower server.idle_timeout (15 s by default), and limit connections per address in the firewall (docs/configuration.md 18)";
    else
        fix = "legitimate load from many addresses: raise the open-file limit (LimitNOFILE in the unit) or server.max_connections, then reload (docs/configuration.md 18)";
    return Finding{"warn", "connections_refused", "", msg, fix};
}

json::Value health(const Config& running, const Config& boot, bool as_root, std::time_t now, const std::vector<Finding>& extra) {
    auto findings = health_findings(running, boot, as_root, now);
    findings.insert(findings.end(), extra.begin(), extra.end());
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
