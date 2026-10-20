#include "services/php_requirements.hpp"

#include <algorithm>
#include <array>
#include <cctype>

#include "services/json.hpp"

namespace agensio::php {

namespace {

std::string lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

// A version of up to three numeric parts, each at most five digits; `parts` how many were written.
struct Ver {
    std::array<long, 3> n{0, 0, 0};
    int parts = 0;
};

bool parse_ver(std::string_view s, Ver& v) {
    v = Ver{};
    if (!s.empty() && (s.front() == 'v' || s.front() == 'V')) s.remove_prefix(1);
    while (!s.empty()) {
        if (v.parts == 3) return false;
        std::size_t i = 0;
        long x = 0;
        while (i < s.size() && i < 6 && std::isdigit(static_cast<unsigned char>(s[i]))) x = x * 10 + (s[i++] - '0');
        if (i == 0 || i > 5) return false;
        v.n[static_cast<std::size_t>(v.parts++)] = x;
        s.remove_prefix(i);
        if (s.empty()) break;
        if (s.front() != '.') return false;
        s.remove_prefix(1);
        if (s.empty()) return false;
    }
    return v.parts > 0;
}

int cmp(const Ver& a, const Ver& b) {
    for (std::size_t i = 0; i < 3; ++i)
        if (a.n[i] != b.n[i]) return a.n[i] < b.n[i] ? -1 : 1;
    return 0;
}

// The next version at part `at`: 8.2 at 1 -> 8.3.0, at 0 -> 9.0.0 (an exclusive upper bound).
Ver bump(Ver v, int at) {
    v.n[static_cast<std::size_t>(at)] += 1;
    for (int i = at + 1; i < 3; ++i) v.n[static_cast<std::size_t>(i)] = 0;
    return v;
}

std::vector<std::string_view> split(std::string_view s, std::string_view sep) {
    std::vector<std::string_view> out;
    while (true) {
        const std::size_t at = s.find(sep);
        out.push_back(s.substr(0, at));
        if (at == std::string_view::npos) return out;
        s.remove_prefix(at + sep.size());
    }
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return s;
}

// One comparison of an and-group: true when `v` meets it; `ok` false when it cannot be read.
bool term_allows(std::string_view t, const Ver& v, bool& ok) {
    if (const std::size_t at = t.find('@'); at != std::string_view::npos) t = t.substr(0, at);  // a stability flag
    if (t.empty()) {
        ok = false;
        return true;
    }
    if (t == "*") return true;
    std::string_view op;
    for (std::string_view o : {">=", "<=", "!=", "==", "<>", ">", "<", "=", "^", "~"})
        if (t.starts_with(o)) {
            op = o;
            break;
        }
    t.remove_prefix(op.size());
    t = trim(t);
    // A wildcard: 8.2.* is >= 8.2.0 < 8.3.0; 8.* is >= 8.0.0 < 9.0.0.
    if (t.ends_with(".*") || t.ends_with(".x") || t.ends_with(".X")) {
        Ver base;
        if (!op.empty() || !parse_ver(t.substr(0, t.size() - 2), base) || base.parts > 2) {
            ok = false;
            return true;
        }
        return cmp(v, base) >= 0 && cmp(v, bump(base, base.parts - 1)) < 0;
    }
    Ver w;
    if (!parse_ver(t, w)) {
        ok = false;
        return true;
    }
    if (op == ">=") return cmp(v, w) >= 0;
    if (op == ">") return cmp(v, w) > 0;
    if (op == "<=") return cmp(v, w) <= 0;
    if (op == "<") return cmp(v, w) < 0;
    if (op == "!=" || op == "<>") return cmp(v, w) != 0;
    if (op == "^") {  // the next major, or below 1.0 the next minor
        const int at = w.n[0] > 0 || w.parts == 1 ? 0 : (w.n[1] > 0 || w.parts == 2 ? 1 : 2);
        return cmp(v, w) >= 0 && cmp(v, bump(w, at)) < 0;
    }
    if (op == "~") {  // ~8.2 is >= 8.2 < 9.0, ~8.2.3 is >= 8.2.3 < 8.3.0
        const int at = w.parts <= 1 ? 0 : w.parts - 2;
        return cmp(v, w) >= 0 && cmp(v, bump(w, at)) < 0;
    }
    // Exact: 8.2 means 8.2.0 only in Composer; PHP's patch releases are its point, so "8.2" as a
    // constraint is read as that minor (what an application means when it writes it).
    if (w.parts < 3) return cmp(v, w) >= 0 && cmp(v, bump(w, w.parts - 1)) < 0;
    return cmp(v, w) == 0;
}

}  // namespace

// From each application's own pages for its current stable line, read 2026-10-21 (the research notes and
// every page are listed in docs/configuration.md 7b). Required is only what the application cannot run
// without and enforces: its composer.json's require (Composer refuses to install without them), or for
// WordPress, which ships none, its own wp-includes/version.php ($required_php_extensions). Recommended is
// what its pages ask for beyond that; cache back ends (apcu, memcached, redis) and what a page calls
// optional are neither, and an application's own run-time checks are never read. A site's installed
// release declares its own range, which wins over the minimum here.
const std::vector<AppRequirements>& app_requirement_table() {
    static const std::vector<AppRequirements> table = {
        // WordPress 7.x: 7.4 minimum (6.9 and older 7.2.24), 8.3 recommended, 8.5 supported. mysqli is
        // recommended, not required: a site on the SQLite Database Integration plugin runs without it.
        {"wordpress", "7.4", "8.3", "8.5", {"hash", "json"},
         {"curl", "dom", "exif", "fileinfo", "igbinary", "imagick", "intl", "mbstring", "mysqli", "openssl", "xml", "zip"},
         "https://wordpress.org/about/requirements/", "2026-10-21"},
        // Drupal 11.x (core/composer.json): 8.3.0 minimum, 8.4 recommended (core's RECOMMENDED_PHP), 8.5 supported.
        {"drupal", "8.3.0", "8.4", "8.5",
         {"date", "dom", "filter", "gd", "hash", "json", "pcre", "pdo", "session", "simplexml", "spl", "tokenizer", "xml", "zlib"}, {"openssl"},
         "https://www.drupal.org/docs/getting-started/system-requirements/php-requirements", "2026-10-21"},
        // Laravel 12.x (13.x asks 8.3, which its skeleton's composer.json declares): laravel/framework's
        // require; the deployment page's further extensions recommended.
        {"laravel", "8.2", "", "8.5", {"ctype", "filter", "hash", "mbstring", "openssl", "session", "tokenizer"}, {"curl", "dom", "fileinfo", "pdo", "xml"},
         "https://laravel.com/docs/12.x/deployment#server-requirements", "2026-10-21"},
        // Grav 2.x (1.7 is legacy; its composer.json declares ^7.3.6 || ^8.0): composer.json's require; the
        // requirements page's mbstring and SimpleXML, which composer only suggests, and its iconv and intl
        // recommended. No newest version stated.
        {"grav", "8.3", "", "", {"ctype", "curl", "dom", "fileinfo", "gd", "json", "libxml", "openssl", "session", "zip"},
         {"iconv", "intl", "mbstring", "simplexml"}, "https://learn.getgrav.org/2/basics/requirements", "2026-10-21"},
    };
    return table;
}

const AppRequirements* app_requirements(std::string_view app) {
    for (const auto& r : app_requirement_table())
        if (r.app == app) return &r;
    return nullptr;
}

int compare_versions(std::string_view a, std::string_view b) {
    Ver x, y;
    parse_ver(a, x);
    parse_ver(b, y);
    return cmp(x, y);
}

bool constraint_allows(std::string_view constraint, std::string_view version, bool& known) {
    known = false;
    Ver v;
    if (constraint.size() > 200 || !parse_ver(version, v)) return true;
    bool any = false;
    std::size_t groups = 0;
    for (std::string_view alt : split(constraint, "||")) {
        for (std::string_view part : split(alt, "|")) {  // the single bar Composer still reads
            if (++groups > 16) return true;
            part = trim(part);
            if (part.empty()) return true;
            // A hyphen range, "8.1 - 8.3": >= 8.1, and <= 8.3.x (a partial upper bound covers its minor).
            if (const std::size_t h = part.find(" - "); h != std::string_view::npos) {
                Ver lo, hi;
                if (!parse_ver(trim(part.substr(0, h)), lo) || !parse_ver(trim(part.substr(h + 3)), hi)) return true;
                const bool upper = hi.parts == 3 ? cmp(v, hi) <= 0 : cmp(v, bump(hi, hi.parts - 1)) < 0;
                any = any || (cmp(v, lo) >= 0 && upper);
                continue;
            }
            // The and-group: comparisons separated by spaces or commas; ">= 8.1" with a space is one.
            bool all = true, ok = true;
            std::string term;
            std::size_t terms = 0;
            auto flush = [&] {
                if (term.empty()) return;
                if (++terms > 16) ok = false;
                all = term_allows(term, v, ok) && all;
                term.clear();
            };
            for (std::size_t i = 0; i < part.size(); ++i) {
                const char c = part[i];
                if (c == ',' || std::isspace(static_cast<unsigned char>(c))) {
                    // an operator alone waits for its version
                    if (!term.empty() && term.find_first_of("0123456789*") == std::string::npos) continue;
                    flush();
                } else {
                    term.push_back(c);
                }
            }
            flush();
            if (!ok) return true;
            any = any || all;
        }
    }
    known = true;
    return any;
}

Declared parse_composer(std::string_view json_text) {
    Declared d;
    json::Value v;
    std::string err;
    if (json_text.size() > 512 * 1024 || !json::parse(json_text, v, err) || !v.is_object()) return d;
    const json::Value& req = v["require"];
    if (!req.is_object()) return d;
    d.from = "composer.json";
    if (req["php"].is_string() && req.get("php").size() <= 200) d.php = std::string(req.get("php"));
    for (const auto& [k, val] : req.members()) {
        if (!k.starts_with("ext-") || k.size() > 64 || d.ext.size() >= 64) continue;
        std::string name = lower(std::string_view(k).substr(4));
        if (name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_") == std::string::npos && !name.empty()) d.ext.push_back(std::move(name));
    }
    std::sort(d.ext.begin(), d.ext.end());
    d.ext.erase(std::unique(d.ext.begin(), d.ext.end()), d.ext.end());
    return d;
}

std::string parse_wp_required(std::string_view text) {
    const std::size_t at = text.find("$required_php_version");
    if (at == std::string_view::npos) return {};
    std::string_view rest = text.substr(at + 21, 64);
    const std::size_t eq = rest.find('=');
    if (eq == std::string_view::npos) return {};
    rest.remove_prefix(eq + 1);
    rest = trim(rest);
    if (rest.empty() || (rest.front() != '\'' && rest.front() != '"')) return {};
    const char q = rest.front();
    rest.remove_prefix(1);
    const std::size_t end = rest.find(q);
    if (end == std::string_view::npos) return {};
    const std::string_view value = rest.substr(0, end);
    Ver v;
    return parse_ver(value, v) ? std::string(value) : std::string();
}

Declared declared_from(std::string_view composer_json, std::string_view wp_version_php) {
    Declared d = parse_composer(composer_json);
    if (d.php.empty())
        if (const std::string wp = parse_wp_required(wp_version_php); !wp.empty()) {
            d.php = ">=" + wp;
            d.from = "wp-includes/version.php";
        }
    if (d.php.empty() && d.ext.empty()) d.from.clear();
    return d;
}

RequirementCheck check_requirements(const AppRequirements* table, const Declared& declared, std::string_view version,
                                    const std::vector<std::string>& modules, bool modules_known) {
    RequirementCheck r;
    if (!table && declared.php.empty() && declared.ext.empty()) return r;
    r.judged = true;
    bool known = false;
    if (!declared.php.empty()) {
        r.outside = !constraint_allows(declared.php, version, known);
        if (known) r.range = declared.php + " (" + declared.from + ")";
    }
    if (!known && table && !table->min.empty()) {
        r.outside = compare_versions(version, table->min) < 0;
        r.range = ">= " + table->min + " (" + table->app + "'s requirements)";
    }
    if (table && !table->tested.empty()) {
        Ver v, t;
        // Newer than the newest minor it supports: 8.5 against 8.4 (8.4.30 is not newer).
        if (parse_ver(version, v) && parse_ver(table->tested, t)) r.untested = v.n[0] > t.n[0] || (v.n[0] == t.n[0] && v.n[1] > t.n[1]);
    }
    if (modules_known) {
        auto loaded = [&](const std::string& ext) {
            const std::string e = ext == "opcache" ? "zend opcache" : ext;
            return std::find(modules.begin(), modules.end(), e) != modules.end() || std::find(modules.begin(), modules.end(), ext) != modules.end();
        };
        std::vector<std::string> required = declared.ext;
        if (table) required.insert(required.end(), table->required.begin(), table->required.end());
        std::sort(required.begin(), required.end());
        required.erase(std::unique(required.begin(), required.end()), required.end());
        for (const auto& e : required)
            if (!loaded(e)) r.missing.push_back(e);
        if (table)
            for (const auto& e : table->recommended_ext)
                if (!loaded(e) && std::find(required.begin(), required.end(), e) == required.end()) r.missing_recommended.push_back(e);
    }
    return r;
}

}  // namespace agensio::php
