#include "control/protection.hpp"

#include "control/sites.hpp"

#include <algorithm>
#include <filesystem>
#ifndef _WIN32
#include <pwd.h>
#include <sys/types.h>
#endif
#include <initializer_list>
#include <cctype>
#include <map>
#include <set>

namespace agensio::control {

namespace {

bool loopback_host(std::string_view host) {
    return host == "::1" || host == "localhost" || host.starts_with("127.");
}

void add_unique(std::vector<unsigned>& v, unsigned x) {
    if (std::find(v.begin(), v.end(), x) == v.end()) v.push_back(x);
}

void add_unique(std::vector<std::string>& v, const std::string& x) {
    if (std::find(v.begin(), v.end(), x) == v.end()) v.push_back(x);
}

std::string port_set(const std::vector<unsigned>& ports) {
    std::string out = "{ ";
    for (std::size_t i = 0; i < ports.size(); ++i) out += (i ? ", " : "") + std::to_string(ports[i]);
    return out + " }";
}

std::string port_list(const std::vector<unsigned>& ports) {
    std::string out;
    for (std::size_t i = 0; i < ports.size(); ++i) out += (i ? "," : "") + std::to_string(ports[i]);
    return out;
}

std::string shipped(std::string_view sub) { return std::string(kProtectionShippedDir) + "/" + std::string(sub); }

std::string hex2(unsigned char u) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    return std::string{kHex[u >> 4], kHex[u & 15]};
}

// One character of a login path: literal (escaped when the regex would read it) or
// percent-encoded, a letter under either case's code (the server decodes %55 and %75 alike,
// the applications take either case; alpha.45 report). The two codes of a letter differ in
// the first hex digit alone (0x41-0x5A against 0x61-0x7A), so they are one class:
// (?:c|\x25[46]3). The '%' is written \x25 so the jail file's configparser never sees one,
// and the filter's (?i) covers the hex digits' case.
std::string spelled(char c) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    const unsigned char u = static_cast<unsigned char>(c);
    std::string out = "(?:";
    if (c == '.' || c == '?' || c == '+' || c == '/' || c == '~') out += '\\';
    out += c;
    out += "|\\x25";
    if (std::isalpha(u)) {
        const unsigned char upper = static_cast<unsigned char>(std::toupper(u));
        out += std::string("[") + kHex[upper >> 4] + kHex[(upper >> 4) + 2] + "]" + kHex[u & 15];
    } else {
        out += hex2(u);
    }
    return out + ")";
}

std::string spelled(const std::string& s) {
    std::string out;
    for (char c : s) out += spelled(c);
    return out;
}

// Slashes and dots as a client may write them, literal or encoded (the server decodes %2F
// and %2E before it normalises).
const std::string kSlashes = "(?:/|\\x252F)+";
const std::string kSlashOpt = "(?:/|\\x252F)*";
const std::string kDot = "(?:\\.|\\x252E)";
// Between two segments, and before the first: slashes, then any number of "./" runs and
// "seg/../" pops. The two branches are disjoint (a run starts with a dot, a pop with a plain
// character that is neither a dot nor a percent sign) and each consumes its tokens in one way
// only, so a 16 KB line of "./" costs linear time (alpha.45 report: the first grammar let "."
// start both branches, and such a line took the jail's thread 2.3 s). The group is written
// once, as the filter's `sep` variable, and every path refers to it as <sep>: fail2ban
// substitutes its tags in a jail's filter parameter too, so a path's entry is a hundred
// characters instead of five hundred (the owner's objection to the first rendering).
const std::string kSepText = kSlashes + "(?:(?:" + kDot + kSlashes + "|[^/?\\s.\\x25][^/?\\s\\x25]*" + kSlashes + kDot + kDot + kSlashes + "))*";
const std::string kSep = "<sep>";

}  // namespace

std::string spelling_regex(const LoginPath& lp) {
    const std::size_t q = lp.path.find('?');
    const std::string path = lp.path.substr(0, q);
    std::string body;
    std::size_t i = 0;
    while (i < path.size()) {
        while (i < path.size() && path[i] == '/') ++i;
        if (i >= path.size()) break;
        const std::size_t end = path.find('/', i);
        body += kSep + spelled(path.substr(i, end == std::string::npos ? std::string::npos : end - i));
        i = end == std::string::npos ? path.size() : end;
    }
    // A PHP preset's front controller may stand before the path (/index.php/user/login,
    // /index.php?controller=...), never alone: the path itself is what makes a login.
    const std::string index = kSep + "index" + kDot + "php";
    std::string out;
    if (body.empty()) {
        // The root, a query login: the separator run is the whole path and nothing may follow
        // it but the query, so no trailing-slash quantifier after it (alpha.46 report: the run
        // split two ways against two lookaheads scanned before the '?' made a 10 KB line of
        // slashes cost minutes, with the GIL held, every jail of the daemon standing still).
        out = lp.php ? "(?:" + index + "|" + kSep + ")" : kSep;
    } else {
        out = (lp.php ? "(?:" + index + ")?" : std::string()) + body;
        if (lp.format) out += "(?:" + kDot + "[a-z0-9]{1,8})?";  // Rails' optional format
        // Path info after a .php script, never across a '?', so the query starts where the
        // first '?' is and the parameters are looked for once.
        if (lp.php && path.size() > 4 && path.ends_with(".php")) out += "(?:" + kSlashes + "[^?\\s]*)?";
        else out += kSlashOpt;
    }
    if (q == std::string::npos) return out + "(?:[?&]\\S*)?";
    // The literal '?' first, so a line without a query fails here at once; then every
    // parameter of the entry present after it, in any order, with others allowed: each
    // lookahead runs once, from the '?', and scans the query a single time.
    out += "\\?";
    const std::string query = lp.path.substr(q + 1);
    std::size_t p = 0;
    while (p <= query.size()) {
        const std::size_t amp = query.find('&', p);
        const std::string pair = query.substr(p, amp == std::string::npos ? std::string::npos : amp - p);
        if (!pair.empty()) {
            const std::size_t eq = pair.find('=');
            out += "(?=(?:\\S*&)?" + spelled(pair.substr(0, eq)) + (eq == std::string::npos ? std::string() : "=" + spelled(pair.substr(eq + 1))) + "(?:[&\\s]|$))";
        }
        if (amp == std::string::npos) break;
        p = amp + 1;
    }
    return out + "\\S*";
}

std::string login_paths_regex(const std::vector<LoginPath>& paths) {
    std::string out;
    for (std::size_t i = 0; i < paths.size(); ++i) out += (i ? "|" : "") + spelling_regex(paths[i]);
    return out;
}

namespace {

// The failure tier's rows: what fail2ban and the application communities use (2026-10-03
// research: fail2ban ships drupal-auth over Drupal's syslog module; WordPress's standard is
// the WP fail2ban plugin logging to the auth facility with its own wordpress-hard and
// wordpress-soft filters). A new application is a row.
struct FailureTier {
    std::string_view app;  // a view, so `app == "drupal"` compares the text, not two addresses
    const char* jail;
    const char* filter;
    bool auth_log;  // the auth facility's file; else the system log
    unsigned maxretry;
    const char* findtime;
    const char* bantime;
    const char* source;
    const char* silent;  // a journal with no line of the application: what that means
};
const FailureTier kFailureTiers[] = {
    {"wordpress", "agensio-wordpress-soft", "wordpress-soft", true, 5, "10m", "1h",
     "failed WordPress logins, form and XML-RPC, as the WP fail2ban plugin logs them to the auth log (\"Authentication failure for admin from ...\")",
     "the WP fail2ban plugin is not active on the site yet, or no login has happened since"},
    {"wordpress", "agensio-wordpress-hard", "wordpress-hard", true, 1, "10m", "1d",
     "what the WP fail2ban plugin logs as hostile at the first hit (blocked user names, pingback errors)",
     "the WP fail2ban plugin is not active on the site yet, or no login has happened since"},
    {"drupal", "agensio-drupal-auth", "drupal-auth", false, 5, "10m", "1h",
     "failed Drupal logins as its Syslog module logs them (\"Login attempt failed for ...\"), with fail2ban's own drupal-auth filter",
     "Drupal's Syslog module is not enabled on the site yet"},
};

std::string first_existing(std::initializer_list<const char*> candidates, bool& present) {
    std::error_code ec;
    for (const char* c : candidates)
        if (std::filesystem::is_regular_file(c, ec)) {
            present = true;
            return c;
        }
    present = false;
    return *candidates.begin();
}

std::string join(const std::vector<std::string>& v, const char* sep);

std::vector<std::string> tier_needs(const std::string& app, const std::string& root, const std::string& log, bool log_present, bool journal,
                                    const std::vector<std::string>& unidentified = {}) {
    std::vector<std::string> out;
    if (app == "wordpress") {
        out.push_back("install and activate the WP fail2ban plugin from the WordPress admin panel (Plugins > Add New, \"WP fail2ban\"); it logs every failed login to the system's auth log; agensio installs no plugin");
        // The plugin's filter files sit in the site's tree, which the site's account can write
        // (alpha.47 report: a planted filter bans whom it likes or freezes fail2ban): root takes
        // them from the plugin's release, or reads the site's copies first.
        out.push_back("as root, take the plugin's two filters from its release, not from the site's directory, which the site's account can write: cd /tmp && curl -fsSLO "
                      "https://downloads.wordpress.org/plugin/wp-fail2ban.latest-stable.zip && unzip -o -j wp-fail2ban.latest-stable.zip wp-fail2ban/filters.d/wordpress-hard.conf "
                      "wp-fail2ban/filters.d/wordpress-soft.conf -d /etc/fail2ban/filter.d/ (or read " + root + "/wp-content/plugins/wp-fail2ban/filters.d/wordpress-hard.conf and "
                      "wordpress-soft.conf first, then install -m 644 them into /etc/fail2ban/filter.d/)");
    } else if (app == "drupal") {
        out.push_back("enable Drupal's Syslog module in the site (Extend > Syslog) so that failed logins reach the system log; the drupal-auth filter ships with fail2ban; agensio changes nothing in the application");
    }
    if (journal && !unidentified.empty())
        out.push_back("give " + join(unidentified, ", ") + " an account of its own (site_update with user; the PHP pool then runs as it), so that its journal lines carry a trusted _UID: the jail reads no line of a site it cannot tell from any other process on the host, since SYSLOG_IDENTIFIER is whatever a writer claims");
    if (!journal && !log_present) out.push_back("the log " + log + " is not on this host although a syslog daemon runs: have it write that file, or stop the daemon and the jail reads the journal");
    out.push_back("then render the jail again, as root: agensio ctl protection --jail > " + std::string(kJailFile) + "; fail2ban-client reload");
    return out;
}

// Why a failure jail is rendered disabled, for the jail file's comment and health's finding.
std::vector<std::string> disabled_reasons(const FailureJail& f) {
    std::vector<std::string> out;
    if (!f.filter_installed) out.push_back("the filter " + f.filter + " is not in /etc/fail2ban/filter.d/");
    if (!f.journal && !f.log_present) out.push_back("the log " + f.log + " is not on this host");
    if (f.journal && f.journalmatch.empty()) out.push_back("no site of this jail has an account of its own on this host, so no trusted journal field (_UID) tells its lines from any other process's");
    return out;
}

#ifndef _WIN32
std::optional<unsigned> system_uid(const std::string& account) {
    if (const struct passwd* pw = ::getpwnam(account.c_str())) return static_cast<unsigned>(pw->pw_uid);
    return std::nullopt;
}
#else
std::optional<unsigned> system_uid(const std::string&) { return std::nullopt; }
#endif

}  // namespace

bool syslog_daemon_present() {
    std::error_code ec;
    for (const char* pid : {"/run/rsyslogd.pid", "/run/syslog-ng.pid", "/run/syslogd.pid"})
        if (std::filesystem::exists(pid, ec)) return true;
    return false;
}

std::vector<std::string> failure_tier_steps(const std::string& app, const std::string& root, const std::string& site_without_account) {
    for (const auto& t : kFailureTiers)
        if (app == t.app) {
            bool present = false;
            const std::string log = t.auth_log ? first_existing({"/var/log/auth.log", "/var/log/secure"}, present) : first_existing({"/var/log/syslog", "/var/log/messages"}, present);
            std::vector<std::string> out{"fail2ban counts this site's failed logins, not only the attempts at its login paths, once the application's side is in place:"};
            std::vector<std::string> unidentified;
            if (!site_without_account.empty()) unidentified.push_back(site_without_account + " (no account of its own: the site's user is not set)");
            for (const auto& n : tier_needs(app, root, log, present, !syslog_daemon_present(), unidentified)) out.push_back(n);
            return out;
        }
    return {};
}

namespace {

// The access-log jails share the shape; the text is one place so the shipped copy and the host's
// rendering never drift.
std::string login_filter_text() {
    std::string paths;
    const ProtectionInput def = default_protection_input();
    if (!def.login_jails.empty()) paths = login_paths_regex(def.login_jails.front().paths);
    return "# fail2ban filter for agensio (docs/configuration.md 18): credentials posted to a login path.\n"
           "# The access log is in the combined format, the client address its first field (behind a\n"
           "# trusted proxy, the one X-Forwarded-For named). A form login is a POST; a failed and a\n"
           "# successful one look alike in an access log, so this counts attempts: no one types ten\n"
           "# passwords in ten minutes, every brute-force tool does. The jail passes this host's login\n"
           "# paths as `paths` (agensio ctl protection --jail renders them from the sites' presets and\n"
           "# their login_paths); the default below is every preset's. Each path is written in every\n"
           "# spelling the server and the applications accept, since the log holds the request as the\n"
           "# client sent it: every character literal or percent-encoded (the percent written \\x25), repeated\n"
           "# slashes (encoded too), ./ and seg/../ segments, any case, for a PHP preset an optional\n"
           "# /index.php front controller before the path and path info after a .php file, for a Rails\n"
           "# application an optional .format suffix, and for a login routed through the query string its\n"
           "# parameters in any order with others allowed. The grammar is unambiguous, so a long request\n"
           "# line costs linear time. agensio ctl protection renders the same from each site's paths, one\n"
           "# agensio-login jail per access log.\n"
           "\n"
           "[INCLUDES]\n"
           "before = common.conf\n"
           "\n"
           "[Init]\n"
           "# <sep>: a path separator as a client may write it: slashes, literal or encoded, then any\n"
           "# number of ./ runs and seg/../ pops; unambiguous, so a long line costs linear time.\n"
           "sep = " + kSepText + "\n"
           "paths = " + paths + "\n"
           "\n"
           "[Definition]\n"
           "failregex = (?i)^<HOST> \\S+ \\S+ \\[\\] \"POST (?:<paths>) HTTP/\\S+\" \\d{3} \n"
           "ignoreregex =\n"
           "datepattern = ^[^\\[]*\\[({DATE})\n";
}

// Failed passwords on [[site.auth]] paths (2026-10-08), from the error log as fail2ban's own
// nginx-http-auth and apache-auth read theirs (docs/fail2ban-ref/config/filter.d/): a 401 in an
// access log is the challenge every browser meets first, so counting 401s (this filter until
// alpha.57) banned the people who had the password. The line is Dispatcher::auth_failed_line's:
// the client first and ours (an address, <ADDR>), what a client chose later and escaped, so a
// user name cannot pass for another address; "expired" is a right password and no guess.
const char* kFilterAuth =
    "# fail2ban filter for agensio (docs/configuration.md 18, 19b): failed passwords on [[site.auth]] paths.\n"
    "# One \"auth failed\" line in the error log per login the server refused: a wrong password, an unknown\n"
    "# or locked user, malformed credentials. The challenge every browser meets first (a 401 without\n"
    "# credentials) writes none, and an expired user's right password is no guess; the error log, not the\n"
    "# access log, as fail2ban's own nginx-http-auth and apache-auth read theirs.\n"
    "\n"
    "[INCLUDES]\n"
    "before = common.conf\n"
    "\n"
    "[Definition]\n"
    "failregex = ^\\s*\\[warn\\] auth failed: client <ADDR> site \\S+ realm \"[^\"]*\" user \"[^\"]*\" \\((?:wrong password|unknown user|locked user|malformed credentials)\\) \n"
    "ignoreregex =\n"
    "datepattern = {^LN-BEG}\n";

// Requests refused with 403: an address outside a site's access rule ([[site.access]]), a password
// asked over plain HTTP, an application refusing. 401 is not counted (see above).
const char* kFilterDenied =
    "# fail2ban filter for agensio (docs/configuration.md 18): requests refused with 403.\n"
    "# An address outside a site's access rule, a password asked for over plain HTTP, an application\n"
    "# refusing. A 401 is not counted: every browser meets one first on a password-protected path\n"
    "# (agensio-auth counts the failed passwords themselves, from the error log).\n"
    "\n"
    "[INCLUDES]\n"
    "before = common.conf\n"
    "\n"
    "[Definition]\n"
    "failregex = ^<HOST> \\S+ \\S+ \\[\\] \"\\S+ \\S+ HTTP/\\S+\" 403 \n"
    "ignoreregex =\n"
    "datepattern = ^[^\\[]*\\[({DATE})\n";

const char* kFilterScan =
    "# fail2ban filter for agensio (docs/configuration.md 18): paths that do not exist, in numbers.\n"
    "# A browser meets a 404 now and then; a scanner probing for wp-login.php, phpmyadmin and\n"
    "# backups meets dozens a minute (the agensio presets answer those 404 themselves).\n"
    "\n"
    "[INCLUDES]\n"
    "before = common.conf\n"
    "\n"
    "[Definition]\n"
    "failregex = ^<HOST> \\S+ \\S+ \\[\\] \"(?:GET|POST|HEAD) \\S+ HTTP/\\S+\" 404 \n"
    "ignoreregex =\n"
    "datepattern = ^[^\\[]*\\[({DATE})\n";

const char* kFilterPost =
    "# fail2ban filter for agensio (docs/configuration.md 18): POST requests, whatever the path.\n"
    "# The catch-all behind agensio-login for an application whose login path nobody named: the\n"
    "# jail's threshold is high (a POST a second, sustained), so a user never reaches it and a\n"
    "# brute-force tool does. An API clients legitimately post to that often is excluded with\n"
    "# the `ignore` parameter: filter = agensio-post[ignore=\"/api/|/jsonrpc\\.php\"] in the jail.\n"
    "\n"
    "[INCLUDES]\n"
    "before = common.conf\n"
    "\n"
    "[Init]\n"
    "ignore = (?!)\n"
    "\n"
    "[Definition]\n"
    "failregex = ^<HOST> \\S+ \\S+ \\[\\] \"POST \\S+ HTTP/\\S+\" \\d{3} \n"
    "ignoreregex = ^<HOST> \\S+ \\S+ \\[\\] \"POST (?:<ignore>)\n"
    "datepattern = ^[^\\[]*\\[({DATE})\n";

const std::vector<ProtectionFilter>& shipped_filters() {
    static const std::vector<ProtectionFilter> kFilters = {
        {"agensio-login", login_filter_text()}, {"agensio-auth", kFilterAuth}, {"agensio-scan", kFilterScan}, {"agensio-post", kFilterPost}, {"agensio-denied", kFilterDenied}};
    return kFilters;
}

// ---- the helper's answer ----

// Ports a match expression names: `tcp dport 443`, `tcp dport { 80, 443 }`, `tcp dport 8000-8010`,
// `tcp dport @ports` (resolved through the ruleset's sets when their elements were listed).
using PortSets = std::map<std::string, std::vector<unsigned>>;

void ports_of_value(const json::Value& v, std::vector<unsigned>& out, const PortSets& sets) {
    if (v.type() == json::Value::Type::number) {
        if (v.num() >= 1 && v.num() <= 65535) add_unique(out, static_cast<unsigned>(v.num()));
    } else if (v.is_string()) {
        const std::string s(v.str());
        if (s == "http") add_unique(out, 80);
        else if (s == "https") add_unique(out, 443);
        else if (s.starts_with("@")) {
            if (auto it = sets.find(s.substr(1)); it != sets.end())
                for (unsigned p : it->second) add_unique(out, p);
        }
    } else if (v.is_array()) {
        for (const auto& e : v.items()) ports_of_value(e, out, sets);
    } else if (v.is_object()) {
        if (v["set"].is_array()) ports_of_value(v["set"], out, sets);
        if (v["range"].is_array() && v["range"].items().size() == 2) {
            const double a = v["range"].items()[0].num(), b = v["range"].items()[1].num();
            if (a >= 1 && b <= 65535 && b >= a && b - a <= 1024)
                for (unsigned p = static_cast<unsigned>(a); p <= static_cast<unsigned>(b); ++p) add_unique(out, p);
        }
        if (v["elem"].is_object() || v["elem"].is_array() || v["elem"].type() == json::Value::Type::number) ports_of_value(v["elem"], out, sets);
        if (v["val"].type() == json::Value::Type::number || v["val"].is_object()) ports_of_value(v["val"], out, sets);
    }
}

// True when the expression tree holds a per-source limit: a `limit` statement or a `ct count`
// (both inside a dynamic set update, or on their own).
bool has_limit(const json::Value& v) {
    if (v.is_object()) {
        for (const auto& m : v.members()) {
            if (m.first == "limit" || m.first == "ct count") return true;
            if (has_limit(m.second)) return true;
        }
    } else if (v.is_array()) {
        for (const auto& e : v.items())
            if (has_limit(e)) return true;
    }
    return false;
}

std::string unit_state_word(const json::Value& st) {
    if (st.is_null()) return "";
    if (st.get("LoadState") == "not-found") return "not-found";
    const std::string_view file = st.get("UnitFileState");
    if (file == "enabled" || file == "enabled-runtime" || file == "static") return "enabled";
    return "disabled";
}

std::string after_label(const std::string& text, std::string_view label) {
    const std::size_t at = text.find(label);
    if (at == std::string::npos) return "";
    std::size_t p = at + label.size();
    while (p < text.size() && (text[p] == ':' || text[p] == '\t' || text[p] == ' ')) ++p;
    const std::size_t nl = text.find('\n', p);
    std::string v = text.substr(p, nl == std::string::npos ? std::string::npos : nl - p);
    while (!v.empty() && (v.back() == '\r' || v.back() == ' ' || v.back() == '\t')) v.pop_back();
    return v;
}

std::uint64_t number_after(const std::string& text, std::string_view label) {
    const std::string v = after_label(text, label);
    if (v.empty() || v.find_first_not_of("0123456789") != std::string::npos) return 0;
    return std::stoull(v);
}

std::string join(const std::vector<std::string>& v, const char* sep) {
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) out += (i ? sep : "") + v[i];
    return out;
}

std::string join_ports(const std::vector<unsigned>& v) {
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) out += (i ? ", " : "") + std::to_string(v[i]);
    return out;
}

json::Value strings_json(const std::vector<std::string>& v) {
    json::Value a = json::Value::array();
    for (const auto& s : v) a.push(s);
    return a;
}

json::Value ports_json(const std::vector<unsigned>& v) {
    json::Value a = json::Value::array();
    for (unsigned p : v) a.push(static_cast<double>(p));
    return a;
}

std::string ports_to_shell(const std::vector<std::string>& cmds) { return join(cmds, "; "); }

}  // namespace

ProtectionInput protection_input(const Config& cfg, const UidLookup& uid_of, std::optional<bool> journal) {
    ProtectionInput in;
    in.firewall_file = (cfg.config_path.parent_path() / "firewall.nft").string();
    in.host_protection = cfg.control.host_protection;
    in.combined = !cfg.log.json;
    if (cfg.log.error != "stderr") in.error_log = cfg.log.error;
    in.error_log_warn = cfg.log.level != "error";
    for (const auto& s : cfg.sites) {
        if (!s.server_names.empty() && std::any_of(s.auth.begin(), s.auth.end(), [](const AuthRule& r) { return !r.open; })) add_unique(in.auth_sites, s.server_names.front());
        for (const auto& l : s.listen) {
            const std::size_t colon = l.rfind(':');
            if (colon == std::string::npos) continue;
            const std::string host = l.substr(0, colon);
            const unsigned port = static_cast<unsigned>(std::atoi(l.c_str() + colon + 1));
            if (loopback_host(host) || !port) continue;
            in.exposed = true;
            add_unique(in.tcp_ports, port);
            if (s.tls && s.h3) add_unique(in.udp_ports, port);
        }
        const std::string name = s.server_names.empty() ? std::string() : s.server_names.front();
        LoginJail* jail = nullptr;
        if (s.access_log.empty()) {
            if (!name.empty()) add_unique(in.unlogged, name);
        } else {
            add_unique(in.logs, s.access_log);
            auto it = std::find_if(in.login_jails.begin(), in.login_jails.end(), [&](const LoginJail& j) { return j.log == s.access_log; });
            if (it == in.login_jails.end()) {
                in.login_jails.push_back(LoginJail{"", s.access_log, {}, {}});
                it = in.login_jails.end() - 1;
            }
            if (!name.empty()) add_unique(it->sites, name);
            jail = &*it;
        }
        const bool php = php_app(s.app), format = rails_app(s.app);
        auto add_path = [&](const std::string& p) {
            add_unique(in.login_paths, p);
            if (!jail) return;
            auto found = std::find_if(jail->paths.begin(), jail->paths.end(), [&](const LoginPath& lp) { return lp.path == p; });
            if (found == jail->paths.end()) jail->paths.push_back(LoginPath{p, php, format});
            else {
                found->php = found->php || php;
                found->format = found->format || format;
            }
        };
        for (const auto& p : preset_login_paths(s.app)) add_path(p);
        for (const auto& p : s.login_paths) add_path(p);
    }
    std::sort(in.tcp_ports.begin(), in.tcp_ports.end());
    std::sort(in.udp_ports.begin(), in.udp_ports.end());
    std::sort(in.logs.begin(), in.logs.end());
    std::sort(in.login_paths.begin(), in.login_paths.end());
    std::sort(in.auth_sites.begin(), in.auth_sites.end());
    // The server-wide log's jail first, then one per site log, named after the first site writing it.
    std::stable_sort(in.login_jails.begin(), in.login_jails.end(), [&](const LoginJail& a, const LoginJail& b) {
        const bool da = a.log == cfg.log.access, db = b.log == cfg.log.access;
        return da != db ? da : a.log < b.log;
    });
    // The failure tier: one jail per row whose preset a site uses, the sites listed, the host's
    // log and filter files looked for now (enabled only with both).
    for (const auto& t : kFailureTiers) {
        FailureJail fj;
        std::string root;
        for (const auto& s : cfg.sites)
            if (s.app == t.app && !s.server_names.empty()) {
                add_unique(fj.sites, s.server_names.front());
                if (root.empty()) root = s.root;
            }
        if (fj.sites.empty()) continue;
        fj.name = t.jail;
        fj.app = t.app;
        fj.filter = t.filter;
        fj.maxretry = t.maxretry;
        fj.findtime = t.findtime;
        fj.bantime = t.bantime;
        fj.source = t.source;
        fj.silent = t.silent;
        fj.log = t.auth_log ? first_existing({"/var/log/auth.log", "/var/log/secure"}, fj.log_present) : first_existing({"/var/log/syslog", "/var/log/messages"}, fj.log_present);
        fj.journal = journal.value_or(!syslog_daemon_present());
        if (fj.journal) {
            // One group per site account: its uid, the field journald attached from the sender's
            // credentials, with the php-fpm unit for WordPress (the plugin's identity carries the
            // client's Host header, so it is not matched; the plugin's filters require it in the
            // line, _daemon = (?:wordpress|wp)) and the Syslog module's default identity for
            // Drupal (fail2ban's drupal-auth filter pins no identity itself, so this word is the
            // one selecting Drupal's lines); groups joined with "+", fail2ban's and journalctl's
            // "or" (docs/fail2ban-ref/filtersystemd.py, addJournalMatch). Never the identity
            // alone: any process may claim it (alpha.49 report). A site without an account, or
            // whose account is not on this host, has no trusted field: listed, not read.
            std::string unit;
            if (t.app != "drupal") {
                const std::string reload = php_fpm_reload_command(cfg, "");
                if (const std::size_t at = reload.find("systemctl reload "); at != std::string::npos) {
                    unit = reload.substr(at + 17);
                    unit = unit.substr(0, unit.find(' '));
                    if (!unit.empty()) unit = "_SYSTEMD_UNIT=" + unit + ".service";
                }
            }
            std::vector<std::string> groups;
            for (const auto& s : cfg.sites) {
                if (s.app != t.app || s.server_names.empty()) continue;
                const std::string& name = s.server_names.front();
                if (s.user.empty()) {
                    fj.unidentified.push_back(name + " (no account of its own: the site's user is not set)");
                    continue;
                }
                const std::optional<unsigned> uid = uid_of ? uid_of(s.user) : system_uid(s.user);
                if (!uid) {
                    fj.unidentified.push_back(name + " (the account " + s.user + " does not exist on this host)");
                    continue;
                }
                std::string group = t.app == "drupal" ? std::string("SYSLOG_IDENTIFIER=drupal") : unit;
                group += (group.empty() ? "" : " ") + std::string("_UID=") + std::to_string(*uid);
                add_unique(groups, group);
                if (*uid >= 1000) fj.user_journals = true;
            }
            for (const auto& g : groups) fj.journalmatch += (fj.journalmatch.empty() ? "" : " + ") + g;
        }
        std::error_code ec;
        fj.filter_installed = std::filesystem::is_regular_file("/etc/fail2ban/filter.d/" + fj.filter + ".conf", ec);
        fj.needs = tier_needs(fj.app, root, fj.log, fj.log_present, fj.journal, fj.unidentified);
        in.failure_jails.push_back(std::move(fj));
    }
    std::vector<std::string> taken;
    for (auto& j : in.login_jails) {
        std::sort(j.paths.begin(), j.paths.end(), [](const LoginPath& a, const LoginPath& b) { return a.path < b.path; });
        std::string base = "agensio-login";
        if (j.log != cfg.log.access && !j.sites.empty()) {
            base += "-";
            for (char c : j.sites.front()) base += std::isalnum(static_cast<unsigned char>(c)) ? static_cast<char>(std::tolower(static_cast<unsigned char>(c))) : '-';
        }
        std::string name = base;
        for (unsigned n = 2; std::find(taken.begin(), taken.end(), name) != taken.end(); ++n) name = base + "-" + std::to_string(n);
        taken.push_back(name);
        j.name = name;
    }
    return in;
}

ProtectionInput default_protection_input() {
    ProtectionInput in;
    in.tcp_ports = {80, 443};
    in.udp_ports = {443};
    in.logs = {"/var/log/agensio/access.log"};
    in.error_log = "/var/log/agensio/error.log";
    LoginJail jail{"agensio-login", in.logs.front(), {}, {}};
    for (const auto& app : app_presets())
        for (const auto& p : preset_login_paths(app)) {
            add_unique(in.login_paths, p);
            auto found = std::find_if(jail.paths.begin(), jail.paths.end(), [&](const LoginPath& lp) { return lp.path == p; });
            if (found == jail.paths.end()) jail.paths.push_back(LoginPath{p, php_app(app), rails_app(app)});
            else {
                found->php = found->php || php_app(app);
                found->format = found->format || rails_app(app);
            }
        }
    std::sort(in.login_paths.begin(), in.login_paths.end());
    std::sort(jail.paths.begin(), jail.paths.end(), [](const LoginPath& a, const LoginPath& b) { return a.path < b.path; });
    in.login_jails.push_back(std::move(jail));
    in.exposed = true;
    in.firewall_file = std::string(kDefaultFirewallFile);
    return in;
}

std::string render_nft(const ProtectionInput& in) {
    const std::string tcp = port_set(in.tcp_ports.empty() ? std::vector<unsigned>{80, 443} : in.tcp_ports);
    std::string s;
    s += "#!/usr/sbin/nft -f\n";
    s += "# agensio: per-address limits on the web ports, in a table of its own (docs/configuration.md 18).\n";
    s += "# Rendered by `agensio ctl protection --nft` for this host's listeners; the packaged copy at\n";
    s += "# " + shipped("firewall/agensio.nft") + " is the rendering for ports 80 and 443.\n";
    s += "# Nothing outside `table inet agensio` is touched: no other table, chain or rule, no policy, so\n";
    s += "# the distribution's firewall, a panel's rules, ufw and firewalld keep theirs and this keeps its own.\n";
    s += "#   trial:  nft -f THIS_FILE          (in the kernel only; `nft delete table inet agensio` or a reboot removes it)\n";
    s += "#   keep:   systemctl enable --now agensio-firewall.service   (loads " + in.firewall_file + " at boot)\n";
    s += "table inet agensio\n";
    s += "delete table inet agensio\n";
    s += "table inet agensio {\n";
    s += "    # Per-source state: new connections in the last minute, connections held, QUIC handshakes.\n";
    s += "    # IPv6 is counted per /64, one subscriber.\n";
    s += "    set new4 { type ipv4_addr; flags dynamic; timeout 1m; }\n";
    s += "    set new6 { type ipv6_addr; flags dynamic; timeout 1m; }\n";
    s += "    set held4 { type ipv4_addr; flags dynamic; }\n";
    s += "    set held6 { type ipv6_addr; flags dynamic; }\n";
    if (!in.udp_ports.empty()) {
        s += "    set quic4 { type ipv4_addr; flags dynamic; timeout 1m; }\n";
        s += "    set quic6 { type ipv6_addr; flags dynamic; timeout 1m; }\n";
    }
    s += "    chain input {\n";
    s += "        type filter hook input priority filter - 10; policy accept;\n";
    s += "        # Loopback and the packets of connections already accepted are not this chain's business.\n";
    s += "        iif \"lo\" return\n";
    s += "        ct state established,related return\n";
    s += "        # More than 30 new connections a second from one address (bursts of 60 allowed): dropped.\n";
    s += "        tcp dport " + tcp + " ct state new update @new4 { ip saddr limit rate over 30/second burst 60 packets } counter drop comment \"agensio: new connections per IPv4 address\"\n";
    s += "        tcp dport " + tcp + " ct state new update @new6 { ip6 saddr & ffff:ffff:ffff:ffff:: limit rate over 30/second burst 60 packets } counter drop comment \"agensio: new connections per IPv6 /64\"\n";
    s += "        # More than 200 connections held by one address: the next one is refused with a reset.\n";
    s += "        tcp dport " + tcp + " ct state new add @held4 { ip saddr ct count over 200 } counter reject with tcp reset comment \"agensio: connections held per IPv4 address\"\n";
    s += "        tcp dport " + tcp + " ct state new add @held6 { ip6 saddr & ffff:ffff:ffff:ffff:: ct count over 200 } counter reject with tcp reset comment \"agensio: connections held per IPv6 /64\"\n";
    if (!in.udp_ports.empty()) {
        const std::string udp = port_set(in.udp_ports);
        s += "        # QUIC: more than 50 handshakes a second from one address (long-header packets, the first\n";
        s += "        # byte's top two bits set, RFC 9000 17.2); the data packets of a connection are never limited here.\n";
        s += "        udp dport " + udp + " @th,64,8 & 0xc0 == 0xc0 update @quic4 { ip saddr limit rate over 50/second burst 100 packets } counter drop comment \"agensio: QUIC handshakes per IPv4 address\"\n";
        s += "        udp dport " + udp + " @th,64,8 & 0xc0 == 0xc0 update @quic6 { ip6 saddr & ffff:ffff:ffff:ffff:: limit rate over 50/second burst 100 packets } counter drop comment \"agensio: QUIC handshakes per IPv6 /64\"\n";
    }
    s += "    }\n";
    s += "}\n";
    return s;
}

namespace {

// What root changes so that agensio-auth has lines to read: the error log in a file, at warn.
// Empty when it has them.
std::string auth_log_step(const ProtectionInput& in) {
    if (in.error_log.empty())
        return "[log] error = \"/var/log/agensio/error.log\" in the main configuration (root's; the package's default), "
               "then agensio reload and this file rendered again";
    if (!in.error_log_warn) return "[log] level = \"warn\" in the main configuration (root's), then agensio reload and this file rendered again";
    return {};
}

}  // namespace

std::string render_jail(const ProtectionInput& in) {
    const std::string ports = port_list(in.tcp_ports.empty() ? std::vector<unsigned>{80, 443} : in.tcp_ports);
    const std::vector<std::string> logs = in.logs.empty() ? std::vector<std::string>{"/var/log/agensio/access.log"} : in.logs;
    std::string logpath;
    for (std::size_t i = 0; i < logs.size(); ++i) logpath += (i ? "\n            " : "") + logs[i];
    std::string s;
    s += "# agensio: fail2ban jails over its access logs and its error log (docs/configuration.md 18), rendered by\n";
    s += "# `agensio ctl protection --jail` for this host: its web ports, its logs and the login\n";
    s += "# paths of its sites (each preset's, plus every site's login_paths), one login jail per log, and for a\n";
    s += "# preset whose application logs its failed logins (WordPress with the WP fail2ban plugin, Drupal with its\n";
    s += "# Syslog module) a jail over that log, counting failures rather than attempts. Install as\n";
    s += "# " + std::string(kJailFile) + " with the filters from " + shipped("fail2ban/filter.d") + ", then\n";
    s += "# `fail2ban-client reload`; render again when a site is added (health says when this file is stale).\n";
    s += "# The access logs are in the combined format: the client address is the first field (behind a trusted\n";
    s += "# proxy, the one X-Forwarded-For named), as in the error log's lines. Bans go through nftables into fail2ban's own table;\n";
    s += "# a host whose firewall is managed otherwise sets banaction in its jail.local.\n";
    if (!in.combined)
        s += "#\n# NOTE: this host's access logs are JSON ([log] format = \"json\"); these filters read the combined\n# format only, so nothing here matches until the format is combined.\n";
    // One login jail per access log, with the paths of the sites that write it, in every
    // spelling; a host without a known login path gets the jail disabled with the reason.
    std::vector<LoginJail> jails = in.login_jails;
    if (jails.empty()) jails.push_back(LoginJail{"agensio-login", "", {}, {}});
    for (const auto& j : jails) {
        const std::string paths = login_paths_regex(j.paths);
        s += "\n[" + j.name + "]\n";
        s += "# Credentials posted to a login path" + (j.sites.empty() ? std::string() : " of " + join(j.sites, ", ")) + ": ten in ten minutes bans for an hour.\n";
        if (paths.empty()) {
            s += "# No login path is known for the site(s) writing this log: name them with the sites' login_paths\n";
            s += "# (site_update, agensio ctl site-update NAME --login-path /login), then render this file again.\n";
            s += "enabled   = false\n";
        } else {
            s += "enabled   = true\n";
        }
        s += "port      = " + ports + "\n";
        s += "filter    = agensio-login" + (paths.empty() ? std::string() : "[paths=\"" + paths + "\"]") + "\n";
        s += "logpath   = " + (j.log.empty() ? logpath : j.log) + "\n";
        s += "banaction = nftables-multiport\n";
        s += "maxretry  = 10\n";
        s += "findtime  = 10m\n";
        s += "bantime   = 1h\n";
    }
    // The failure tier: failures the application logged itself, read with the filter fail2ban
    // or the application ships; enabled only when the filter file and the log exist, since
    // fail2ban refuses a configuration that names either when missing.
    for (const auto& f : in.failure_jails) {
        s += "\n[" + f.name + "]\n";
        s += "# " + f.source + ", for " + join(f.sites, ", ") + ": " + std::to_string(f.maxretry) + " in " + f.findtime + " ban" + (f.maxretry == 1 ? "s" : "") + " for " + f.bantime + ".\n";
        if (f.journal) {
            s += "# Reads the journal: no syslog daemon writes files on this host, so a log file would stay empty.\n";
            s += "# Matched on each site account's _UID, a field journald sets from the sender's credentials, never on the\n";
            s += "# identity alone, which any process may claim.\n";
            if (!f.unidentified.empty()) s += "# Not read, no trusted field tells their lines apart: " + join(f.unidentified, ", ") + ".\n";
        }
        if (!f.enabled()) {
            s += "# Disabled: " + join(disabled_reasons(f), "; ") + ". Needs:\n";
            for (const auto& n : f.needs) s += "#   " + n + "\n";
            s += "enabled   = false\n";
        } else {
            s += "enabled   = true\n";
        }
        s += "port      = " + ports + "\n";
        s += "filter    = " + f.filter + "\n";
        if (f.journal) {
            // journalflags=1 opens the users' journals too: journald files an ordinary uid's lines
            // there, and the backend's default (4) reads the system journal alone.
            s += std::string("backend   = systemd") + (f.user_journals ? "[journalflags=1]" : "") + "\n";
            if (!f.journalmatch.empty()) s += "journalmatch = " + f.journalmatch + "\n";
        } else {
            s += "logpath   = " + f.log + "\n";
        }
        s += "banaction = nftables-multiport\n";
        s += "maxretry  = " + std::to_string(f.maxretry) + "\n";
        s += "findtime  = " + f.findtime + "\n";
        s += "bantime   = " + f.bantime + "\n";
    }
    // Failed passwords ([[site.auth]]): the error log's lines. The jail names no site, so a site
    // that gains a password needs no new rendering; without a file at warn it waits, disabled.
    s += "\n[agensio-auth]\n";
    s += "# Failed passwords on [[site.auth]] paths, the error log's \"auth failed\" lines (never the challenge\n";
    s += "# every browser meets first): ten in ten minutes bans for an hour.\n";
    if (const std::string step = auth_log_step(in); !step.empty()) {
        s += "# Disabled: " + std::string(in.error_log.empty() ? "the error log goes to stderr ([log] error) and fail2ban reads files"
                                                                : "[log] level = \"error\" leaves out the auth failed lines, which are warn") + ". Needs:\n";
        s += "#   " + step + "\n";
        s += "enabled   = false\n";
    } else {
        s += "enabled   = true\n";
    }
    s += "port      = " + ports + "\n";
    s += "filter    = agensio-auth\n";
    if (!in.error_log.empty()) s += "logpath   = " + in.error_log + "\n";
    s += "banaction = nftables-multiport\n";
    s += "maxretry  = 10\n";
    s += "findtime  = 10m\n";
    s += "bantime   = 1h\n";
    s += "\n[agensio-denied]\n";
    s += "# Requests refused with 403 (an address outside a site's access rule, an application refusing): ten in ten\n";
    s += "# minutes bans for an hour.\n";
    s += "enabled   = true\n";
    s += "port      = " + ports + "\n";
    s += "filter    = agensio-denied\n";
    s += "logpath   = " + logpath + "\n";
    s += "banaction = nftables-multiport\n";
    s += "maxretry  = 10\n";
    s += "findtime  = 10m\n";
    s += "bantime   = 1h\n";
    s += "\n[agensio-scan]\n";
    s += "# Paths that do not exist: forty in five minutes bans for an hour.\n";
    s += "enabled   = true\n";
    s += "port      = " + ports + "\n";
    s += "filter    = agensio-scan\n";
    s += "logpath   = " + logpath + "\n";
    s += "banaction = nftables-multiport\n";
    s += "maxretry  = 40\n";
    s += "findtime  = 5m\n";
    s += "bantime   = 1h\n";
    s += "\n[agensio-post]\n";
    s += "# POST requests to any path, the catch-all for an unnamed login: 120 in two minutes bans for\n";
    s += "# half an hour. An API posted to that often: filter = agensio-post[ignore=\"/api/|/jsonrpc\\.php\"].\n";
    s += "enabled   = true\n";
    s += "port      = " + ports + "\n";
    s += "filter    = agensio-post\n";
    s += "logpath   = " + logpath + "\n";
    s += "banaction = nftables-multiport\n";
    s += "maxretry  = 120\n";
    s += "findtime  = 2m\n";
    s += "bantime   = 30m\n";
    return s;
}

std::string render_firewall_unit(const ProtectionInput& in) {
    std::string s;
    s += "[Unit]\n";
    s += "Description=agensio firewall limits (per-address limits on the web ports, table inet agensio)\n";
    s += "Documentation=https://github.com/YiannisBourkelis/agensio/blob/main/docs/configuration.md\n";
    s += "# After the distribution's firewall, whose own start may flush the ruleset; before the web server.\n";
    s += "After=network-pre.target nftables.service firewalld.service ufw.service\n";
    s += "Before=agensio.service\n";
    s += "ConditionPathExists=" + in.firewall_file + "\n";
    s += "\n[Service]\n";
    s += "Type=oneshot\n";
    s += "RemainAfterExit=yes\n";
    s += "ExecStart=/usr/sbin/nft -f " + in.firewall_file + "\n";
    s += "ExecReload=/usr/sbin/nft -f " + in.firewall_file + "\n";
    s += "ExecStop=/usr/sbin/nft delete table inet agensio\n";
    s += "\n[Install]\n";
    s += "WantedBy=multi-user.target\n";
    return s;
}

const std::vector<ProtectionFilter>& protection_filters() { return shipped_filters(); }

std::vector<std::string> firewall_trial_commands(const ProtectionInput& in) {
    return {"agensio ctl protection --nft > " + in.firewall_file, "nft -f " + in.firewall_file,
            "systemd-run --on-active=10min --unit " + std::string(kFirewallTrialUnit) + " /usr/sbin/nft delete table inet agensio"};
}

std::vector<std::string> firewall_keep_commands(const ProtectionInput& in) {
    std::vector<std::string> out{"systemctl stop " + std::string(kFirewallTrialUnit) + ".timer"};
    if (in.firewall_file != kDefaultFirewallFile) {
        out.push_back("agensio ctl protection --unit > /etc/systemd/system/" + std::string(kFirewallUnit));
        out.push_back("systemctl daemon-reload");
    }
    out.push_back("systemctl enable --now " + std::string(kFirewallUnit));
    return out;
}

std::vector<std::string> firewall_remove_commands() {
    return {"systemctl disable --now " + std::string(kFirewallUnit), "nft delete table inet agensio"};
}

std::string filter_install_command() {
    std::string filters = "install -m 644";
    for (const auto& f : shipped_filters()) filters += " " + shipped("fail2ban/filter.d/" + std::string(f.name) + ".conf");
    return filters + " /etc/fail2ban/filter.d/";
}

std::vector<std::string> installed_filter_paths() {
    std::vector<std::string> out;
    for (const auto& f : shipped_filters()) out.push_back("/etc/fail2ban/filter.d/" + std::string(f.name) + ".conf");
    return out;
}

std::vector<std::string> fail2ban_install_commands() {
    return {filter_install_command(), "agensio ctl protection --jail > " + std::string(kJailFile), "fail2ban-client reload"};
}

ProtectionProbe read_probe(const json::Value& reply, const ProtectionInput& in) {
    ProtectionProbe p;
    if (!reply.is_object() || !reply["ok"].boolean()) {
        p.why = reply["busy"].boolean() ? "the helper is busy with a task or an install; ask again when it finishes"
                : !reply.get("error").empty() ? std::string(reply.get("error"))
                                               : "the check runs through the provisioning helper (agensio started as root with [control] provision), which is not available";
        return p;
    }
    p.checked = true;
    // The firewall
    const json::Value& nft = reply["nft"];
    p.nft_available = nft["available"].boolean();
    p.nft_why = nft.get("why");
    if (p.nft_available && nft["ruleset"].is_object()) {
        const json::Value& items = nft["ruleset"]["nftables"];
        PortSets sets;
        for (const auto& o : items.items())
            if (o["set"].is_object() && (o["set"].get("type") == "inet_service")) {
                std::vector<unsigned> ports;
                ports_of_value(o["set"]["elem"], ports, {});
                sets[std::string(o["set"].get("name"))] = ports;
            }
        for (const auto& o : items.items()) {
            if (o["table"].is_object() && o["table"].get("family") == "inet" && o["table"].get("name") == "agensio") p.table = true;
            if (!o["rule"].is_object()) continue;
            const json::Value& r = o["rule"];
            const bool ours = r.get("family") == "inet" && r.get("table") == "agensio";
            std::vector<unsigned> tcp, udp;
            for (const auto& e : r["expr"].items()) {
                const json::Value& m = e["match"];
                if (!m.is_object() || !m["left"]["payload"].is_object() || m["left"]["payload"].get("field") != "dport") continue;
                const std::string_view proto = m["left"]["payload"].get("protocol");
                if (proto == "tcp") ports_of_value(m["right"], tcp, sets);
                else if (proto == "udp") ports_of_value(m["right"], udp, sets);
            }
            if (has_limit(r["expr"])) {
                for (unsigned x : tcp) add_unique(p.limited_tcp, x);
                for (unsigned x : udp) add_unique(p.limited_udp, x);
            }
            if (ours)
                for (const auto& e : r["expr"].items())
                    if (e["counter"].is_object()) p.rules.push_back({std::string(r.get("comment")), static_cast<std::uint64_t>(e["counter"]["packets"].num())});
        }
        std::sort(p.limited_tcp.begin(), p.limited_tcp.end());
        std::sort(p.limited_udp.begin(), p.limited_udp.end());
    }
    // The units
    const json::Value& units = reply["units"];
    p.units_why = reply.get("units_why");
    if (units.is_object()) {
        p.firewall_unit = unit_state_word(units[std::string(kFirewallUnit)]);
        p.trial_running = units[std::string(kFirewallTrialUnit) + ".timer"].get("ActiveState") == "active";
        for (const char* m : {"nftables.service", "firewalld.service", "ufw.service"})
            if (units[m].is_object() && units[m].get("LoadState") != "not-found") p.managers.emplace_back(m, std::string(units[m].get("ActiveState")));
        p.fail2ban_service = units["fail2ban.service"].get("ActiveState");
    }
    // fail2ban
    const json::Value& f2b = reply["fail2ban"];
    p.fail2ban_available = f2b["available"].boolean();
    p.fail2ban_why = f2b.get("why");
    for (const auto& j : f2b["jails"].items()) {
        ProtectionProbe::Jail jail;
        jail.name = j.get("name");
        const std::string status(j.get("status"));
        const std::string files = after_label(status, "File list");
        std::size_t i = 0;
        while (i < files.size()) {
            const std::size_t sp = files.find(' ', i);
            const std::string f = files.substr(i, sp == std::string::npos ? std::string::npos : sp - i);
            if (!f.empty()) {
                jail.files.push_back(f);
                if (std::find(in.logs.begin(), in.logs.end(), f) != in.logs.end()) jail.ours = true;
                if (!in.error_log.empty() && f == in.error_log) jail.error_log = true;
            }
            if (sp == std::string::npos) break;
            i = sp + 1;
        }
        jail.banned = number_after(status, "Currently banned");
        jail.total_banned = number_after(status, "Total banned");
        p.jails.push_back(std::move(jail));
    }
    // The journal, one answer per failure jail in journal mode (alpha.48 report).
    const json::Value& jr = reply["journal"];
    if (jr.is_object()) {
        p.journal_why = jr.get("why");
        for (const auto& j : jr["jails"].items())
            if (!j["seen"].is_null()) p.journal_seen.emplace_back(std::string(j.get("name")), j["seen"].boolean());
    }
    return p;
}

namespace {

// The states the findings and the report share.
struct Verdict {
    bool nft_missing = false;      // nft not installed
    bool covered = false;          // every public TCP port has a per-source limit, in some table
    std::vector<unsigned> uncovered_tcp, uncovered_udp;
    bool ours = false;             // the agensio table is loaded
    bool saved = false;            // the unit is enabled
    bool trial = false;
    bool saved_unknown = false;    // no systemctl
    bool f2b_missing = false;      // fail2ban not installed
    bool f2b_down = false;         // installed, not running
    bool f2b_ours = false;         // a jail reads one of our logs
    std::string jail_state;        // "same" | "stale" | "missing" (our jail file on disk against the rendering)
    std::string filters_state;     // "same" | "stale" | "missing" | "partial" (the installed filters against the shipped text)
    std::vector<std::string> stale_filters, missing_filters;
    std::uint64_t banned = 0, total_banned = 0;
    // Failed passwords: a jail reads the error log; the installed agensio-auth filter is the one
    // of alpha.57 and before, which counted every 401 of the access logs.
    bool auth_counted = false;
    bool auth_counts_challenges = false;
};

Verdict judge(const ProtectionInput& in, const ProtectionProbe& probe, const ProtectionFiles& files) {
    Verdict v;
    v.nft_missing = probe.checked && !probe.nft_available;
    v.ours = probe.table;
    for (unsigned port : in.tcp_ports)
        if (std::find(probe.limited_tcp.begin(), probe.limited_tcp.end(), port) == probe.limited_tcp.end()) v.uncovered_tcp.push_back(port);
    for (unsigned port : in.udp_ports)
        if (std::find(probe.limited_udp.begin(), probe.limited_udp.end(), port) == probe.limited_udp.end()) v.uncovered_udp.push_back(port);
    v.covered = probe.checked && probe.nft_available && v.uncovered_tcp.empty();
    v.trial = probe.trial_running;
    v.saved = probe.firewall_unit == "enabled";
    v.saved_unknown = probe.firewall_unit.empty();
    v.f2b_missing = probe.checked && !probe.fail2ban_available;
    v.f2b_down = probe.fail2ban_available && probe.fail2ban_service != "active" && probe.jails.empty();
    for (const auto& j : probe.jails) {
        if (j.ours) {
            v.f2b_ours = true;
            v.banned += j.banned;
            v.total_banned += j.total_banned;
        }
        if (j.error_log) v.auth_counted = true;
    }
    for (std::size_t i = 0; i < shipped_filters().size() && i < files.installed_filters.size(); ++i)
        if (std::string_view(shipped_filters()[i].name) == "agensio-auth" && files.installed_filters[i] && files.installed_filters[i]->find("(?:401|403)") != std::string::npos)
            v.auth_counts_challenges = true;
    if (!files.installed_jail) v.jail_state = "missing";
    else v.jail_state = *files.installed_jail == render_jail(in) ? "same" : "stale";
    for (std::size_t i = 0; i < shipped_filters().size(); ++i) {
        const std::optional<std::string>* got = i < files.installed_filters.size() ? &files.installed_filters[i] : nullptr;
        if (!got || !*got) v.missing_filters.emplace_back(shipped_filters()[i].name);
        else if (**got != shipped_filters()[i].text) v.stale_filters.emplace_back(shipped_filters()[i].name);
    }
    v.filters_state = !v.stale_filters.empty() ? "stale" : v.missing_filters.size() == shipped_filters().size() ? "missing" : v.missing_filters.empty() ? "same" : "partial";
    return v;
}

}  // namespace

json::Value protection_report(const ProtectionInput& in, const ProtectionProbe& probe, const ProtectionFiles& files) {
    const Verdict v = judge(in, probe, files);
    json::Value r = json::Value::object().set("ok", true).set("host_protection", in.host_protection).set("exposed", in.exposed);
    r.set("ports", json::Value::object().set("tcp", ports_json(in.tcp_ports)).set("udp", ports_json(in.udp_ports)));
    r.set("logs", strings_json(in.logs)).set("log_format", in.combined ? "combined" : "json").set("login_paths", strings_json(in.login_paths));
    if (!in.unlogged.empty()) r.set("unlogged_sites", strings_json(in.unlogged));
    json::Value ljs = json::Value::array();
    for (const auto& j : in.login_jails) {
        json::Value paths = json::Value::array();
        for (const auto& p : j.paths) paths.push(p.path);
        ljs.push(json::Value::object().set("name", j.name).set("log", j.log).set("sites", strings_json(j.sites)).set("paths", std::move(paths)));
    }
    r.set("login_jails", std::move(ljs));
    json::Value fjs = json::Value::array();
    for (const auto& f : in.failure_jails) {
        json::Value seen(nullptr);  // journal mode: whether the journal holds a line of the application (alpha.48 report)
        for (const auto& [name, s] : probe.journal_seen)
            if (name == f.name) seen = json::Value(static_cast<bool>(s));
        fjs.push(json::Value::object().set("name", f.name).set("app", f.app).set("sites", strings_json(f.sites)).set("filter", f.filter).set("log", f.log)
                     .set("enabled", f.enabled()).set("filter_installed", f.filter_installed).set("log_present", f.log_present).set("journal", f.journal)
                     .set("journalmatch", f.journal ? json::Value(f.journalmatch) : json::Value(nullptr)).set("journal_seen", std::move(seen))
                     .set("unidentified", strings_json(f.unidentified)).set("source", f.source).set("needs", strings_json(f.needs)));
    }
    r.set("failure_jails", std::move(fjs));
    // Failed passwords: the sites with one, the log agensio-auth reads, whether a jail reads it.
    json::Value auth = json::Value::object().set("sites", strings_json(in.auth_sites));
    auth.set("error_log", in.error_log.empty() ? json::Value(nullptr) : json::Value(in.error_log)).set("jail_enabled", auth_log_step(in).empty());
    if (const std::string step = auth_log_step(in); !step.empty()) auth.set("needs", step);
    auth.set("counted", v.auth_counted);
    r.set("auth", std::move(auth));
    // The firewall
    json::Value fw = json::Value::object();
    fw.set("table", std::string(kFirewallTable)).set("file", in.firewall_file).set("shipped", shipped("firewall/agensio.nft")).set("unit", std::string(kFirewallUnit));
    fw.set("ruleset", render_nft(in)).set("unit_text", render_firewall_unit(in));
    fw.set("trial", strings_json(firewall_trial_commands(in))).set("keep", strings_json(firewall_keep_commands(in))).set("remove", strings_json(firewall_remove_commands()));
    fw.set("file_present", files.firewall_file.has_value());
    if (files.firewall_file) fw.set("file_current", *files.firewall_file == render_nft(in));
    json::Value det = json::Value::object().set("checked", probe.checked);
    if (!probe.checked) det.set("why", probe.why);
    else {
        det.set("nft_available", probe.nft_available);
        if (!probe.nft_available) det.set("why", probe.nft_why);
        det.set("table_loaded", probe.table).set("limited_tcp_ports", ports_json(probe.limited_tcp)).set("limited_udp_ports", ports_json(probe.limited_udp));
        det.set("covered", v.covered).set("uncovered_tcp_ports", ports_json(v.uncovered_tcp)).set("uncovered_udp_ports", ports_json(v.uncovered_udp));
        json::Value rules = json::Value::array();
        for (const auto& rl : probe.rules) rules.push(json::Value::object().set("rule", rl.comment).set("packets", static_cast<double>(rl.packets)));
        det.set("rules", std::move(rules));
        det.set("unit_state", probe.firewall_unit.empty() ? json::Value(nullptr) : json::Value(probe.firewall_unit)).set("trial_running", probe.trial_running);
        if (!probe.units_why.empty()) det.set("units_why", probe.units_why);
        json::Value managers = json::Value::object();
        for (const auto& [name, state] : probe.managers) managers.set(name, state);
        det.set("firewall_managers", std::move(managers));
    }
    fw.set("detected", std::move(det));
    r.set("firewall", std::move(fw));
    // fail2ban
    json::Value fb = json::Value::object();
    fb.set("file", std::string(kJailFile)).set("shipped", shipped("fail2ban")).set("jail", render_jail(in));
    json::Value filters = json::Value::object();
    for (const auto& f : shipped_filters()) filters.set(f.name, f.text);
    fb.set("filters", std::move(filters)).set("install", strings_json(fail2ban_install_commands())).set("installed_jail", v.jail_state);
    fb.set("installed_filters", json::Value::object().set("state", v.filters_state).set("stale", strings_json(v.stale_filters)).set("missing", strings_json(v.missing_filters)));
    json::Value fdet = json::Value::object().set("checked", probe.checked);
    if (!probe.checked) fdet.set("why", probe.why);
    else {
        fdet.set("fail2ban_available", probe.fail2ban_available);
        if (!probe.fail2ban_available) fdet.set("why", probe.fail2ban_why);
        fdet.set("service", probe.fail2ban_service.empty() ? json::Value(nullptr) : json::Value(probe.fail2ban_service));
        json::Value jails = json::Value::array();
        for (const auto& j : probe.jails) {
            // A jail of someone else's lists its file count alone (2026-10-02 report: a Samba
            // jail read 1,976 per-client logs and the answer was 86 KB of their names).
            json::Value jv = json::Value::object().set("name", j.name).set("reads_agensio_logs", j.ours);
            if (j.ours) jv.set("files", strings_json(j.files));
            else jv.set("files_count", static_cast<double>(j.files.size()));
            jails.push(jv.set("banned", static_cast<double>(j.banned)).set("total_banned", static_cast<double>(j.total_banned)));
        }
        fdet.set("jails", std::move(jails)).set("covered", v.f2b_ours).set("banned", static_cast<double>(v.banned)).set("total_banned", static_cast<double>(v.total_banned));
    }
    fb.set("detected", std::move(fdet));
    r.set("fail2ban", std::move(fb));
    // Findings and a summary in words
    json::Value findings = json::Value::array();
    for (const auto& f : protection_findings(in, probe, files)) {
        json::Value x = json::Value::object().set("severity", f.severity).set("code", f.code).set("message", f.message);
        if (!f.fix.empty()) x.set("fix", f.fix);
        findings.push(std::move(x));
    }
    r.set("findings", std::move(findings));
    std::string summary;
    if (!in.exposed) summary = "every listener is on loopback: nothing is reachable from the network, so no host protection is needed";
    else if (in.host_protection == "off") summary = "[control] host_protection = \"off\": the firewall and fail2ban are not checked; the files above are rendered for this host anyway";
    else if (!probe.checked) summary = "could not check the host: " + probe.why + "; the files above are rendered for this host anyway";
    else {
        summary = v.covered ? (v.ours ? (v.trial ? "the firewall limits are loaded on trial (the timer removes them unless kept)"
                                                  : v.saved ? "the firewall limits are loaded and enabled at boot"
                                                            : v.saved_unknown ? "the firewall limits are loaded; whether they survive a reboot could not be told"
                                                                              : "the firewall limits are loaded but not enabled at boot")
                                       : "per-address limits on the web ports exist in another table (a panel's or the administrator's)")
                           : (v.nft_missing ? "nft is not installed: no per-address limit exists" : "no per-address limit on port(s) " + join_ports(v.uncovered_tcp));
        summary += "; ";
        summary += v.f2b_ours ? "fail2ban reads the access logs (" + std::to_string(v.banned) + " address(es) banned now, " + std::to_string(v.total_banned) + " since start" +
                                    (v.jail_state == "stale" ? "; the installed jail file is older than this rendering" : "") + ")"
                              : v.f2b_missing ? "fail2ban is not installed" : v.f2b_down ? "fail2ban is installed but not running" : "no fail2ban jail reads the access logs";
        if (v.f2b_ours && v.filters_state == "stale") summary += "; the installed filter(s) " + join(v.stale_filters, ", ") + " are older than the shipped text";
        if (v.f2b_ours && !in.auth_sites.empty())
            summary += v.auth_counted ? "; failed passwords are counted from the error log" : "; failed passwords are not counted (no jail reads the error log)";
    }
    r.set("summary", summary);
    return r;
}

std::vector<Finding> protection_findings(const ProtectionInput& in, const ProtectionProbe& probe, const ProtectionFiles& files) {
    std::vector<Finding> out;
    if (!in.exposed || in.host_protection == "off") return out;
    const std::string missing = in.host_protection == "external" ? "info" : "warn";
    const Verdict v = judge(in, probe, files);
    const std::string trial = ports_to_shell(firewall_trial_commands(in));
    const std::string keep = ports_to_shell(firewall_keep_commands(in));
    const std::string f2b = ports_to_shell(fail2ban_install_commands());
    const std::string ports = join_ports(in.tcp_ports);
    if (!probe.checked) {
        out.push_back(Finding{"info", "protection_unchecked", "", "whether the firewall limits the web ports (" + ports + ") per address and fail2ban reads the access logs could not be checked: " + probe.why,
                              "protection_show renders the ruleset and the jails for this host meanwhile; the check needs the root helper"});
        return out;
    }
    // The firewall
    if (v.nft_missing) {
        out.push_back(Finding{missing, "firewall_limits_missing", "", "nft is not installed (" + probe.nft_why + "): no per-address limit on the web ports (" + ports + ") can exist, so one client can hold every connection slot and the ceiling cannot tell it apart",
                              "install nftables, then as root the trial that undoes itself in ten minutes: " + trial + "; check the site and this session still answer, then keep it: " + keep + " (protection_show has the ruleset and every step)"});
    } else if (!v.covered) {
        out.push_back(Finding{missing, "firewall_limits_missing", "",
                              (v.ours ? "the agensio firewall table is loaded but covers no limit on port(s) " + join_ports(v.uncovered_tcp) + ": the listeners changed since it was rendered"
                                      : "no per-address limit on the web ports (" + join_ports(v.uncovered_tcp) + ") in the kernel's firewall: one client can hold every connection slot, and the ceiling refuses the rest without telling it apart") +
                                  (in.host_protection == "external" ? " ([control] host_protection = \"external\": managed outside agensio)" : ""),
                              (v.ours ? "render it again and reload it, as root: agensio ctl protection --nft > " + in.firewall_file + "; nft -f " + in.firewall_file
                                      : "as root, a trial that undoes itself in ten minutes: " + trial + "; check the site and this session still answer, then keep it: " + keep) +
                                  " (protection_show has the ruleset and every step)"});
    } else if (v.ours) {
        if (v.trial)
            out.push_back(Finding{"info", "firewall_limits_trial", "", "the firewall limits (table inet agensio) are loaded on trial: the timer " + std::string(kFirewallTrialUnit) + " removes them when it fires unless they are kept",
                                  "if the site and this session still answer: " + keep});
        else if (!v.saved)
            out.push_back(Finding{v.saved_unknown ? "info" : "warn", "firewall_limits_unsaved", "",
                                  v.saved_unknown ? "the firewall limits (table inet agensio) are loaded; whether they survive a reboot could not be told: " + (probe.units_why.empty() ? std::string("systemd gave no answer") : probe.units_why)
                                                  : "the firewall limits (table inet agensio) are loaded but " + std::string(kFirewallUnit) + " is " + probe.firewall_unit + ": a reboot drops them",
                                  "as root: " + keep});
        if (!v.uncovered_udp.empty())
            out.push_back(Finding{"info", "firewall_quic_unlimited", "", "QUIC on port(s) " + join_ports(v.uncovered_udp) + " has no per-address handshake limit in the loaded table: it was rendered before h3 was enabled",
                                  "render it again and reload it, as root: agensio ctl protection --nft > " + in.firewall_file + "; nft -f " + in.firewall_file});
    }
    // fail2ban
    if (!in.combined) {
        out.push_back(Finding{missing, "fail2ban_log_format", "", "the access logs are JSON ([log] format = \"json\"): the shipped fail2ban filters read the combined format, so no jail can count attempts",
                              "root sets format = \"combined\" under [log] and reloads (the combined format is nginx's, so fail2ban's own filters apply too)"});
    } else if (v.f2b_missing) {
        out.push_back(Finding{missing, "fail2ban_missing", "", "fail2ban is not installed (" + probe.fail2ban_why + "): nothing bans an address that tries passwords against " + (in.login_paths.empty() ? std::string("the sites") : join(in.login_paths, ", ")) + " or scans for files",
                              "install fail2ban, then as root: " + f2b + " (protection_show has the jails and the filters)"});
    } else if (!v.f2b_ours) {
        out.push_back(Finding{missing, "fail2ban_missing", "",
                              (v.f2b_down ? std::string("fail2ban is installed but not running") : "no fail2ban jail reads agensio's access logs (" + join(in.logs, ", ") + ")") +
                                  ": nothing bans an address that tries passwords against " + (in.login_paths.empty() ? std::string("the sites") : join(in.login_paths, ", ")) + " or scans for files" +
                                  (in.host_protection == "external" ? " ([control] host_protection = \"external\": managed outside agensio)" : ""),
                              "as root: " + f2b + (v.f2b_down ? "; systemctl enable --now fail2ban" : "") + " (protection_show has the jails and the filters)"});
    } else {
        // The jails are agensio's: the filter files and the jail file against what this build
        // ships and renders (alpha.44 report: an upgrade changed a filter and the old copy ran on).
        const std::string reinstall = v.filters_state == "stale" || v.filters_state == "partial" ? filter_install_command() + "; " : std::string();
        // All four absent is a host whose own jails read our logs (a panel's): nothing to say.
        if (v.filters_state == "stale" || v.filters_state == "partial")
            out.push_back(Finding{"warn", "fail2ban_filter_stale", "",
                                  (v.stale_filters.empty() ? std::string() : "the installed filter(s) " + join(v.stale_filters, ", ") + " in /etc/fail2ban/filter.d/ differ from the text this build ships") +
                                      (v.stale_filters.empty() || v.missing_filters.empty() ? "" : "; ") +
                                      (v.missing_filters.empty() ? std::string() : "the filter(s) " + join(v.missing_filters, ", ") + " are not installed") +
                                      ": the jails run with what an older build matched",
                                  "as root: " + filter_install_command() + "; " + (v.jail_state == "stale" ? "agensio ctl protection --jail > " + std::string(kJailFile) + "; " : std::string()) + "fail2ban-client reload"});
        if (v.jail_state == "stale")
            out.push_back(Finding{"info", "fail2ban_jail_stale", "", std::string(kJailFile) + " is older than this host's rendering (a site, a log or a login path was added since)",
                                  "as root: " + reinstall + "agensio ctl protection --jail > " + std::string(kJailFile) + "; fail2ban-client reload"});
    }
    // Failed passwords ([[site.auth]], 2026-10-08): counted from the error log by agensio-auth; the
    // filter of alpha.57 and before counted every 401 of the access logs, the challenge included.
    if (v.f2b_ours && !in.auth_sites.empty()) {
        const std::string sites = join(in.auth_sites, ", ");
        const std::string render = "as root: " + filter_install_command() + "; agensio ctl protection --jail > " + std::string(kJailFile) + "; fail2ban-client reload";
        if (v.auth_counts_challenges)
            out.push_back(Finding{"warn", "fail2ban_auth_challenges", "",
                                  "the installed agensio-auth filter is an older build's and counts every 401 in the access logs: the first request of every visitor to a password-protected path of " +
                                      sites + " is one (the challenge that makes the browser ask), so fail2ban bans the people who have the password",
                                  render});
        if (!v.auth_counted) {
            const std::string step = auth_log_step(in);
            out.push_back(Finding{missing, "fail2ban_auth_unseen", "",
                                  "failed passwords on " + sites + " are not counted: " +
                                      (in.error_log.empty() ? std::string("the error log goes to stderr, and fail2ban reads files")
                                       : !in.error_log_warn ? std::string("[log] level = \"error\" leaves out the auth failed lines, which are warn")
                                                            : "no fail2ban jail reads the error log " + in.error_log + ", where each is a line (the installed jail file is an older build's, or fail2ban was not reloaded after it was written)"),
                                  step.empty() ? render : "root sets " + step});
        }
    }
    // The failure tier a preset offers but the host does not have in place yet: the
    // application's plugin or module, root's filter copy, the log (informational: the attempt
    // tier counts meanwhile; agensio installs nothing, it says what to install).
    if (v.f2b_ours) {
        // On a journald-only host a jail whose filter fail2ban ships is enabled at once, since
        // the journal is always there, and said nothing while the application wrote nothing
        // into it (alpha.48 report: the Drupal note vanished with the Syslog module still off);
        // the helper asks the journal for one line matching the jail from the last 30 days, and
        // a jail it could not ask about claims nothing.
        auto journal_silent = [&](const FailureJail& f) {
            if (!f.enabled() || !f.journal) return false;
            for (const auto& [name, seen] : probe.journal_seen)
                if (name == f.name) return !seen;
            return false;
        };
        // A site the jail cannot read (journal mode, no account of its own) is named too, with
        // the account step as the fix (alpha.49 report).
        std::vector<std::string> apps;
        for (const auto& f : in.failure_jails)
            if ((!f.enabled() || journal_silent(f) || !f.unidentified.empty()) && std::find(apps.begin(), apps.end(), f.app) == apps.end()) apps.push_back(f.app);
        for (const auto& app : apps) {  // one finding per application, its jails named
            std::string disabled, why, silent, silent_why, unread, unread_sites, sites;
            std::vector<std::string> needs;
            bool full = false;  // the whole list of steps (a jail disabled), not only the application's
            for (const auto& f : in.failure_jails) {
                if (f.app != app) continue;
                if (sites.empty()) sites = join(f.sites, ", ");
                if (!f.enabled()) {
                    disabled += (disabled.empty() ? "" : ", ") + f.name;
                    if (!full) needs = f.needs, full = true;
                    for (const auto& reason : disabled_reasons(f))
                        if (why.find(reason) == std::string::npos) why += (why.empty() ? "" : "; ") + reason;
                    continue;
                }
                if (journal_silent(f)) {
                    silent += (silent.empty() ? "" : ", ") + f.name;
                    if (silent_why.empty()) silent_why = "it holds no line matching " + f.journalmatch + " from the last 30 days, so " + f.silent;
                    if (needs.empty() && !f.needs.empty()) needs = {f.needs.front()};  // the application's step; the filter and the jail are in place
                }
                if (!f.unidentified.empty()) {
                    unread += (unread.empty() ? "" : ", ") + f.name;
                    if (unread_sites.empty()) unread_sites = join(f.unidentified, ", ");
                    if (needs.empty())
                        for (const auto& n : f.needs)
                            if (n.starts_with("give ")) needs = {n};
                }
            }
            std::string what;
            if (!disabled.empty()) what = "the jail(s) " + disabled + " over the application's own log are rendered disabled: " + why;
            if (!silent.empty()) what += (what.empty() ? "" : "; ") + ("the jail(s) " + silent + " read the journal and " + silent_why);
            if (!unread.empty()) what += (what.empty() ? "" : "; ") + ("the jail(s) " + unread + " read no line of " + unread_sites + ", which no trusted journal field tells from any other process's");
            out.push_back(Finding{"info", "fail2ban_failures_unseen", "",
                                  sites + " (" + app + "): failed logins are counted only as attempts at the login paths; " + what, join(needs, "; ")});
        }
    }
    if (!in.unlogged.empty() && v.f2b_ours)
        out.push_back(Finding{"info", "fail2ban_blind", "", "site(s) without an access log: " + join(in.unlogged, ", ") + "; fail2ban cannot see their requests",
                              "give each an access_log (site file) or set [log] access, then render the jail again"});
    return out;
}

}  // namespace agensio::control
