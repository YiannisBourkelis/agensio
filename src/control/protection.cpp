#include "control/protection.hpp"

#include <algorithm>
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

// A login path as a regex alternative: every character check_login_path admits is literal
// but '.', which is escaped (the path set is plain, so this is the whole grammar).
std::string regex_literal(const std::string& p) {
    std::string out;
    for (char c : p) {
        if (c == '.') out += '\\';
        out += c;
    }
    return out;
}

std::string shipped(std::string_view sub) { return std::string(kProtectionShippedDir) + "/" + std::string(sub); }

// The four jails share the shape; the text is one place so the shipped copy and the host's
// rendering never drift.
const char* kFilterLogin =
    "# fail2ban filter for agensio (docs/configuration.md 18): credentials posted to a login path.\n"
    "# The access log is in the combined format, the client address its first field (behind a\n"
    "# trusted proxy, the one X-Forwarded-For named). A form login is a POST; a failed and a\n"
    "# successful one look alike in an access log, so this counts attempts: no one types ten\n"
    "# passwords in ten minutes, every brute-force tool does. The jail passes this host's login\n"
    "# paths as `paths` (agensio ctl protection --jail renders them from the sites' presets and\n"
    "# their login_paths); the default below is every preset's.\n"
    "\n"
    "[INCLUDES]\n"
    "before = common.conf\n"
    "\n"
    "[Init]\n"
    "paths = /wp-login\\.php|/user/login|/login|/cp/auth/login|/admin|/admin/login/|/django-admin/login/\n"
    "\n"
    "[Definition]\n"
    "failregex = ^<HOST> \\S+ \\S+ \\[\\] \"POST (?:<paths>)(?:\\?\\S*)? HTTP/\\S+\" \\d{3} \n"
    "ignoreregex =\n"
    "datepattern = ^[^\\[]*\\[({DATE})\n";

const char* kFilterAuth =
    "# fail2ban filter for agensio (docs/configuration.md 18): requests refused with 401 or 403.\n"
    "# HTTP authentication, API tokens and the applications that answer a failed login with 403.\n"
    "\n"
    "[INCLUDES]\n"
    "before = common.conf\n"
    "\n"
    "[Definition]\n"
    "failregex = ^<HOST> \\S+ \\S+ \\[\\] \"\\S+ \\S+ HTTP/\\S+\" (?:401|403) \n"
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

const std::vector<ProtectionFilter> kFilters = {
    {"agensio-login", kFilterLogin}, {"agensio-auth", kFilterAuth}, {"agensio-scan", kFilterScan}, {"agensio-post", kFilterPost}};

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

ProtectionInput protection_input(const Config& cfg) {
    ProtectionInput in;
    in.firewall_file = (cfg.config_path.parent_path() / "firewall.nft").string();
    in.host_protection = cfg.control.host_protection;
    in.combined = !cfg.log.json;
    for (const auto& s : cfg.sites) {
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
        if (s.access_log.empty()) {
            if (!s.server_names.empty()) add_unique(in.unlogged, s.server_names.front());
        } else {
            add_unique(in.logs, s.access_log);
        }
        for (const auto& p : preset_login_paths(s.app)) add_unique(in.login_paths, p);
        for (const auto& p : s.login_paths) add_unique(in.login_paths, p);
    }
    std::sort(in.tcp_ports.begin(), in.tcp_ports.end());
    std::sort(in.udp_ports.begin(), in.udp_ports.end());
    std::sort(in.logs.begin(), in.logs.end());
    std::sort(in.login_paths.begin(), in.login_paths.end());
    return in;
}

ProtectionInput default_protection_input() {
    ProtectionInput in;
    in.tcp_ports = {80, 443};
    in.udp_ports = {443};
    in.logs = {"/var/log/agensio/access.log"};
    for (const auto& app : app_presets())
        for (const auto& p : preset_login_paths(app)) add_unique(in.login_paths, p);
    std::sort(in.login_paths.begin(), in.login_paths.end());
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

std::string render_jail(const ProtectionInput& in) {
    const std::string ports = port_list(in.tcp_ports.empty() ? std::vector<unsigned>{80, 443} : in.tcp_ports);
    const std::vector<std::string> logs = in.logs.empty() ? std::vector<std::string>{"/var/log/agensio/access.log"} : in.logs;
    std::string logpath;
    for (std::size_t i = 0; i < logs.size(); ++i) logpath += (i ? "\n            " : "") + logs[i];
    std::string paths;
    for (std::size_t i = 0; i < in.login_paths.size(); ++i) paths += (i ? "|" : "") + regex_literal(in.login_paths[i]);
    std::string s;
    s += "# agensio: fail2ban jails over its access logs (docs/configuration.md 18), rendered by\n";
    s += "# `agensio ctl protection --jail` for this host: its web ports, its access logs and the login\n";
    s += "# paths of its sites (each preset's, plus every site's login_paths). Install as\n";
    s += "# " + std::string(kJailFile) + " with the filters from " + shipped("fail2ban/filter.d") + ", then\n";
    s += "# `fail2ban-client reload`; render again when a site is added (health says when this file is stale).\n";
    s += "# The logs are in the combined format: the client address is the first field (behind a trusted\n";
    s += "# proxy, the one X-Forwarded-For named). Bans go through nftables into fail2ban's own table;\n";
    s += "# a host whose firewall is managed otherwise sets banaction in its jail.local.\n";
    if (!in.combined)
        s += "#\n# NOTE: this host's access logs are JSON ([log] format = \"json\"); these filters read the combined\n# format only, so nothing here matches until the format is combined.\n";
    s += "\n[agensio-login]\n";
    s += "# Credentials posted to a login path: ten in ten minutes bans for an hour.\n";
    if (in.login_paths.empty()) {
        s += "# No login path is known for this host's sites: name them with the sites' login_paths\n";
        s += "# (site_update, agensio ctl site-update NAME --login-path /login), then render this file again.\n";
        s += "enabled   = false\n";
    } else {
        s += "enabled   = true\n";
    }
    s += "port      = " + ports + "\n";
    s += "filter    = agensio-login" + (paths.empty() ? std::string() : "[paths=\"" + paths + "\"]") + "\n";
    s += "logpath   = " + logpath + "\n";
    s += "banaction = nftables-multiport\n";
    s += "maxretry  = 10\n";
    s += "findtime  = 10m\n";
    s += "bantime   = 1h\n";
    s += "\n[agensio-auth]\n";
    s += "# Requests refused with 401 or 403: ten in ten minutes bans for an hour.\n";
    s += "enabled   = true\n";
    s += "port      = " + ports + "\n";
    s += "filter    = agensio-auth\n";
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

const std::vector<ProtectionFilter>& protection_filters() { return kFilters; }

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

std::vector<std::string> fail2ban_install_commands() {
    std::string filters = "install -m 644";
    for (const auto& f : kFilters) filters += " " + shipped("fail2ban/filter.d/" + std::string(f.name) + ".conf");
    filters += " /etc/fail2ban/filter.d/";
    return {filters, "agensio ctl protection --jail > " + std::string(kJailFile), "fail2ban-client reload"};
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
            }
            if (sp == std::string::npos) break;
            i = sp + 1;
        }
        jail.banned = number_after(status, "Currently banned");
        jail.total_banned = number_after(status, "Total banned");
        p.jails.push_back(std::move(jail));
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
    std::uint64_t banned = 0, total_banned = 0;
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
    for (const auto& j : probe.jails)
        if (j.ours) {
            v.f2b_ours = true;
            v.banned += j.banned;
            v.total_banned += j.total_banned;
        }
    if (!files.installed_jail) v.jail_state = "missing";
    else v.jail_state = *files.installed_jail == render_jail(in) ? "same" : "stale";
    return v;
}

}  // namespace

json::Value protection_report(const ProtectionInput& in, const ProtectionProbe& probe, const ProtectionFiles& files) {
    const Verdict v = judge(in, probe, files);
    json::Value r = json::Value::object().set("ok", true).set("host_protection", in.host_protection).set("exposed", in.exposed);
    r.set("ports", json::Value::object().set("tcp", ports_json(in.tcp_ports)).set("udp", ports_json(in.udp_ports)));
    r.set("logs", strings_json(in.logs)).set("log_format", in.combined ? "combined" : "json").set("login_paths", strings_json(in.login_paths));
    if (!in.unlogged.empty()) r.set("unlogged_sites", strings_json(in.unlogged));
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
    for (const auto& f : kFilters) filters.set(f.name, f.text);
    fb.set("filters", std::move(filters)).set("install", strings_json(fail2ban_install_commands())).set("installed_jail", v.jail_state);
    json::Value fdet = json::Value::object().set("checked", probe.checked);
    if (!probe.checked) fdet.set("why", probe.why);
    else {
        fdet.set("fail2ban_available", probe.fail2ban_available);
        if (!probe.fail2ban_available) fdet.set("why", probe.fail2ban_why);
        fdet.set("service", probe.fail2ban_service.empty() ? json::Value(nullptr) : json::Value(probe.fail2ban_service));
        json::Value jails = json::Value::array();
        for (const auto& j : probe.jails)
            jails.push(json::Value::object().set("name", j.name).set("files", strings_json(j.files)).set("reads_agensio_logs", j.ours)
                           .set("banned", static_cast<double>(j.banned)).set("total_banned", static_cast<double>(j.total_banned)));
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
    } else if (v.jail_state == "stale") {
        out.push_back(Finding{"info", "fail2ban_jail_stale", "", std::string(kJailFile) + " is older than this host's rendering (a site, a log or a login path was added since)",
                              "as root: agensio ctl protection --jail > " + std::string(kJailFile) + "; fail2ban-client reload"});
    }
    if (!in.unlogged.empty() && v.f2b_ours)
        out.push_back(Finding{"info", "fail2ban_blind", "", "site(s) without an access log: " + join(in.unlogged, ", ") + "; fail2ban cannot see their requests",
                              "give each an access_log (site file) or set [log] access, then render the jail again"});
    return out;
}

}  // namespace agensio::control
