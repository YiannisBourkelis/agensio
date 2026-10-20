#include "control/php.hpp"

#include <algorithm>
#include <fstream>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "config.hpp"

namespace agensio::control {

namespace {

std::string os_release_id() {
    std::ifstream in("/etc/os-release");
    std::string line;
    while (std::getline(in, line))
        if (line.starts_with("ID=")) {
            std::string id = line.substr(3);
            id.erase(std::remove(id.begin(), id.end(), '"'), id.end());
            return id;
        }
    return {};
}

std::string first_binary(std::initializer_list<const char*> candidates) {
#ifndef _WIN32
    for (const char* c : candidates)
        if (::access(c, X_OK) == 0) return c;
#else
    (void)candidates;
#endif
    return {};
}

json::Value strings_json(const std::vector<std::string>& v) {
    json::Value a = json::Value::array();
    for (const auto& s : v) a.push(s);
    return a;
}

// Where another version comes from when the repositories do not offer it: the usual repository of
// the distribution, by its own instructions (never copied here, where they would go stale).
std::string repository_hint(const std::string& distro) {
    if (distro == "ubuntu") return "the ondrej/php PPA (as root: add-apt-repository ppa:ondrej/php && apt update)";
    if (distro == "debian") return "Ondřej Surý's repository, by its instructions at https://packages.sury.org/php/README.txt";
    return "the distribution's usual repository for PHP versions (Debian: packages.sury.org, Ubuntu: ppa:ondrej/php, RHEL: Remi's)";
}

}  // namespace

PhpInventory php_inventory(const Config& cfg, const php::Exec& exec, bool as_root) {
    PhpInventory inv;
    inv.as_root = as_root;
    inv.distro = os_release_id();
    const php::Fs fs = php::system_fs();
    inv.runtimes = php::discover(cfg, fs);
    const std::string systemctl = first_binary({"/usr/bin/systemctl", "/bin/systemctl"});
    for (const auto& r : inv.runtimes) {
        inv.facts.push_back(php::gather(r, exec, as_root, systemctl));
        std::vector<std::string> pools;
        for (const auto& name : fs.list(r.pools))
            if (name.starts_with("agensio-") && name.ends_with(".conf")) pools.push_back(name.substr(0, name.size() - 5));
        std::sort(pools.begin(), pools.end());
        inv.pools.push_back(std::move(pools));
    }
    if (const std::string apt = first_binary({"/usr/bin/apt-cache"}); !apt.empty()) {
        inv.apt = true;
        inv.installable = php::installable(exec, inv.runtimes, apt);
    }
    return inv;
}

json::Value php_versions_json(const Config& cfg, const PhpInventory& inv, std::time_t now) {
    json::Value runtimes = json::Value::array();
    for (std::size_t i = 0; i < inv.runtimes.size(); ++i) {
        const php::Runtime& r = inv.runtimes[i];
        const php::Facts& f = i < inv.facts.size() ? inv.facts[i] : php::Facts{};
        json::Value v = json::Value::object().set("version", r.version);
        if (!f.exact.empty()) v.set("exact", f.exact);
        v.set("fpm", r.fpm).set("conf", r.conf).set("pools_dir", r.pools);
        if (!r.unit.empty()) v.set("unit", r.unit);
        if (!r.cli.empty()) v.set("cli", r.cli);
        if (r.configured) v.set("configured", true);  // root's [php.runtimes], not discovered
        if (!f.unit_active.empty())
            v.set("service", json::Value::object().set("active", f.unit_active).set("enabled", f.unit_enabled.empty() ? json::Value() : json::Value(f.unit_enabled)));
        if (f.tested) {
            json::Value t = json::Value::object().set("ok", f.config_ok);
            if (!f.config_error.empty()) t.set("error", f.config_error);
            v.set("config_test", std::move(t));
            v.set("process_control_timeout", f.control_timeout.empty() ? json::Value() : json::Value(f.control_timeout));
            const bool cuts = f.control_timeout.empty() || f.control_timeout == "0" || f.control_timeout == "0s";
            v.set("reload_cuts_requests", cuts);  // without it a reload cuts every request in flight on its pools
        }
        v.set("opcache", json::Value::object().set("enabled", f.opcache).set("memory_mb", f.opcache_memory.empty() ? json::Value() : json::Value(f.opcache_memory))
                             .set("validate_permission", f.validate_permission));
        v.set("extensions", strings_json(f.modules));
        json::Value support = json::Value::object().set("status", php::support_status(r.version, now));
        if (const php::Release* rel = php::release(r.version)) {
            if (*rel->active_until) support.set("active_until", rel->active_until);
            support.set("security_until", rel->security_until);
        }
        v.set("support", std::move(support));
        // The pools its directory holds now, and the sites they belong to.
        const std::vector<std::string> pools = i < inv.pools.size() ? inv.pools[i] : std::vector<std::string>{};
        json::Value sites = json::Value::array();
        for (const auto& s : cfg.sites)
            if (s.pool.generated && std::find(pools.begin(), pools.end(), s.pool.name) != pools.end()) sites.push(s.server_names.front());
        v.set("pools", strings_json(pools)).set("sites", std::move(sites));
        if (!f.error.empty()) v.set("error", f.error);
        runtimes.push(std::move(v));
    }
    json::Value out = json::Value::object().set("runtimes", std::move(runtimes));
    // What else could be installed: from the repositories when they were asked, else the supported
    // versions of PHP's table with the repository that has them.
    json::Value can = json::Value::array();
    for (const auto& v : inv.installable)
        can.push(json::Value::object().set("version", v).set("support", php::support_status(v, now)).set("install", "as root: apt install php" + v + "-fpm"));
    out.set("installable", std::move(can));
    json::Value elsewhere = json::Value::array();
    for (const auto& rel : php::releases()) {
        const std::string v = rel.version;
        if (php::find(inv.runtimes, v) || std::find(inv.installable.begin(), inv.installable.end(), v) != inv.installable.end()) continue;
        if (php::support_status(v, now) == "eol") continue;
        elsewhere.push(v);
    }
    if (!elsewhere.items().empty())
        out.set("not_offered", json::Value::object().set("versions", std::move(elsewhere))
                                   .set("how", (inv.apt ? "not in the configured repositories: " : "") + repository_hint(inv.distro) +
                                                   ", then as root: apt install phpX.Y-fpm and the extensions the sites need (phpX.Y-mbstring, -xml, -gd ...)"));
    if (!inv.as_root)
        out.set("note", "php-fpm's configuration test (and process_control_timeout, read through it) needs root: run by the provisioning helper when "
                        "agensio starts as root with [control] provision, so not shown here");
    out.set("installing", "installing or removing a PHP version is root's; agensio gives the lines and never runs them");
    return out;
}

}  // namespace agensio::control
