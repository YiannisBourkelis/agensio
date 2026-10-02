// Host protection (2026-10-02, docs/configuration.md 18): what the server does not do itself,
// rendered for root and checked by health. Per-address connection and rate limits belong to
// the kernel's firewall, brute force on logins to fail2ban over the access logs; agensio
// renders both for this host (the ruleset in a table of its own, the jails over its logs
// with the login paths of its sites), gives root the commands that apply them for a trial
// and keep them, and reads back, through the helper, whether they are in place. Pure
// functions over the Config and the helper's answer; the unit tests hold the shipped files
// in packaging/ to the renderers.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "control/commands.hpp"
#include "services/json.hpp"

namespace agensio::control {

// What the files are rendered from.
struct ProtectionInput {
    std::vector<unsigned> tcp_ports;          // every listener's port the world can reach (plain and TLS), ascending
    std::vector<unsigned> udp_ports;          // the TLS ports that also speak h3 (QUIC)
    std::vector<std::string> logs;            // the access logs fail2ban reads, ascending
    std::vector<std::string> login_paths;     // the presets' and the sites' own, ascending, unique
    std::vector<std::string> unlogged;        // sites without an access log (fail2ban cannot see them)
    bool combined = true;                     // [log] format = "combined": the filters read that format only
    bool exposed = false;                     // at least one listener is not loopback
    std::string firewall_file;                // where this host keeps the ruleset: <config dir>/firewall.nft
    std::string host_protection = "check";    // [control] host_protection
};
ProtectionInput protection_input(const Config& cfg);
// The shipped files: ports 80 and 443 with QUIC on 443, /var/log/agensio/access.log, every
// preset's login paths, the packaged configuration directory.
ProtectionInput default_protection_input();

// The files. Every value rendered into them is a port number, a path check_login_path
// accepted, or a log path from the configuration; nothing a caller typed.
std::string render_nft(const ProtectionInput& in);
std::string render_jail(const ProtectionInput& in);
std::string render_firewall_unit(const ProtectionInput& in);
struct ProtectionFilter {
    const char* name;  // agensio-login, agensio-auth, agensio-scan, agensio-post
    const char* text;
};
const std::vector<ProtectionFilter>& protection_filters();

constexpr std::string_view kProtectionShippedDir = "/usr/share/agensio";
constexpr std::string_view kFirewallTable = "inet agensio";
constexpr std::string_view kFirewallUnit = "agensio-firewall.service";
constexpr std::string_view kFirewallTrialUnit = "agensio-firewall-trial";
constexpr std::string_view kDefaultFirewallFile = "/etc/agensio/firewall.nft";
constexpr std::string_view kJailFile = "/etc/fail2ban/jail.d/agensio.conf";
// The commands root runs, in order: a trial that undoes itself, keeping it, removing it, and
// the fail2ban install.
std::vector<std::string> firewall_trial_commands(const ProtectionInput& in);
std::vector<std::string> firewall_keep_commands(const ProtectionInput& in);
std::vector<std::string> firewall_remove_commands();
std::vector<std::string> fail2ban_install_commands();

// The helper's host_protection answer, read: {"ok", "nft": {"available", "why", "ruleset",
// "terse"}, "units": {unit: {systemctl properties}} | null, "units_why", "fail2ban":
// {"available", "why", "service", "status", "jails": [{"name", "status"}]}}.
struct ProtectionProbe {
    bool checked = false;      // something was learned; else `why`
    std::string why;
    // The firewall
    bool nft_available = false;
    std::string nft_why;
    bool table = false;                       // table inet agensio is loaded
    std::vector<unsigned> limited_tcp, limited_udp;  // ports a per-source limit or count rule covers, in any table
    struct Rule {
        std::string comment;
        std::uint64_t packets = 0;
    };
    std::vector<Rule> rules;                  // our table's counted rules
    std::string firewall_unit;                // "enabled", "disabled", "not-found", "" (unknown)
    bool trial_running = false;               // agensio-firewall-trial.timer is active
    std::string units_why;                    // systemctl unavailable: units unknown
    std::vector<std::pair<std::string, std::string>> managers;  // nftables, firewalld, ufw: ActiveState of each present
    // fail2ban
    bool fail2ban_available = false;
    std::string fail2ban_why;
    std::string fail2ban_service;             // ActiveState, "" unknown
    struct Jail {
        std::string name;
        std::vector<std::string> files;
        std::uint64_t banned = 0, total_banned = 0;
        bool ours = false;                    // reads one of this host's access logs
    };
    std::vector<Jail> jails;
};
ProtectionProbe read_probe(const json::Value& reply, const ProtectionInput& in);

// What the server read from disk itself (both files are world-readable): the ruleset kept
// at in.firewall_file and the installed jail file; nullopt when absent.
struct ProtectionFiles {
    std::optional<std::string> firewall_file;
    std::optional<std::string> installed_jail;
};

// The answer of GET /v1/protection (agensio ctl protection, MCP protection_show).
json::Value protection_report(const ProtectionInput& in, const ProtectionProbe& probe, const ProtectionFiles& files);
// Health's findings: nothing for a host without a public listener or with host_protection =
// "off"; with "external" the missing pieces are informational.
std::vector<Finding> protection_findings(const ProtectionInput& in, const ProtectionProbe& probe, const ProtectionFiles& files);

}  // namespace agensio::control
