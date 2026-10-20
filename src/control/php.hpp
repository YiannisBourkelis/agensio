// php_versions (docs/configuration.md 7b, docs/design-php-versions.md 8): the PHP versions installed,
// their facts, and the ones the system's repositories can install. Built by the provisioning helper
// as root (php-fpm's configuration test needs it), else by the server on a thread of its own: it runs
// programs, never on a worker.
#pragma once

#include <ctime>
#include <functional>
#include <string>
#include <vector>

#include "services/json.hpp"
#include "services/php_runtimes.hpp"

namespace agensio {
struct Config;
}

namespace agensio::control {

// What the answer is built from: the runtimes and their facts, the versions installable, and the
// pool files found in each runtime's pool directory (names without ".conf").
struct PhpInventory {
    std::vector<php::Runtime> runtimes;
    std::vector<php::Facts> facts;           // one per runtime
    std::vector<std::vector<std::string>> pools;  // one per runtime: the agensio pools its directory holds
    std::vector<std::string> installable;    // from the repositories; empty when unknown
    bool apt = false;                        // the repositories were asked (Debian, Ubuntu)
    bool as_root = false;                    // php-fpm's configuration test ran
    std::string distro;                      // /etc/os-release's ID ("debian", "ubuntu"), "" unknown
};

// Gathers it on this machine: discovery, each runtime's programs, apt-cache.
PhpInventory php_inventory(const Config& cfg, const php::Exec& exec, bool as_root);
json::Value php_versions_json(const Config& cfg, const PhpInventory& inv, std::time_t now);

}  // namespace agensio::control
