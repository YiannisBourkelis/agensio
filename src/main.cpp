#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#ifndef _WIN32
#include <signal.h>
#include <sys/types.h>
#endif
#include <iostream>
#include <string>

#include "config.hpp"
#include "server.hpp"
#include "services/pools.hpp"
#include "upstream/fcgi_client.hpp"

namespace {

void usage() {
    std::cout << "agensio " AGENSIO_VERSION
                 " - a fast static web server built on Asio\n\n"
                 "usage: agensio [-c config.toml] [-t] [-v]\n"
                 "       agensio pools [-c config.toml] [--out DIR] [--dry-run]\n"
                 "       agensio reload [-c config.toml]\n"
                 "  -c, --config FILE   configuration file (default: ./agensio.toml, ./config/agensio.toml,\n"
                 "                      /etc/agensio/agensio.toml, /usr/local/etc/agensio/agensio.toml)\n"
                 "  -t, --test          check the configuration (and FastCGI upstreams) and exit\n"
                 "      --explain       with -t: print the effective configuration after presets\n"
                 "  -v, --version       print the version and exit\n"
                 "  reload              validate the configuration, then signal the running server\n"
                 "                      (server.pid_file, SIGHUP) to switch to it without a restart\n"
                 "  pools               write the php-fpm pool of every site with `user` into the pool\n"
                 "                      directory (server.pools or the distro's); exit 3 when files changed\n"
                 "                      (reload php-fpm), 0 when up to date; --dry-run only reports\n";
}

// Without -c: the working directory first (development), then the system locations, so
// `agensio`, `agensio -t` and `agensio reload` need no arguments on an installed machine.
std::filesystem::path default_config() {
    for (const char* candidate : {"agensio.toml", "config/agensio.toml", "/etc/agensio/agensio.toml",
                                  "/usr/local/etc/agensio/agensio.toml", "/opt/homebrew/etc/agensio/agensio.toml"})
        if (std::filesystem::is_regular_file(candidate)) return candidate;
    return "agensio.toml";
}

}  // namespace

// NOLINTNEXTLINE(bugprone-exception-escape): everything that can throw is inside the try blocks below.
int main(int argc, char** argv) {
    std::filesystem::path config_path;
    bool test_only = false;
    bool explain = false;
    bool pools = false;
    bool reload = false;
    bool dry_run = false;
    std::filesystem::path pools_out;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "-c" || a == "--config") && i + 1 < argc) config_path = argv[++i];
        else if (a == "-t" || a == "--test") test_only = true;
        else if (a == "--explain") explain = true;
        else if (a == "pools" && i == 1) pools = true;
        else if (a == "reload" && i == 1) reload = true;
        else if (pools && a == "--out" && i + 1 < argc) pools_out = argv[++i];
        else if (pools && a == "--dry-run") dry_run = true;
        else if (a == "-v" || a == "--version") {
            std::cout << "agensio " AGENSIO_VERSION "\n";
            return 0;
        } else if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else {
            std::cerr << "unknown argument: " << a << "\n";
            usage();
            return 2;
        }
    }
    if (config_path.empty()) config_path = default_config();

    agensio::Config cfg;
    try {
        cfg = agensio::load_config(config_path);
    } catch (const std::exception& e) {
        std::cerr << "configuration error: " << e.what() << "\n";
        return 1;
    }
    if (reload) {
#ifdef _WIN32
        std::cerr << "reload is not available on Windows\n";
        return 1;
#else
        std::ifstream pf(cfg.pid_file);
        long pid = 0;
        if (!(pf >> pid) || pid <= 0) {
            std::cerr << "error: no pid in " << cfg.pid_file << "; is agensio running with " << cfg.config_path.string()
                      << "? (server.pid_file names the file; a server that could not write it says so in its error log)\n";
            return 2;
        }
        if (::kill(static_cast<pid_t>(pid), SIGHUP) != 0) {
            std::cerr << "error: cannot signal pid " << pid << ": " << std::strerror(errno) << "\n";
            return 2;
        }
        std::cout << "configuration valid; reload signalled to pid " << pid << " (see the error log for the result)\n";
        return 0;
#endif
    }
    if (pools) {
        if (pools_out.empty()) {
            std::string version;
            for (const auto& s : cfg.sites)
                if (s.pool.generated && !s.pool.version.empty()) version = s.pool.version;
            pools_out = agensio::pools_dir(cfg, version);
            if (pools_out.empty()) {
                std::cerr << "error: no php-fpm pool directory found; set server.pools or pass --out DIR\n";
                return 1;
            }
        }
        const int rc = agensio::write_pools(cfg, pools_out, dry_run, std::cout);
        std::cout.flush();
        return rc;
    }
    // Hosting rules (sites with `user`): ownership and sharing, checked the same way before
    // a start and under -t so the message names the path and the mode to fix.
    const auto hosting_errors = agensio::check_hosting(cfg, agensio::system_facts());
    for (const auto& e : hosting_errors) std::cerr << "configuration error: " << e << "\n";
    if (!hosting_errors.empty() && !explain) return 1;
    if (test_only || explain) {
        if (explain) agensio::explain_config(cfg, std::cout);
        std::cout.flush();
        if (!hosting_errors.empty()) return 1;
        for (const auto& w : agensio::check_upstreams(cfg))
            std::cerr << "warning: " << w << "\n";
        std::cout << "configuration " << cfg.config_path.string() << " is OK (" << cfg.sites.size() << " site(s))\n";
        return 0;
    }

    try {
        agensio::Server server(std::move(cfg));
        std::cout << "agensio " AGENSIO_VERSION " starting with " << server.worker_count() << " worker(s)"
                  << (server.reuse_port_enabled() ? ", SO_REUSEPORT per worker" : ", shared acceptor") << "\n";
        for (const auto& l : server.listeners()) {
            std::cout << "  listening on " << (l.tls ? "https://" : "http://") << l.address << "  sites:";
            for (const auto& n : l.site_names)
                std::cout << ' ' << n;
            std::cout << "\n";
        }
        server.run();
        std::cout << "agensio stopped\n";
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
