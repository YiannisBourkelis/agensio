#include <cstring>
#include <filesystem>
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
                 "  -c, --config FILE   configuration file (default: agensio.toml, then config/agensio.toml)\n"
                 "  -t, --test          check the configuration (and FastCGI upstreams) and exit\n"
                 "      --explain       with -t: print the effective configuration after presets\n"
                 "  -v, --version       print the version and exit\n"
                 "  pools               write the php-fpm pool of every site with `user` into the pool\n"
                 "                      directory (server.pools or the distro's); exit 3 when files changed\n"
                 "                      (reload php-fpm), 0 when up to date; --dry-run only reports\n";
}

std::filesystem::path default_config() {
    for (const char* candidate : {"agensio.toml", "config/agensio.toml"})
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
    bool dry_run = false;
    std::filesystem::path pools_out;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "-c" || a == "--config") && i + 1 < argc) config_path = argv[++i];
        else if (a == "-t" || a == "--test") test_only = true;
        else if (a == "--explain") explain = true;
        else if (a == "pools" && i == 1) pools = true;
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
    if (test_only || explain) {
        if (explain) agensio::explain_config(cfg, std::cout);
        std::cout.flush();
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
