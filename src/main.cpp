#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>

#include "config.hpp"
#include "server.hpp"

namespace {

void usage() {
    std::cout << "agensio " AGENSIO_VERSION
                 " - a fast static web server built on Asio\n\n"
                 "usage: agensio [-c config.toml] [-t] [-v]\n"
                 "  -c, --config FILE   configuration file (default: agensio.toml, then config/agensio.toml)\n"
                 "  -t, --test          check the configuration and exit\n"
                 "  -v, --version       print the version and exit\n";
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
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "-c" || a == "--config") && i + 1 < argc) config_path = argv[++i];
        else if (a == "-t" || a == "--test") test_only = true;
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
    if (test_only) {
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
