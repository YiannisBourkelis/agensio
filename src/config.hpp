// Configuration model and TOML loader.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace agensio {

struct TlsConfig {
    std::filesystem::path cert;
    std::filesystem::path key;
};

struct SiteConfig {
    std::vector<std::string> server_names;  // lower-case host names, "*" matches anything
    std::vector<std::string> listen;        // "host:port" strings, normalised
    std::string root;                       // absolute document root, no trailing slash
    std::vector<std::string> index{"index.html"};
    std::optional<TlsConfig> tls;
    bool is_default = false;
};

struct Config {
    // [server]
    unsigned workers = 0;                 // 0 = hardware threads
    std::uint32_t idle_timeout_s = 15;
    std::size_t max_header_size = 16 * 1024;
    std::string reuse_port = "auto";     // auto | on | off
    bool tcp_nodelay = true;
    bool sendfile = true;                // zero-copy streaming of uncached files on plain sockets
    std::string server_header = "agensio";

    // [cache]
    std::size_t cache_max_file_size = 4u * 1024 * 1024;
    std::size_t cache_max_size = 256u * 1024 * 1024;
    double cache_evict_fraction = 0.2;
    std::uint32_t cache_revalidate_s = 1;
    std::size_t stream_chunk_size = 64 * 1024;
    std::size_t cache_sendfile_min_size = 48 * 1024;  // cached files at least this large are served by sendfile on plain sockets (0 = never)

    std::vector<SiteConfig> sites;

    std::filesystem::path config_path;    // the file this came from
};

// Parses "4MB", "256k", "1G", "65536". Throws std::invalid_argument.
std::size_t parse_size(std::string_view text);

// Loads and validates a configuration file. Throws std::runtime_error with a
// human readable message on any problem.
Config load_config(const std::filesystem::path& path);

}  // namespace agensio
