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
#include <iterator>
#include <string>

#include "config.hpp"
#include "control/client.hpp"
#include "control/mcp.hpp"
#include "control/reference.hpp"
#include "services/json.hpp"
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
                 "       agensio keys [--markdown]      every configuration key with type, default, meaning, reload or restart,\n"
                 "                                      and who may change it (docs/keys.md is this output)\n"
                 "       agensio ctl <command> [--socket PATH] [-c config.toml]\n"
                 "       agensio mcp [--socket PATH] [-c config.toml]\n"
                 "  -c, --config FILE   configuration file (default: ./agensio.toml, ./config/agensio.toml,\n"
                 "                      /etc/agensio/agensio.toml, /usr/local/etc/agensio/agensio.toml)\n"
                 "  -t, --test          check the configuration (and FastCGI upstreams) and exit\n"
                 "      --explain       with -t: print the effective configuration after presets\n"
                 "  -v, --version       print the version and exit\n"
                 "  reload              validate the configuration, then signal the running server\n"
                 "                      (server.pid_file, SIGHUP) to switch to it without a restart\n"
                 "  ctl                 talk to the running server's control socket ([control]) as the\n"
                 "                      invoking user. Read: status | sites | site NAME | validate | health |\n"
                 "                      logs [--site NAME] [--since 3h] [--level error|warn|info]\n"
                 "                           [--status 5xx|4xx|all] [--limit N]\n"
                 "                      Change (need --yes, take --reason TEXT): reload | logs-reopen |\n"
                 "                      site-create --domain D [--alias A]... [--https auto|none] [--cert F --key F]\n"
                 "                           [--user U|--no-user] [--group G] [--app static|php|laravel|wordpress|proxy]\n"
                 "                           [--root DIR] [--upstream URL] [--php-socket S] [--php-children N]\n"
                 "                           [--no-redirect] [--hsts] [--listen-plain A] [--listen-tls A]\n"
                 "                      site-update NAME (same flags) | site-disable NAME | site-enable NAME |\n"
                 "                      site-delete NAME | cert-renew NAME |\n"
                 "                      site-install NAME [--url https://... | --file UPLOAD | --version V] [--sha256 H]\n"
                 "                           [--path SUB] [--create-path] [--strip 0|1] [--dry-run]\n"
                 "                      site-copy NAME --from SUB --to SUB [--overwrite] [--dry-run]\n"
                 "                      site-update NAME --set KEY=VALUE ... (settings [NAME] lists the keys and ceilings)\n"
                 "                      Uploads: upload NAME [FILE] (stdin by default) | uploads | uploads-delete NAME\n"
                 "  mcp                 Model Context Protocol server on stdin/stdout for an AI agent host,\n"
                 "                      exposing the control commands as tools as the invoking user\n"
                 "                      (spawn it locally or over SSH: ssh admin@host agensio mcp)\n"
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
        else if (a == "keys" && i == 1) {  // the configuration reference, no server needed
            const bool markdown = i + 1 < argc && std::string(argv[i + 1]) == "--markdown";
            if (markdown) std::cout << agensio::control::reference_markdown();
            else std::cout << agensio::control::config_reference(nullptr).dump() << "\n";
            return 0;
        }
        else if (a == "mcp" && i == 1) {
            std::string socket_path;
            for (int j = i + 1; j < argc; ++j) {
                std::string b = argv[j];
                if (b == "--socket" && j + 1 < argc) socket_path = argv[++j];
                else if ((b == "-c" || b == "--config") && j + 1 < argc) config_path = argv[++j];
                else { std::cerr << "mcp: unexpected argument " << b << "\n"; return 2; }
            }
            if (socket_path.empty()) {
                try {
                    agensio::Config cfg = agensio::load_config(config_path.empty() ? default_config() : config_path);
                    socket_path = cfg.control.enabled ? cfg.control.socket : agensio::default_control_socket();
                } catch (const std::exception&) {
                    socket_path = agensio::default_control_socket();
                }
            }
            return agensio::run_mcp(socket_path, std::cin, std::cout);
        }
        else if (a == "ctl" && i == 1) {
            auto ctl_usage = [] {
                std::cout << "usage: agensio ctl <command> [options] [--socket PATH] [-c config.toml]\n"
                             "read:   status | sites | site NAME | validate | health | presets | uploads | settings [NAME] | reference |\n"
                             "        logs [--site NAME] [--since 3h] [--level error|warn|info] [--status 5xx|4xx|all] [--limit N]\n"
                             "change (each needs --yes, takes --reason TEXT):\n"
                             "        reload | logs-reopen | site-disable NAME | site-enable NAME | site-delete NAME | cert-renew NAME\n"
                             "        site-create --domain D [--alias A]... [--https auto|none] [--cert F --key F] [--user U|--no-user]\n"
                             "                    [--group G] [--app NAME] [--root DIR] [--upstream URL] [--php-socket S]\n"
                             "                    [--php-children N] [--php-version V] [--no-redirect] [--hsts] [--listen-plain A] [--listen-tls A]\n"
                             "        site-update NAME (same options as site-create); --dry-run on either checks and shows the\n"
                             "                    file without writing, listing every problem at once\n"
                             "        --set KEY=VALUE (site-create and site-update, repeatable): a per-site limit, e.g.\n"
                             "                    --set max_body_size=200MB --set memory_limit=512M; `settings NAME` lists the keys,\n"
                             "                    their units, the current value and the ceiling [control] site_limits allows\n"
                             "        site-install NAME [--url https://host/app.tar.gz | --file UPLOAD | --version V] [--sha256 HEX]\n"
                             "                    [--path SUB] [--create-path] [--strip 0|1] [--dry-run]: puts an application's files\n"
                             "                    into the site's (empty) directory as the site's account; no source = the preset's\n"
                             "                    official archive. A plugin or theme: --path wp-content/plugins/NAME --create-path\n"
                             "                    makes the missing directories (as the site's account, below the site's directory)\n"
                             "        site-copy NAME --from SUB --to SUB [--overwrite] [--dry-run]: copies one of the site's files\n"
                             "                    to another path of the same site, as the site's account (drop-ins such as\n"
                             "                    wp-content/db.php from a plugin's db.copy); the destination's directory must exist\n"
                             "        uploads-delete NAME\n"
                             "upload: upload NAME [FILE]   stores FILE (or stdin) on the server for site-install --file NAME;\n"
                             "                    needs the operator role, no --yes\n"
                             "Answers are the control API's JSON; exit 1 on any refusal. Without --yes a change is\n"
                             "refused (428) and nothing happens.\n";
            };
            if (i + 1 >= argc) {
                ctl_usage();
                return 2;
            }
            for (int j = i + 1; j < argc; ++j)
                if (std::string(argv[j]) == "--help" || std::string(argv[j]) == "-h") {
                    ctl_usage();
                    return 0;
                }
            std::string command, socket_path, site_name, query, upload_file;
            agensio::json::Value body = agensio::json::Value::object();
            agensio::json::Value aliases = agensio::json::Value::array();
            bool yes = false;
            for (int j = i + 1; j < argc; ++j) {
                std::string b = argv[j];
                auto value = [&](std::string& into) { if (j + 1 < argc) into = argv[++j]; };
                auto field = [&](const char* key) { std::string v; value(v); body.set(key, v); };
                if (b == "--socket") value(socket_path);
                else if (b == "-c" || b == "--config") { std::string v; value(v); config_path = v; }
                else if (b == "--site" || b == "--since" || b == "--level" || b == "--status" || b == "--limit") {
                    std::string v;
                    value(v);
                    query += (query.empty() ? "?" : "&") + b.substr(2) + "=" + v;
                } else if (b == "--yes") yes = true;
                else if (b == "--reason") field("reason");
                else if (b == "--domain") field("domain");
                else if (b == "--alias") { std::string v; value(v); aliases.push(v); }
                else if (b == "--https") field("https");
                else if (b == "--cert" || b == "--key") {
                    std::string v; value(v);
                    agensio::json::Value h = body["https"].is_object() ? body["https"] : agensio::json::Value::object();
                    h.set(b.substr(2), v);
                    body.set("https", h);
                } else if (b == "--user") field("user");
                else if (b == "--no-user") body.set("no_user", true);
                else if (b == "--dry-run") body.set("dry_run", true);
                else if (b == "--group") field("group");
                else if (b == "--app") field("app");
                else if (b == "--root") field("root");
                else if (b == "--upstream") field("upstream");
                else if (b == "--php-socket") field("php_socket");
                else if (b == "--php-children") { std::string v; value(v); body.set("php_children", std::atoi(v.c_str())); }
                else if (b == "--php-version") field("php_version");
                else if (b == "--no-redirect") body.set("redirect_http", false);
                else if (b == "--hsts") body.set("hsts", true);
                else if (b == "--listen-plain") field("listen_plain");
                else if (b == "--listen-tls") field("listen_tls");
                else if (b == "--url") field("url");
                else if (b == "--file") field("file");
                else if (b == "--version") field("version");
                else if (b == "--sha256") field("sha256");
                else if (b == "--path") field("path");
                else if (b == "--strip") { std::string v; value(v); body.set("strip", std::atoi(v.c_str())); }
                else if (b == "--create-path") body.set("create_path", true);
                else if (b == "--from") field("from");
                else if (b == "--to") field("to");
                else if (b == "--overwrite") body.set("overwrite", true);
                else if (b == "--set") {
                    std::string v; value(v);
                    const std::size_t eq = v.find('=');
                    if (eq == std::string::npos || eq == 0) { std::cerr << "ctl: --set needs KEY=VALUE\n"; return 2; }
                    agensio::json::Value st = body["settings"].is_object() ? body["settings"] : agensio::json::Value::object();
                    st.set(v.substr(0, eq), v.substr(eq + 1));
                    body.set("settings", st);
                }
                else if (command.empty()) command = b;
                else if (site_name.empty() && command.starts_with("site") && command != "sites") site_name = b;
                else if (site_name.empty() && (command == "cert-renew" || command == "upload" || command == "uploads-delete" || command == "settings")) site_name = b;
                else if (command == "upload" && upload_file.empty()) upload_file = b;
                else { std::cerr << "ctl: unexpected argument " << b << "\n"; return 2; }
            }
            if (!aliases.items().empty()) body.set("aliases", aliases);
            std::string path, method = "GET";
            const bool mutation = command == "reload" || command == "logs-reopen" || command.starts_with("site-") || command == "cert-renew" ||
                                  command == "uploads-delete";
            const bool upload = command == "upload";
            if (command == "status" || command == "sites" || command == "health" || command == "presets" || command == "uploads") path = "/v1/" + command;
            else if (command == "settings") path = site_name.empty() ? "/v1/settings" : "/v1/sites/" + site_name + "/settings";
            else if (command == "reference") path = "/v1/config/reference";
            else if (command == "site" && !site_name.empty()) path = "/v1/sites/" + site_name;
            else if (command == "validate") path = "/v1/config/validate";
            else if (command == "logs") path = "/v1/logs" + query;
            else if (command == "reload") path = "/v1/reload";
            else if (command == "logs-reopen") path = "/v1/logs/reopen";
            else if (command == "site-create") path = "/v1/sites";
            else if (command == "site-update" && !site_name.empty()) path = "/v1/sites/" + site_name;
            else if ((command == "site-disable" || command == "site-enable" || command == "site-delete") && !site_name.empty())
                path = "/v1/sites/" + site_name + "/" + command.substr(5);
            else if (command == "cert-renew" && !site_name.empty()) path = "/v1/sites/" + site_name + "/renew";
            else if (command == "site-install" && !site_name.empty()) path = "/v1/sites/" + site_name + "/install";
            else if (command == "site-copy" && !site_name.empty()) path = "/v1/sites/" + site_name + "/copy";
            else if (command == "uploads-delete" && !site_name.empty()) path = "/v1/uploads/" + site_name + "/delete";
            else if (upload && !site_name.empty()) path = "/v1/uploads/" + site_name;
            else {
                std::cerr << "ctl: unknown or incomplete command '" << command << "' (see agensio --help)\n";
                return 2;
            }
            if (mutation) {
                method = "POST";
                if (yes) body.set("confirm", true);
            }
            std::string upload_bytes;
            if (upload) {
                method = "PUT";
                std::istream* in = &std::cin;
                std::ifstream f;
                if (!upload_file.empty()) {
                    f.open(upload_file, std::ios::binary);
                    if (!f) {
                        std::cerr << "upload: cannot read " << upload_file << "\n";
                        return 1;
                    }
                    in = &f;
                }
                upload_bytes.assign(std::istreambuf_iterator<char>(*in), std::istreambuf_iterator<char>());
                if (upload_bytes.empty()) {
                    std::cerr << "upload: nothing to send (give a file, or pipe the archive on stdin)\n";
                    return 1;
                }
            }
            if (socket_path.empty()) {
                try {
                    agensio::Config cfg = agensio::load_config(config_path.empty() ? default_config() : config_path);
                    socket_path = cfg.control.enabled ? cfg.control.socket : agensio::default_control_socket();
                } catch (const std::exception&) {
                    socket_path = agensio::default_control_socket();  // the file may be unreadable for this user
                }
            }
            agensio::ControlReply reply;
            std::string error;
            if (!agensio::control_request(socket_path, method, path, upload ? upload_bytes : mutation ? body.dump() : std::string(), reply, error)) {
                std::cerr << error << "\n";
                return 1;
            }
            if (reply.status == 428 && !yes) {
                std::cerr << "this command changes the server: add --yes (and --reason \"why\") to confirm\n";
                return 1;
            }
            std::cout << reply.body;
            return reply.status < 300 ? 0 : 1;
        }
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
        const bool cfg_h2 = cfg.h2, cfg_h2c = cfg.h2c;
        agensio::Server server(std::move(cfg));
        std::cout << "agensio " AGENSIO_VERSION " starting with " << server.worker_count() << " worker(s)"
                  << (server.reuse_port_enabled() ? ", SO_REUSEPORT per worker" : ", shared acceptor") << "\n";
        for (const auto& l : server.listeners()) {
            std::cout << "  listening on " << (l.tls ? "https://" : "http://") << l.address
                      << (l.tls ? (cfg_h2 ? " (h2, h1)" : " (h1)") : (cfg_h2c ? " (h2c, h1)" : " (h1)"))
                      << "  sites:";
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
