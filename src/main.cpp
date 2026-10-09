#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#ifndef _WIN32
#include <signal.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#endif
#include <iostream>
#include <iterator>
#include <string>

#include "config.hpp"
#include "control/client.hpp"
#include "control/mcp.hpp"
#include "control/protection.hpp"
#include "control/reference.hpp"
#include "services/json.hpp"
#include "services/tasks.hpp"
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
                 "  passwd [--method yescrypt|bcrypt|sha512] [--cost N] USER\n"
                 "                      print a line for a [[site.auth]] user file (USER:hash), the\n"
                 "                      password asked twice at a terminal or read from stdin\n"
                 "  reload              validate the configuration, then signal the running server\n"
                 "                      (server.pid_file, SIGHUP) to switch to it without a restart\n"
                 "  ctl                 talk to the running server's control socket ([control]) as the\n"
                 "                      invoking user. Read: status | sites | site NAME | validate | health | protection |\n"
                 "                      logs [--site NAME] [--since 3h] [--level error|warn|info]\n"
                 "                           [--status 5xx|4xx|all] [--limit N]\n"
                 "                      Change (need --yes, take --reason TEXT): reload | logs-reopen |\n"
                 "                      site-create --domain D [--alias A]... [--https auto|none] [--cert F --key F]\n"
                 "                           [--user U|--no-user] [--group G] [--app static|php|laravel|drupal|wordpress|grav|proxy|rails|redmine|django|wagtail|node]\n"
                 "                           [--root DIR] [--upstream URL] [--project NAME] [--entry FILE] [--php-socket S] [--php-children N]\n"
                 "                           [--no-redirect] [--hsts] [--listen-plain A] [--listen-tls A]\n"
                 "                      site-update NAME (same flags) | site-disable NAME | site-enable NAME |\n"
                 "                      site-delete NAME [--files] | site-restore ENTRY | trash-delete ENTRY | trash | cert-renew NAME |\n"
                 "                      site-install NAME [--url https://... | --file UPLOAD | --version V] [--sha256 H]\n"
                 "                           [--path SUB] [--create-path] [--strip 0|1] [--dry-run]\n"
                 "                      site-copy NAME --from SUB --to SUB [--overwrite] [--dry-run]\n"
                 "                      site-task NAME TASK [--param KEY=VALUE]... [--dry-run] (site-tasks NAME lists them)\n"
                 "                      site-env-set NAME [--set KEY=VALUE]... [--unset KEY]... [--generate KEY]...\n"
                 "                           (site-env NAME [--reveal KEY]... shows names, lengths, fingerprints; admin)\n"
                 "                      site-auth-user-set NAME USER [--generate | --prompt] [--expires YYYY-MM-DD | --no-expiry]\n"
                 "                           [--note TEXT | --no-note] [--lock | --unlock] | site-auth-user-delete NAME USER\n"
                 "                           (site-auth-users NAME lists them; a managed site's passwords; admin)\n"
                 "                      Rails service (read): site-unit NAME [--raw] | site-service NAME |\n"
                 "                           site-service-logs NAME [--lines N] [--since 3h] [--raw] (admin) |\n"
                 "                           site-task-output NAME [--offset N] [--length N] [--raw] (admin)\n"
                 "                      site-update NAME --set KEY=VALUE ... (settings [NAME] lists the keys and ceilings)\n"
                 "                      site-update NAME --login-path /login ... (where the fail2ban jail counts attempts)\n"
                 "                      site-update NAME --restrict PATH=ADDR[,ADDR...] ... (only those addresses reach PATH)\n"
                 "                      site-update NAME --restrict-admin ADDR[,ADDR...] [--admin-login] [--admin-language L]...\n"
                 "                      site-update NAME --auth PATH | --auth-exact PATH | --auth-open PATH ... [--auth-realm TEXT]\n"
                 "                           [--auth-skip ADDR[,ADDR...]] [--auth-plain-http] | --no-auth (a password; the site's users first)\n"
                 "                           (WordPress, Drupal: only those addresses reach the admin; --no-restrict-admin)\n"
                 "                      site-update NAME --refuse PATTERN ... (paths answered 404, gitignore-style; --no-refuse)\n"
                 "                      access-check NAME PATH ADDRESS: what the site's access rules decide for that client\n"
                 "                      path-check NAME PATH: what the site does with PATH and why (refuse, location, file, script)\n"
                 "                      protection [--nft | --jail | --unit | --filter NAME]: the firewall ruleset and the\n"
                 "                           fail2ban jails rendered for this host, with what is in place (--nft and the\n"
                 "                           others print one file alone, for root to redirect into place)\n"
                 "                      Uploads: upload NAME [FILE] (stdin by default) | uploads | uploads-delete NAME\n"
                 "  mcp                 Model Context Protocol server on stdin/stdout for an AI agent host,\n"
                 "                      exposing the control commands as tools as the invoking user\n"
                 "                      (spawn it locally or over SSH: ssh admin@host agensio mcp)\n"
                 "  protection          render the host protection files from the configuration alone, no server\n"
                 "                      needed: --nft | --jail | --unit | --filter NAME print one file; --defaults renders\n"
                 "                      the packaged copies (ports 80 and 443) instead of this configuration's listeners\n"
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

#ifdef AGENSIO_HAS_AUTH
// A password for `user` from the terminal (asked twice, not echoed) or one line of stdin; false
// when the two differ. For `agensio passwd` and `agensio ctl site-auth-user-set --prompt`, which
// hash it here, so the password itself goes nowhere.
bool read_password(const std::string& user, std::string& password) {
    password.clear();
    if (::isatty(STDIN_FILENO)) {
        termios old_mode{};
        ::tcgetattr(STDIN_FILENO, &old_mode);
        termios quiet = old_mode;
        quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
        std::string again;
        std::cerr << "Password for " << user << ": ";
        std::getline(std::cin, password);
        std::cerr << "\nAgain: ";
        std::getline(std::cin, again);
        std::cerr << "\n";
        ::tcsetattr(STDIN_FILENO, TCSANOW, &old_mode);
        if (password != again) return false;
    } else {
        std::getline(std::cin, password);
    }
    if (!password.empty() && password.back() == '\r') password.pop_back();
    return true;
}
#endif

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
        else if (a == "passwd" && i == 1) {  // one line of a [[site.auth]] user file, no server needed
#ifdef AGENSIO_HAS_AUTH
            std::string user, method;
            unsigned long cost = 0;
            for (int j = i + 1; j < argc; ++j) {
                std::string b = argv[j];
                if (b == "--method" && j + 1 < argc) method = argv[++j];
                else if (b == "--cost" && j + 1 < argc) {
                    try {
                        cost = std::stoul(argv[++j]);
                    } catch (const std::exception&) {
                        std::cerr << "passwd: --cost takes a number\n";
                        return 2;
                    }
                } else if (user.empty() && !b.empty() && b[0] != '-') user = b;
                else {
                    std::cerr << "passwd: unexpected argument " << b << "\n";
                    return 2;
                }
            }
            bool name_ok = !user.empty() && user.size() <= 255;
            for (const unsigned char c : user) name_ok = name_ok && c > 0x20 && c != 0x7f && c != ':';
            if (!name_ok) {
                std::cerr << "usage: agensio passwd [--method yescrypt|bcrypt|sha512] [--cost N] USER\n"
                             "       (a user name of 1 to 255 characters, no ':' or space; the password from the terminal or stdin)\n";
                return 2;
            }
            std::string password;
            if (!read_password(user, password)) {
                std::cerr << "passwd: the two passwords differ\n";
                return 1;
            }
            std::string error;
            const std::string hash = agensio::auth::make_hash(password, method, cost, error);
            if (hash.empty()) {
                std::cerr << "passwd: " << error << "\n";
                return 2;
            }
            std::cout << user << ":" << hash << "\n";
            return 0;
#else
            std::cerr << "passwd: this agensio was built without authentication (libxcrypt and OpenSSL)\n";
            return 2;
#endif
        }
        else if (a == "protection" && i == 1) {  // the host protection files, rendered from the configuration alone
            std::string part, filter;
            bool defaults = false;
            for (int j = i + 1; j < argc; ++j) {
                std::string b = argv[j];
                if ((b == "-c" || b == "--config") && j + 1 < argc) config_path = argv[++j];
                else if (b == "--nft" || b == "--jail" || b == "--unit") part = b.substr(2);
                else if (b == "--filter" && j + 1 < argc) { part = "filter"; filter = argv[++j]; }
                else if (b == "--defaults") defaults = true;
                else { std::cerr << "protection: unexpected argument " << b << "\n"; return 2; }
            }
            agensio::control::ProtectionInput in;
            if (defaults) in = agensio::control::default_protection_input();
            else {
                try {
                    in = agensio::control::protection_input(agensio::load_config(config_path.empty() ? default_config() : config_path));
                } catch (const std::exception& e) {
                    std::cerr << "protection: " << e.what() << "\n";
                    return 1;
                }
            }
            if (part == "nft") std::cout << agensio::control::render_nft(in);
            else if (part == "jail") std::cout << agensio::control::render_jail(in);
            else if (part == "unit") std::cout << agensio::control::render_firewall_unit(in);
            else if (part == "filter") {
                for (const auto& f : agensio::control::protection_filters())
                    if (filter == f.name) { std::cout << f.text; return 0; }
                std::cerr << "protection: no filter " << filter << " (agensio-login, agensio-auth, agensio-scan, agensio-post, agensio-denied)\n";
                return 2;
            } else {
                std::cout << agensio::control::protection_report(in, agensio::control::read_probe(agensio::json::Value(nullptr), in), {}).dump() << "\n";
            }
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
                             "read:   status | sites | site NAME | validate | health | presets | uploads | settings [NAME] | reference | trash |\n"
                             "        protection [--nft | --jail | --unit | --filter NAME] (the firewall ruleset and the fail2ban jails rendered\n"
                             "                    for this host's listeners, logs and login paths, the root commands that try, keep and remove\n"
                             "                    them, and what the kernel and fail2ban do now; one file alone with --nft, --jail, --unit or\n"
                             "                    --filter agensio-login|agensio-auth|agensio-scan|agensio-post|agensio-denied, for root to redirect into place) |\n"
                             "        site-unit NAME [--raw] (the Puma unit of a Rails site, rendered for root: --raw prints the unit alone) |\n"
                             "        site-service NAME (whether the Rails site's agensio-app-USER.service runs, from systemctl show) |\n"
                             "        site-service-logs NAME [--lines N] [--since 30m|3h|2d] [--raw] (admin, audited: its journal;\n"
                             "                    --raw prints the lines alone) |\n"
                             "        site-task-output NAME [--offset N] [--length N] [--raw] (admin: the last task's whole output\n"
                             "                    in slices of up to 64 KB; a task's answer carries only a part) |\n"
                             "        site-tasks NAME | site-env NAME [--reveal KEY]... (admin: the site's environment as names, lengths\n"
                             "                    and fingerprints; a value only for each --reveal KEY, audited as a secret read) |\n"
                             "        logs [--site NAME] [--since 3h] [--level error|warn|info] [--status 5xx|4xx|all] [--limit N]\n"
                             "change (each needs --yes, takes --reason TEXT):\n"
                             "        reload | logs-reopen | site-disable NAME | site-enable NAME | cert-renew NAME\n"
                             "        site-delete NAME [--files]: the configuration alone (a .bak stays), or with --files everything of the\n"
                             "                    site (directory, account state, logs, environment file) into root's trash, <sites_root>/.trash,\n"
                             "                    for [control] trash_keep days; the account is kept\n"
                             "        site-restore ENTRY | trash-delete ENTRY | trash-expire (the trash's entries: `trash` lists them)\n"
                             "        site-create --domain D [--alias A]... [--https auto|none] [--cert F --key F] [--user U|--no-user]\n"
                             "                    [--group G] [--app NAME] [--root DIR] [--upstream URL] [--project NAME] [--entry FILE] [--php-socket S]\n"
                             "                    [--php-children N] [--php-version V] [--no-redirect] [--hsts] [--listen-plain A] [--listen-tls A]\n"
                             "                    [--encoded-slashes deny|allow] (allow: a %2F in the path is decoded and looked up, Apache's NoDecode,\n"
                             "                    for an application that encodes a slash inside a path segment; deny, the default, answers 404)\n"
                             "        site-update NAME (same options as site-create); --dry-run on either checks and shows the\n"
                             "                    file without writing, listing every problem at once\n"
                             "        --login-path PATH (site-create and site-update, repeatable): where the application posts\n"
                             "                    credentials, on top of the preset's known paths; the fail2ban jail counts attempts there;\n"
                             "                    given together they replace the site's list; --no-login-paths clears\n"
                             "        --private PATH, --entry-point /x.php, --cache PATH=SECONDS, --front-controller /x.php\n"
                             "                    (site-create and site-update, repeatable): an application's own rules, which only\n"
                             "                    make the site serve less; each replaces its own part (the private paths, the entry\n"
                             "                    points, the cached directories, the front controller) and keeps the site's other\n"
                             "                    rules; --no-rules clears them all\n"
                             "        --restrict PATH=ADDR[,ADDR...], --restrict-exact PATH=ADDR[,...] (site-update, repeatable): only\n"
                             "                    those clients reach PATH and everything below it (or PATH alone); ADDR is an address,\n"
                             "                    a range (203.0.113.0/24, 2001:db8:5::/64), a set root named in [addresses] (@office),\n"
                             "                    or any (reopens a path below a restricted one); \"/\" restricts the whole site; others\n"
                             "                    get 403. Given together they replace the site's restricted list and keep its other\n"
                             "                    rules; --no-restrict clears the list. Try first: access-check NAME PATH ADDRESS\n"
                             "        --restrict-admin ADDR[,ADDR...] (site-update, app = wordpress or drupal): only those clients\n"
                             "                    reach the preset's administration (WordPress /wp-admin, with admin-ajax.php and the login\n"
                             "                    page's files kept open; Drupal /admin, update.php, core/install.php, authorize.php,\n"
                             "                    rebuild.php); --admin-login adds the login page, --admin-language L (Drupal, repeatable)\n"
                             "                    the admin and login under /L/; --no-restrict-admin removes it. The admin is open to\n"
                             "                    everyone until this is set. `presets` lists each preset's admin paths\n"
                             "        --auth PATH, --auth-exact PATH, --auth-open PATH (site-update, repeatable): a password on PATH\n"
                             "                    and everything below it (or PATH alone), with the site's own users (site-auth-user-set\n"
                             "                    first: refused until the site has one); --auth-open frees a path below a protected\n"
                             "                    one. --auth-realm TEXT (the dialog's name), --auth-skip ADDR[,ADDR...] (let in without a\n"
                             "                    password) and --auth-plain-http (ask over plain HTTP too, readable on the network) apply\n"
                             "                    to each --auth of the command. Given together they replace the site's password rules;\n"
                             "                    --no-auth removes them. Check with path-check NAME PATH\n"
                             "        --refuse PATTERN (site-create and site-update, repeatable): paths the site answers 404\n"
                             "                    whichever location would serve them, gitignore-style: /vendor/ from the root,\n"
                             "                    composer.json or *.yaml in any directory, * within one segment\n"
                             "                    (/ext/*/Resources/Private/), ** any number of directories (/a/**/*.ts); given\n"
                             "                    together they replace the site's list and keep its other rules; --no-refuse clears it\n"
                             "        path-check NAME PATH: what the site does with a GET for PATH and why, as the server decides\n"
                             "                    it: refused (by which refuse pattern or refusal by name), the file served, the script run,\n"
                             "                    the application it goes to; every step on the way (try_files, index, redirects) (viewer)\n"
                             "        access-check NAME PATH ADDRESS: which access rule decides PATH for a client at ADDRESS,\n"
                             "                    allowed or refused (viewer); the path as the client sends it, the address as the\n"
                             "                    server sees it (the 403 page shows it)\n"
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
                             "        site-task NAME TASK [--param KEY=VALUE]... [--dry-run]: runs one named task of the site's\n"
                             "                    preset as the site's account in its directory (app = rails: gem_install_rails,\n"
                             "                    rails_new --param name=NAME, bundle_install, db_prepare, db_migrate, assets_precompile;\n"
                             "                    app = django | wagtail: venv_create, pip_install --param \"packages=wagtail gunicorn\"\n"
                             "                    (any packages; it prints a warning, and your --yes is the confirmation), startproject,\n"
                             "                    pip_install_requirements, django_settings, migrate, collectstatic,\n"
                             "                    createsuperuser --param username=U --param email=E, check_deploy;\n"
                             "                    app = node: npm_ci, npm_run --param script=NAME);\n"
                             "                    `site-tasks NAME` lists them with their parameters. Never a command line.\n"
                             "        site-env-set NAME [--set KEY=VALUE]... [--unset KEY]... [--generate KEY]...: the variables the\n"
                             "                    site's tasks and its application service get (app = rails or proxy), in a file\n"
                             "                    root's and 0600; --generate SECRET_KEY_BASE fills a missing name with a random secret\n"
                             "        site-auth-user-set NAME USER [--generate | --prompt] [--expires YYYY-MM-DD | --no-expiry]\n"
                             "                    [--note TEXT | --no-note] [--lock | --unlock]: a user of the managed site's password\n"
                             "                    file (<config dir>/auth/NAME.users, root's, 0640): --generate makes a password and\n"
                             "                    answers it once; --prompt asks for one here (twice, not echoed; or one line of stdin)\n"
                             "                    and sends only its hash; --lock refuses every login and keeps the password\n"
                             "        site-auth-user-delete NAME USER | site-auth-users NAME (names, methods, expiry, notes;\n"
                             "                    never a hash; admin)\n"
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
            std::string command, socket_path, site_name, query, upload_file, reveal, raw_part, raw_filter;
            std::string check_path, check_address;  // access-check NAME PATH ADDRESS, path-check NAME PATH
            agensio::json::Value restrict_rules = agensio::json::Value::array();  // --restrict / --restrict-exact
            bool restrict_given = false;  // --restrict, --restrict-exact or --no-restrict: rules.restricted is replaced
            agensio::json::Value admin_rule = agensio::json::Value::object();  // --restrict-admin, --admin-login, --admin-language
            bool admin_given = false;  // rules.admin is replaced (--no-restrict-admin: removed)
            agensio::json::Value refuse_list = agensio::json::Value::array();  // --refuse
            bool refuse_given = false;  // --refuse or --no-refuse: rules.refuse is replaced
            agensio::json::Value auth_rules = agensio::json::Value::array();  // --auth, --auth-exact, --auth-open
            agensio::json::Value auth_skip = agensio::json::Value::array();   // --auth-skip: every password rule of this command
            std::string auth_realm;                                           // --auth-realm: likewise
            bool auth_plain = false, auth_given = false;                      // --auth-plain-http; any auth flag or --no-auth: rules.auth replaced
            bool app_rules_given = false;  // --private, --entry-point, --cache, --front-controller: each replaces its own part
            bool no_rules = false;         // --no-rules: every rule of the site removed
            bool raw = false;
            agensio::json::Value body = agensio::json::Value::object();
            agensio::json::Value aliases = agensio::json::Value::array();
            bool yes = false;
            bool prompt = false;  // site-auth-user-set --prompt: the password asked and hashed here
            for (int j = i + 1; j < argc; ++j) {
                std::string b = argv[j];
                auto value = [&](std::string& into) { if (j + 1 < argc) into = argv[++j]; };
                auto field = [&](const char* key) { std::string v; value(v); body.set(key, v); };
                if (b == "--socket") value(socket_path);
                else if (b == "-c" || b == "--config") { std::string v; value(v); config_path = v; }
                else if (b == "--site" || b == "--since" || b == "--level" || b == "--status" || b == "--limit" || b == "--lines" || b == "--offset" ||
                         b == "--length") {
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
                else if (b == "--project") field("project");
                else if (b == "--entry") field("entry");
                else if (b == "--files") body.set("files", true);
                else if (b == "--private" || b == "--entry-point") {
                    std::string v; value(v);
                    app_rules_given = true;
                    const char* key = b == "--private" ? "private" : "entry_points";
                    agensio::json::Value rules = body["rules"].is_object() ? body["rules"] : agensio::json::Value::object();
                    agensio::json::Value list = rules[key].is_array() ? rules[key] : agensio::json::Value::array();
                    list.push(v);
                    rules.set(key, list);
                    body.set("rules", rules);
                } else if (b == "--cache") {
                    std::string v; value(v);
                    app_rules_given = true;
                    const std::size_t eq = v.find('=');
                    if (eq == std::string::npos || eq == 0) { std::cerr << "ctl: --cache needs PATH=SECONDS\n"; return 2; }
                    agensio::json::Value rules = body["rules"].is_object() ? body["rules"] : agensio::json::Value::object();
                    agensio::json::Value list = rules["cache"].is_array() ? rules["cache"] : agensio::json::Value::array();
                    list.push(agensio::json::Value::object().set("path", v.substr(0, eq)).set("max_age", static_cast<double>(std::atol(v.c_str() + eq + 1))));
                    rules.set("cache", list);
                    body.set("rules", rules);
                } else if (b == "--front-controller") {
                    std::string v; value(v);
                    app_rules_given = true;
                    agensio::json::Value rules = body["rules"].is_object() ? body["rules"] : agensio::json::Value::object();
                    rules.set("front_controller", v);
                    body.set("rules", rules);
                } else if (b == "--no-rules") {
                    no_rules = true;
                    body.set("rules", agensio::json::Value::object());
                }
                else if (b == "--restrict" || b == "--restrict-exact") {
                    std::string v; value(v);
                    const std::size_t eq = v.find('=');
                    if (eq == std::string::npos || eq == 0 || eq + 1 == v.size()) { std::cerr << "ctl: " << b << " needs PATH=ADDRESS[,ADDRESS...] (addresses, ranges, @sets or any)\n"; return 2; }
                    agensio::json::Value allow = agensio::json::Value::array();
                    for (std::size_t from = eq + 1; from <= v.size();) {
                        std::size_t comma = v.find(',', from);
                        if (comma == std::string::npos) comma = v.size();
                        if (comma > from) allow.push(v.substr(from, comma - from));
                        from = comma + 1;
                    }
                    agensio::json::Value rule = agensio::json::Value::object().set("path", v.substr(0, eq)).set("allow", allow);
                    if (b == "--restrict-exact") rule.set("match", "exact");
                    restrict_rules.push(rule);
                    restrict_given = true;
                } else if (b == "--no-restrict") restrict_given = true;
                else if (b == "--restrict-admin") {
                    std::string v; value(v);
                    agensio::json::Value allow = agensio::json::Value::array();
                    for (std::size_t from = 0; from <= v.size();) {
                        std::size_t comma = v.find(',', from);
                        if (comma == std::string::npos) comma = v.size();
                        if (comma > from) allow.push(v.substr(from, comma - from));
                        from = comma + 1;
                    }
                    admin_rule.set("allow", allow);
                    admin_given = true;
                } else if (b == "--admin-login") { admin_rule.set("login", true); admin_given = true; }
                else if (b == "--admin-language") {
                    std::string v; value(v);
                    agensio::json::Value langs = admin_rule["languages"].is_array() ? admin_rule["languages"] : agensio::json::Value::array();
                    langs.push(v);
                    admin_rule.set("languages", langs);
                    admin_given = true;
                } else if (b == "--no-restrict-admin") { admin_rule = agensio::json::Value::object(); admin_given = true; }
                else if (b == "--auth" || b == "--auth-exact" || b == "--auth-open") {
                    std::string v; value(v);
                    agensio::json::Value rule = agensio::json::Value::object().set("path", v);
                    if (b == "--auth-exact") rule.set("match", "exact");
                    if (b == "--auth-open") rule.set("open", true);
                    auth_rules.push(rule);
                    auth_given = true;
                } else if (b == "--auth-realm") { value(auth_realm); auth_given = true; }
                else if (b == "--auth-skip") {
                    std::string v; value(v);
                    for (std::size_t from = 0; from <= v.size();) {
                        std::size_t comma = v.find(',', from);
                        if (comma == std::string::npos) comma = v.size();
                        if (comma > from) auth_skip.push(v.substr(from, comma - from));
                        from = comma + 1;
                    }
                    auth_given = true;
                } else if (b == "--auth-plain-http") { auth_plain = true; auth_given = true; }
                else if (b == "--no-auth") auth_given = true;
                else if (b == "--refuse") {
                    std::string v; value(v);
                    refuse_list.push(v);
                    refuse_given = true;
                } else if (b == "--no-refuse") refuse_given = true;
                else if (b == "--login-path") {
                    std::string v; value(v);
                    agensio::json::Value list = body["login_paths"].is_array() ? body["login_paths"] : agensio::json::Value::array();
                    list.push(v);
                    body.set("login_paths", list);
                } else if (b == "--no-login-paths") body.set("login_paths", agensio::json::Value::array());
                else if (b == "--nft" || b == "--jail" || b == "--unit") { raw = true; raw_part = b.substr(2); }
                else if (b == "--filter") { raw = true; raw_part = "filter"; value(raw_filter); }
                else if (b == "--php-socket") field("php_socket");
                else if (b == "--php-children") { std::string v; value(v); body.set("php_children", std::atoi(v.c_str())); }
                else if (b == "--php-version") field("php_version");
                else if (b == "--no-redirect") body.set("redirect_http", false);
                else if (b == "--hsts") body.set("hsts", true);
                else if (b == "--encoded-slashes") field("encoded_slashes");
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
                else if (b == "--reveal") { std::string v; value(v); reveal += (reveal.empty() ? "" : ",") + v; }
                else if (b == "--raw") raw = true;
                else if (command == "site-auth-user-set" && b == "--generate") body.set("generate", true);  // a flag here, no name
                else if (b == "--prompt") prompt = true;
                else if (b == "--lock" || b == "--unlock") body.set("locked", b == "--lock");
                else if (b == "--expires") field("expires");
                else if (b == "--no-expiry") body.set("expires", "");
                else if (b == "--note") field("note");
                else if (b == "--no-note") body.set("note", "");
                else if (b == "--unset" || b == "--generate") {
                    std::string v; value(v);
                    const char* key = b == "--unset" ? "unset" : "generate";
                    agensio::json::Value list = body[key].is_array() ? body[key] : agensio::json::Value::array();
                    list.push(v);
                    body.set(key, list);
                }
                else if (b == "--param") {
                    std::string v; value(v);
                    const std::size_t eq = v.find('=');
                    if (eq == std::string::npos || eq == 0) { std::cerr << "ctl: --param needs KEY=VALUE\n"; return 2; }
                    agensio::json::Value pm = body["params"].is_object() ? body["params"] : agensio::json::Value::object();
                    pm.set(v.substr(0, eq), v.substr(eq + 1));
                    body.set("params", pm);
                }
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
                else if (command == "site-task" && body["task"].is_null()) body.set("task", b);
                else if ((command == "site-auth-user-set" || command == "site-auth-user-delete") && body["user"].is_null()) body.set("user", b);
                else if (site_name.empty() && (command == "cert-renew" || command == "upload" || command == "uploads-delete" || command == "settings" || command == "trash-delete")) site_name = b;
                else if (command == "access-check" && site_name.empty()) site_name = b;
                else if (command == "access-check" && check_path.empty()) check_path = b;
                else if (command == "access-check" && check_address.empty()) check_address = b;
                else if (command == "path-check" && site_name.empty()) site_name = b;
                else if (command == "path-check" && check_path.empty()) check_path = b;
                else if (command == "upload" && upload_file.empty()) upload_file = b;
                else { std::cerr << "ctl: unexpected argument " << b << "\n"; return 2; }
            }
            if (!aliases.items().empty()) body.set("aliases", aliases);
            if (command == "site-env-set" && body["settings"].is_object()) {  // --set KEY=VALUE names variables here, not settings
                agensio::json::Value nb = agensio::json::Value::object();
                for (const auto& m : body.members())
                    if (m.first != "settings") nb.set(m.first, m.second);
                nb.set("set", body["settings"]);
                body = nb;
            }
            std::string path, method = "GET";
            const bool mutation = command == "reload" || command == "logs-reopen" ||
                                  (command.starts_with("site-") && command != "site-tasks" && command != "site-env" && command != "site-unit" && command != "site-auth-users" &&
                                   command != "site-service" && command != "site-service-logs" && command != "site-task-output") ||
                                  command == "cert-renew" || command == "uploads-delete" || command == "trash-delete" || command == "trash-expire";
            const bool upload = command == "upload";
            if (command == "status" || command == "sites" || command == "health" || command == "presets" || command == "uploads" || command == "trash" || command == "protection")
                path = "/v1/" + command;
            else if (command == "site-restore" && !site_name.empty()) path = "/v1/trash/" + site_name + "/restore";
            else if (command == "trash-delete" && !site_name.empty()) path = "/v1/trash/" + site_name + "/delete";
            else if (command == "trash-expire") path = "/v1/trash/expire";
            else if (command == "settings") path = site_name.empty() ? "/v1/settings" : "/v1/sites/" + site_name + "/settings";
            else if (command == "reference") path = "/v1/config/reference";
            else if (command == "site" && !site_name.empty()) path = "/v1/sites/" + site_name;
            else if (command == "access-check") {
                if (site_name.empty() || check_path.empty() || check_address.empty()) {
                    std::cerr << "ctl: access-check NAME PATH ADDRESS (for example: access-check example.com /wp-admin/ 203.0.113.7)\n";
                    return 2;
                }
                auto enc = [](const std::string& t) {
                    std::string o;
                    for (const char c : t) {
                        if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_' || c == ':') o.push_back(c);
                        else { char h[4]; std::snprintf(h, sizeof h, "%%%02X", static_cast<unsigned char>(c)); o += h; }
                    }
                    return o;
                };
                path = "/v1/sites/" + site_name + "/access?path=" + enc(check_path) + "&address=" + enc(check_address);
            }
            else if (command == "path-check") {
                if (site_name.empty() || check_path.empty()) {
                    std::cerr << "ctl: path-check NAME PATH (for example: path-check example.com /vendor/autoload.php)\n";
                    return 2;
                }
                std::string q;
                for (const char c : check_path) {
                    if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_' || c == ':') q.push_back(c);
                    else { char h[4]; std::snprintf(h, sizeof h, "%%%02X", static_cast<unsigned char>(c)); q += h; }
                }
                path = "/v1/sites/" + site_name + "/path?path=" + q;
            }
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
            else if (command == "site-task" && !site_name.empty() && !body["task"].is_null()) path = "/v1/sites/" + site_name + "/task";
            else if (command == "site-tasks" && !site_name.empty()) path = "/v1/sites/" + site_name + "/tasks";
            else if (command == "site-unit" && !site_name.empty()) path = "/v1/sites/" + site_name + "/unit";
            else if (command == "site-service" && !site_name.empty()) path = "/v1/sites/" + site_name + "/service";
            else if (command == "site-service-logs" && !site_name.empty()) path = "/v1/sites/" + site_name + "/service/logs" + query;
            else if (command == "site-task-output" && !site_name.empty()) path = "/v1/sites/" + site_name + "/task-output" + query;
            else if ((command == "site-env" || command == "site-env-set") && !site_name.empty())
                path = "/v1/sites/" + site_name + "/env" + (command == "site-env" && !reveal.empty() ? "?reveal=" + reveal : std::string());
            else if (command == "site-auth-users" && !site_name.empty()) path = "/v1/sites/" + site_name + "/auth-users";
            else if ((command == "site-auth-user-set" || command == "site-auth-user-delete") && !site_name.empty() && !body["user"].is_null())
                path = "/v1/sites/" + site_name + "/auth-users" + (command == "site-auth-user-delete" ? "/delete" : "");
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
            // --prompt: the password is asked here and hashed here; only the hash goes to the server
            // (2026-10-09, design section 25), so no server, helper, log or agent ever holds it.
            if (prompt) {
                if (command != "site-auth-user-set") {
                    std::cerr << "ctl: --prompt belongs to site-auth-user-set\n";
                    return 2;
                }
                if (body["generate"].boolean()) {
                    std::cerr << "ctl: --prompt or --generate, not both\n";
                    return 2;
                }
#ifdef AGENSIO_HAS_AUTH
                std::string password, error;
                if (!read_password(std::string(body.get("user")), password)) {
                    std::cerr << "ctl: the two passwords differ\n";
                    return 1;
                }
                const std::string hash = agensio::auth::make_hash(password, "yescrypt", 0, error);
                std::fill(password.begin(), password.end(), '\0');
                if (hash.empty()) {
                    std::cerr << "ctl: " << error << "\n";
                    return 2;
                }
                body.set("hash", hash);
#else
                std::cerr << "ctl: --prompt needs a build with password support (libxcrypt and OpenSSL)\n";
                return 2;
#endif
            }
            // pip_install names what gets installed: the user reads the warning here, and the --yes
            // they typed is their confirmation (the control API refuses the task without one).
            if (command == "site-task" && agensio::tasks::needs_user_confirmation(body.get("task")) && !body["dry_run"].boolean()) {
                std::cerr << "WARNING: " << agensio::tasks::confirmation_warning(site_name, body["params"].get("packages"), "", "") << "\n";
                if (yes) body.set("user_confirmed", "terminal");
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
            // A new site's rules are what this command says.
            if (refuse_given && command == "site-create") {
                agensio::json::Value rules = body["rules"].is_object() ? body["rules"] : agensio::json::Value::object();
                if (!refuse_list.items().empty()) rules.set("refuse", refuse_list);
                body.set("rules", rules);
                refuse_given = false;
            }
            // Every rule flag of site-update changes its own part of the rules (--restrict the address
            // rules, --cache the cached directories, ...): the site's other parts are read and sent back
            // with it, since the server takes the rules object whole. Before alpha.61 --private,
            // --entry-point, --cache and --front-controller skipped this, so given alone they dropped
            // the site's address rules, passwords and refused paths (the cookbook's finding).
            if (auth_given) {  // the realm, skip_for and plain_http of this command go on each of its password rules
                bool any_closed = false;
                agensio::json::Value built = agensio::json::Value::array();
                for (const auto& given : auth_rules.items()) {
                    agensio::json::Value r = given;
                    if (!r["open"].boolean()) {
                        any_closed = true;
                        if (!auth_realm.empty()) r.set("realm", auth_realm);
                        if (!auth_skip.items().empty()) r.set("skip_for", auth_skip);
                        if (auth_plain) r.set("plain_http", true);
                    }
                    built.push(std::move(r));
                }
                auth_rules = std::move(built);
                if ((!auth_realm.empty() || !auth_skip.items().empty() || auth_plain) && !any_closed) {
                    std::cerr << "ctl: --auth-realm, --auth-skip and --auth-plain-http go with --auth PATH or --auth-exact PATH\n";
                    return 2;
                }
            }
            if (restrict_given || admin_given || refuse_given || auth_given || (app_rules_given && command == "site-update")) {
                if (command != "site-update" || site_name.empty()) {
                    std::cerr << "ctl: --restrict, --restrict-exact, --no-restrict, the --restrict-admin flags, the --auth flags and --refuse go with"
                                 " site-update NAME (--refuse with site-create too)\n";
                    return 2;
                }
                if (admin_given && !admin_rule.members().empty() && admin_rule["allow"].is_null()) {
                    std::cerr << "ctl: --admin-login and --admin-language go with --restrict-admin ADDR[,ADDR...]\n";
                    return 2;
                }
                agensio::ControlReply current;
                std::string err;
                if (!agensio::control_request(socket_path, "GET", "/v1/sites/" + site_name, std::string(), current, err)) {
                    std::cerr << err << "\n";
                    return 1;
                }
                agensio::json::Value site_json;
                std::string perr;
                if (current.status != 200 || !agensio::json::parse(current.body, site_json, perr)) {
                    std::cerr << "ctl: cannot read the site's current rules (" << current.status << "): " << current.body << "\n";
                    return 1;
                }
                agensio::json::Value merged = agensio::json::Value::object();
                const agensio::json::Value given = body["rules"].is_object() ? body["rules"] : agensio::json::Value::object();
                if (!no_rules)  // --no-rules with another flag: that flag's part alone remains
                    for (const auto& m : site_json["rules"].members())
                        if (!(restrict_given && m.first == "restricted") && !(admin_given && m.first == "admin") &&
                            !(refuse_given && m.first == "refuse") && !(auth_given && m.first == "auth") && given[m.first].is_null())
                            merged.set(m.first, m.second);
                for (const auto& m : given.members()) merged.set(m.first, m.second);  // the parts --private, --entry-point, --cache, --front-controller name
                if (!restrict_rules.items().empty()) merged.set("restricted", restrict_rules);
                if (!refuse_list.items().empty()) merged.set("refuse", refuse_list);
                if (admin_given && !admin_rule.members().empty()) merged.set("admin", admin_rule);
                if (auth_given && !auth_rules.items().empty()) merged.set("auth", auth_rules);
                body.set("rules", merged);
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
            if (raw && (command == "site-unit" || command == "site-service-logs" || command == "site-task-output") && reply.status == 200) {
                // The unit alone, for root to redirect into place; the journal's or the task's lines alone.
                agensio::json::Value u;
                std::string perr;
                if (agensio::json::parse(reply.body, u, perr)) {
                    std::cout << u.get(command == "site-unit" ? "unit" : "output");
                    return 0;
                }
            }
            if (raw && command == "protection" && reply.status == 200) {
                // One of the host protection files alone (--nft, --jail, --unit, --filter NAME), for root
                // to redirect into place.
                agensio::json::Value u;
                std::string perr;
                if (agensio::json::parse(reply.body, u, perr)) {
                    if (raw_part == "nft") std::cout << u["firewall"].get("ruleset");
                    else if (raw_part == "unit") std::cout << u["firewall"].get("unit_text");
                    else if (raw_part == "jail") std::cout << u["fail2ban"].get("jail");
                    else if (raw_part == "filter") {
                        if (u["fail2ban"]["filters"].get(raw_filter).empty()) {
                            std::cerr << "protection: no filter " << raw_filter << " (agensio-login, agensio-auth, agensio-scan, agensio-post, agensio-denied)\n";
                            return 2;
                        }
                        std::cout << u["fail2ban"]["filters"].get(raw_filter);
                    }
                    return 0;
                }
            }
            if ((command == "access-check" || command == "path-check") && reply.status == 200) {  // the verdict first, the details after
                agensio::json::Value u;
                std::string perr;
                if (agensio::json::parse(reply.body, u, perr)) std::cout << u.get("summary") << "\n";
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
        for (const auto& o : cfg.orphan_additions)
            std::cerr << "warning: " << o.file << " holds root additions for site " << o.site
                      << ", which is not in the configuration (disabled or deleted): ignored\n";
        for (const auto& n : agensio::access_notices(cfg))
            std::cerr << (n.severity == "warning" ? "warning: " : "note: ") << n.text << "\n";
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
