#include "control/reference.hpp"

#include <sstream>

namespace agensio::control {

const std::vector<KeyDef>& key_defs() {
    static const std::vector<KeyDef> defs = {
        {"[server]", "workers", "int", "0: one per hardware thread", "Worker threads; each owns an event loop and, on Linux, its own accepting socket (SO_REUSEPORT). Fewer workers than cores leave room for PHP and the database on the same machine; one worker already serves hundreds of thousands of requests a second on static files.", "restart", "file", "1"},
        {"[server]", "idle_timeout", "seconds", "15", "How long a keep-alive connection may sit idle before the server closes it.", "reload", "file", "1"},
        {"[server]", "max_requests_per_connection", "int", "1000", "Requests served on one connection before the server answers Connection: close (0 = unlimited).", "reload", "file", "1"},
        {"[server]", "max_header_size", "size", "16KB", "The request head (request line and headers) may not exceed this: 431 above it.", "reload", "file", "1"},
        {"[server]", "max_body_size", "size", "1MB", "The request-body limit every site takes unless it sets its own (413 above it); it also drives the generated php-fpm pools' upload sizes. Per site: the site's max_body_size, settable through the control plane.", "reload", "file", "7"},
        {"[server]", "body_timeout", "seconds", "60", "Longest wait between two reads of a request body before the request fails.", "reload", "file", "1"},
        {"[server]", "reuse_port", "enum: auto | on | off", "auto", "Whether every worker gets its own accepting socket (SO_REUSEPORT; Linux) or one worker accepts for all. auto picks the platform's best.", "restart", "file", "1"},
        {"[server]", "tcp_nodelay", "bool", "true", "TCP_NODELAY on client sockets (no Nagle delay on small writes).", "reload", "file", "1"},
        {"[server]", "sendfile", "bool", "true", "Zero-copy sendfile() for files on plain sockets; off makes the server copy through user space (useful only when a filesystem misbehaves with sendfile).", "restart", "file", "1"},
        {"[server]", "sendfile_max_chunk", "size", "1MB", "Bytes per sendfile() call, so one huge file cannot hold a worker.", "reload", "file", "1"},
        {"[server]", "server_header", "string", "agensio", "The Server response header; \"\" sends none.", "reload", "file", "1"},
        {"[server]", "trusted_proxies", "list of CIDRs", "[] (headers ignored)", "Proxies or load balancers in front of agensio whose X-Forwarded-For and X-Forwarded-Proto are believed: the client address in logs and REMOTE_ADDR, and the scheme for PHP (HTTPS, REQUEST_SCHEME), come from them.", "reload", "file", "10"},
        {"[server]", "user", "string", "\"\" (stay the starting account)", "Start as root, bind the ports and open the logs, then run as this account. Required for hosting with per-site users and for the provisioning helper.", "restart", "file", "11"},
        {"[server]", "group", "string", "the user's primary group", "The group the server runs as; per-site sockets and directories grant it access.", "restart", "file", "11"},
        {"[server]", "pools", "path", "detected per distro (/etc/php/<v>/fpm/pool.d, /etc/php-fpm.d)", "Where agensio pools writes the generated php-fpm pool files.", "reload", "file", "11"},
        {"[server]", "pools_run", "path", "/run/php (Linux)", "Where the generated pools listen (agensio-<user>.sock).", "reload", "file", "11"},
        {"[server]", "state_dir", "path", "/var/lib/agensio", "Per-user PHP state (<user>/tmp, <user>/sessions), the ACME storage, the uploads store.", "reload", "file", "11"},
        {"[server]", "strict_users", "bool", "false", "Every site must name a user; a site without one is a configuration error. For hosts where isolation is mandatory.", "reload", "file", "11"},
        {"[server]", "pid_file", "path", "/run/agensio.pid (Linux)", "Written at start; agensio reload signals it. \"\" disables it.", "restart", "file", "12b"},
        {"[server] acme", "email", "string", "(none)", "The ACME account contact; the CA sends expiry warnings there. Setting acme = { email } enables automatic certificates for sites with tls = \"auto\".", "reload", "file", "14"},
        {"[server] acme", "directory", "string", "https://acme-v02.api.letsencrypt.org/directory", "The ACME v2 directory URL: Let's Encrypt by default, any RFC 8555 CA.", "reload", "file", "14"},
        {"[server] acme", "ca", "path", "\"\" (system store)", "A PEM bundle to verify the CA's own TLS with (test beds, private CAs).", "reload", "file", "14"},
        {"[server] acme", "storage", "path", "<state_dir>/acme", "Where the account key and every site's key.pem and fullchain.pem live.", "reload", "file", "14"},
        {"top level", "include", "list of globs", "[]", "Further configuration files, relative to this one: include = [\"sites.d/*.toml\"] is what site-create needs.", "reload", "file", "15"},
        {"[cache]", "max_file_size", "size", "4MB", "Files up to this size are held in memory; larger ones keep an open descriptor and stream.", "restart", "file", "1"},
        {"[cache]", "max_size", "size", "256MB", "Total bytes of file content the cache may hold before it evicts.", "restart", "file", "1"},
        {"[cache]", "evict_fraction", "float", "0.2", "How much of the cache an eviction pass frees.", "reload", "file", "1"},
        {"[cache]", "revalidate_interval", "seconds", "1", "A cached file is stat()ed at most this often; a change on disk shows within this interval.", "reload", "file", "1"},
        {"[cache]", "stream_chunk_size", "size", "64KB", "Read size when a large file is streamed without sendfile (TLS).", "reload", "file", "1"},
        {"[cache]", "sendfile_min_size", "size", "48KB", "Cached files at least this large are sent with sendfile on plain sockets (0 = never); below it the memory copy is cheaper.", "reload", "file", "1"},
        {"[cache]", "max_open_files", "int", "1024", "How many streamed files may keep an open descriptor in the cache (0 = none).", "reload", "file", "1"},
        {"[log]", "access", "path or \"off\"", "logs/access.log next to the configuration", "The access log every site uses unless it sets access_log; \"off\" logs nothing.", "reload", "file", "8"},
        {"[log]", "format", "enum: combined | json", "combined", "Apache/nginx combined (fail2ban-compatible) or one JSON object per line with the upstream outcome.", "reload", "file", "8"},
        {"[log]", "error", "path or \"stderr\"", "stderr", "Where the error log goes.", "reload", "file", "8"},
        {"[log]", "level", "enum: error | warn | info", "warn", "Error-log verbosity; info logs reloads, certificate work, the helper's start.", "reload", "file", "8"},
        {"[control]", "socket", "path", "/run/agensio/control.sock", "The unix socket of the control API; its presence enables the control plane (agensio ctl, agensio mcp). Never a TCP port.", "restart", "file", "15"},
        {"[control]", "admins", "string (group)", "\"\"", "Members of this group are admins (create and change sites, install, copy). root and the server's user always are.", "reload", "file", "15"},
        {"[control]", "operators", "string (group)", "\"\"", "Members may reload, reopen logs, renew certificates, upload archives.", "reload", "file", "15"},
        {"[control]", "viewers", "string (group)", "\"\"", "Members may read: status, sites, logs, health, presets, settings, this reference.", "reload", "file", "15"},
        {"[control]", "audit", "path", "audit.log next to the error log", "One line per mutating command or refusal: time, uid, gid, role, command, outcome.", "reload", "file", "15"},
        {"[control]", "sites_root", "path", "/var/www", "Where site-create lays out sites and the helper may create directories; installs and copies stay below it.", "reload", "file", "15"},
        {"[control]", "provision", "bool", "true", "Fork the root provisioning helper at start (accounts, directories, logs, pools, restart, install, copy on request). false hands root work back as commands.", "restart", "file", "15"},
        {"[control]", "install", "bool", "true", "site-install may download archives from https URLs. false keeps only uploads.", "reload", "file", "15"},
        {"[control]", "install_private", "bool", "false", "Let site-install fetch from loopback, private and link-local addresses (internal mirrors, test beds).", "reload", "file", "15"},
        {"[control]", "install_ca", "path", "\"\" (system store)", "A PEM bundle site-install trusts instead of the system store.", "reload", "file", "15"},
        {"[control]", "upload_max", "size", "512MB", "The largest archive agensio ctl upload may store.", "reload", "file", "15"},
        {"[control]", "site_limits", "table", "{ max_body_size = \"512MB\", memory_limit = \"512M\", max_execution_time = 300, max_input_time = 300, children = 32, max_requests = 1000000 }", "The ceilings a site's settings may be raised to through the control plane; root moves them here.", "reload", "file", "15"},
        {"[[site]]", "server_name", "list of host names", "[\"*\"]", "The names this site answers; \"*\" makes it the listener's catch-all. A name no site lists answers 421.", "reload", "site-create (domain, aliases)", "1b"},
        {"[[site]]", "listen", "list of host:port", "(required)", "The addresses this site listens on; one site per name per address.", "reload (a new privileged port needs a restart)", "site-create (listen_plain, listen_tls)", "1"},
        {"[[site]]", "root", "path", "(required unless app = proxy)", "The document root, or for a preset the project directory (Laravel's public/, Drupal's web/ are served).", "reload", "site-create (root)", "1"},
        {"[[site]]", "app", "enum: static | php | laravel | drupal | wordpress | proxy", "static", "The preset: routing, which .php runs, what is refused; presets_list explains each.", "reload", "site-create (app)", "2"},
        {"[[site]]", "index", "list", "[\"index.html\"] (presets set their own)", "Files tried for a directory request.", "reload", "site file", "1"},
        {"[[site]]", "try_files", "list", "preset-dependent", "What to try for a path: $uri, $uri/, a fallback such as /index.php?$query_string, or =404.", "reload", "site file", "6"},
        {"[[site]]", "user", "string", "\"\"", "The account the site's PHP runs as, in its own pool; also who owns its files. What makes a shared host safe.", "reload (agensio pools / the helper writes the pool)", "site-create (user, no_user)", "11"},
        {"[[site]]", "group", "string", "the user's primary group", "The site's group.", "reload", "site-create (group)", "11"},
        {"[[site]]", "access_log", "path", "[log] access", "This site's own access log; a site with a user gets one, readable by it.", "reload", "site-create", "8"},
        {"[[site]]", "max_body_size", "size", "[server] max_body_size", "This site's request-body limit; drives the pool's upload_max_filesize and post_max_size.", "reload (and a php-fpm reload for the pool)", "settings", "7"},
        {"[[site]]", "tls", "\"auto\" or { cert, key }", "(plain HTTP)", "A certificate obtained and renewed automatically (needs [server] acme and port 80 reachable) or files you manage.", "reload", "site-create (https)", "14"},
        {"[[site]]", "redirect", "\"https\" or \"https://host[:port]\"", "(none)", "Answer every request with a 301 to https (same host) or to a fixed prefix; the site needs no root then.", "reload", "site-create (redirect_http)", "14"},
        {"[[site]]", "default", "bool", "false", "This site is its listener's catch-all (like server_name = [\"*\"]).", "reload", "site file", "1b"},
        {"[[site]]", "hidden_files", "bool", "false", "Serve dot-files (.env, .git) instead of answering 404.", "reload", "site file", "1"},
        {"[[site]]", "symlinks", "enum: allow | deny", "allow", "deny refuses a file whose real path leaves the root.", "reload", "site file", "1"},
        {"[[site]]", "php", "table", "(none)", "php = { socket = ... } names an existing php-fpm; with user and no socket the pool is generated and the keys below size it.", "reload", "site-create (php_socket, php_children, php_version) and settings", "7"},
        {"[[site]]", "proxy", "table", "(none)", "Defaults for the site's proxy locations (host, forwarded, headers, hide, redirects, tls, timeouts).", "reload", "site file", "12"},
        {"[[site]]", "upstream", "URL or list", "(none)", "app = proxy: where the application listens; a list balances round-robin with passive health.", "reload", "site-create (upstream)", "4b"},
        {"[[site]]", "location", "array of tables", "(preset-dependent)", "[[site.location]] blocks; hand-written ones win over a preset's.", "reload", "site file", "6"},
        {"php = {}", "socket", "unix:/path or host:port", "(generated with user)", "An existing php-fpm pool to use.", "reload", "site-create (php_socket)", "7"},
        {"php = {}", "children", "int", "8", "pm.max_children of the generated pool; also the FastCGI connection budget.", "reload + php-fpm reload", "settings (children) / site-create (php_children)", "7"},
        {"php = {}", "pm", "enum: ondemand | dynamic | static", "ondemand", "The pool's process manager: ondemand keeps nothing resident while idle, static keeps every child (benchmarks).", "reload + php-fpm reload", "settings", "7"},
        {"php = {}", "max_requests", "int", "500", "pm.max_requests (0 = never recycle).", "reload + php-fpm reload", "settings", "7"},
        {"php = {}", "memory_limit", "size", "256M", "PHP memory_limit of the pool.", "reload + php-fpm reload", "settings", "7"},
        {"php = {}", "max_execution_time", "seconds", "60", "PHP max_execution_time of the pool.", "reload + php-fpm reload", "settings", "7"},
        {"php = {}", "max_input_time", "seconds", "60", "PHP max_input_time of the pool (how long an upload may take to arrive).", "reload + php-fpm reload", "settings", "7"},
        {"php = {}", "version", "string", "newest installed", "PHP version whose pool directory agensio pools writes to.", "reload + php-fpm reload", "site-create (php_version)", "7"},
        {"php = {}", "open_basedir", "list of paths", "project, tmp, sessions", "Replaces the pool's open_basedir. Root only: it changes what the site may reach.", "reload + php-fpm reload", "site file", "7"},
        {"php = {}", "extra", "table", "{}", "php_admin_value lines. Root only: arbitrary ini keys include code execution.", "reload + php-fpm reload", "site file", "7"},
        {"php = {}", "read_timeout", "seconds", "60", "Waiting for php-fpm's answer: 504 beyond.", "reload", "site file", "7"},
        {"php = {}", "connect_timeout", "seconds", "5", "Connecting to php-fpm: 502 beyond.", "reload", "site file", "7"},
        {"php = {}", "send_timeout", "seconds", "60", "Sending the request to php-fpm.", "reload", "site file", "7"},
        {"php = {}", "max_connections", "int", "children / workers with a pool, else 32", "Connections to php-fpm per worker.", "reload", "site file", "7"},
        {"php = {}", "max_idle", "int", "max_connections", "Kept idle connections per worker (keep_conn).", "reload", "site file", "7"},
        {"php = {}", "idle_timeout", "seconds", "30", "Kept connection closed after this long idle (0 = never); lets an ondemand child exit.", "reload", "site file", "7"},
        {"php = {}", "queue_depth", "int", "256", "Requests waiting for a connection per worker; 503 beyond.", "reload", "site file", "7"},
        {"php = {}", "queue_wait", "seconds", "10", "Longest wait in that queue; 503 with Retry-After beyond.", "reload", "site file", "7"},
        {"php = {}", "priority_reserve", "int", "0", "Connections kept for priority = true locations.", "reload", "site file", "7"},
        {"php = {}", "keep_conn", "bool", "false (true with a generated pool)", "FastCGI keep-alive; php-fpm pins a child to every kept connection.", "reload", "site file", "7"},
        {"php = {}", "buffering", "bool", "true", "Buffer php-fpm's whole answer (memory, then a temp file) so the child is freed at once; false streams it.", "reload", "site file", "7"},
        {"php = {}", "buffer_max", "size", "1MB", "Buffered answer kept in memory up to this, spilled to a temp file above.", "reload", "site file", "7"},
        {"php = {}", "buffer_file_max", "size", "1GB", "Cap on that temp file; beyond it the rest streams.", "reload", "site file", "7"},
        {"php = {}", "request_buffering", "bool", "true", "Collect the request body (memory, then a temp file) before talking to php-fpm; false streams it.", "reload", "site file", "7"},
        {"php = {}", "request_buffer_max", "size", "256KB", "Request body kept in memory up to this, spilled above.", "reload", "site file", "7"},
        {"php = {}", "head_max", "size", "64KB", "Longest response head accepted from php-fpm.", "reload", "site file", "7"},
        {"php = {}", "path_info", "bool", "true", "Route /index.php/extra with PATH_INFO.", "reload", "site file", "7"},
        {"php = {}", "remote_root", "path", "(none)", "php-fpm in a container: the script path as the container sees it.", "reload", "site file", "9"},
        {"php = {}", "max_fails", "int", "1", "Failures before a member of an upstream list is skipped.", "reload", "site file", "12"},
        {"php = {}", "fail_timeout", "seconds", "10", "How long a failed member is skipped.", "reload", "site file", "12"},
        {"proxy = {}", "host", "string", "(passed through)", "The Host header sent to the origin; $host and other variables allowed.", "reload", "site file", "12"},
        {"proxy = {}", "forwarded", "enum: append | replace | off | rfc7239", "append", "How X-Forwarded-For/Proto/Host are built from the peer and trusted_proxies.", "reload", "site file", "12"},
        {"proxy = {}", "headers", "table", "{}", "Fields added to the forwarded request, with $ variables.", "reload", "site file", "12"},
        {"proxy = {}", "hide", "list", "[]", "Response fields removed before the client sees them.", "reload", "site file", "12"},
        {"proxy = {}", "redirects", "enum: rewrite | pass", "rewrite", "Rewrite a Location that points at the origin to this site.", "reload", "site file", "12"},
        {"proxy = {}", "tls", "table { verify, ca, server_name }", "verify = true", "TLS to the origin: verification, a CA bundle, the SNI name.", "reload", "site file", "12"},
        {"proxy = {}", "upgrade", "bool", "true", "Let the origin's 101 turn the connection into a tunnel (WebSockets).", "reload", "site file", "12"},
        {"proxy = {}", "tunnel_timeout", "seconds", "0 (none)", "Idle timeout of an upgraded tunnel.", "reload", "site file", "12"},
        {"proxy = {}", "read_timeout", "seconds", "60", "Waiting for the origin's answer: 504 beyond.", "reload", "site file", "12"},
        {"proxy = {}", "connect_timeout", "seconds", "5", "Connecting to the origin: 502 beyond.", "reload", "site file", "12"},
        {"proxy = {}", "send_timeout", "seconds", "60", "Sending to the origin.", "reload", "site file", "12"},
        {"proxy = {}", "max_connections", "int", "32", "Connections to the origin per worker.", "reload", "site file", "12"},
        {"proxy = {}", "max_idle", "int", "max_connections", "Kept idle connections per worker.", "reload", "site file", "12"},
        {"proxy = {}", "idle_timeout", "seconds", "30", "Kept connection closed after this long idle (0 = until the origin closes it).", "reload", "site file", "12"},
        {"proxy = {}", "queue_depth", "int", "256", "Requests waiting per worker; 503 beyond.", "reload", "site file", "12"},
        {"proxy = {}", "queue_wait", "seconds", "10", "Longest wait in the queue.", "reload", "site file", "12"},
        {"proxy = {}", "priority_reserve", "int", "0", "Connections kept for priority = true locations.", "reload", "site file", "12"},
        {"proxy = {}", "buffering", "bool", "true", "Buffer the origin's answer or stream it.", "reload", "site file", "12"},
        {"proxy = {}", "buffer_max", "size", "1MB", "Memory before the answer spills to a temp file.", "reload", "site file", "12"},
        {"proxy = {}", "buffer_file_max", "size", "1GB", "Cap on that temp file.", "reload", "site file", "12"},
        {"proxy = {}", "request_buffering", "bool", "true", "Collect the request body before forwarding.", "reload", "site file", "12"},
        {"proxy = {}", "request_buffer_max", "size", "256KB", "Memory before the body spills.", "reload", "site file", "12"},
        {"proxy = {}", "head_max", "size", "64KB", "Longest response head accepted.", "reload", "site file", "12"},
        {"proxy = {}", "max_fails", "int", "1", "Failures before a member is skipped.", "reload", "site file", "12"},
        {"proxy = {}", "fail_timeout", "seconds", "10", "How long a failed member is skipped.", "reload", "site file", "12"},
        {"[[site.location]]", "path", "string", "(required)", "The path this location matches.", "reload", "site file", "6"},
        {"[[site.location]]", "match", "enum: prefix | exact | suffix", "prefix", "How path matches: a prefix (longest wins), the exact path, or an ending such as .php.", "reload", "site file", "6"},
        {"[[site.location]]", "root", "path", "the site's root", "A different document root for this location.", "reload", "site file", "6"},
        {"[[site.location]]", "alias", "path", "(none)", "Serve this directory in place of the matched prefix.", "reload", "site file", "6"},
        {"[[site.location]]", "index", "list", "the site's", "Index files for this location.", "reload", "site file", "6"},
        {"[[site.location]]", "try_files", "list", "the site's", "What to try for a path here.", "reload", "site file", "6"},
        {"[[site.location]]", "hidden_files", "bool", "the site's", "Serve dot-files here.", "reload", "site file", "6"},
        {"[[site.location]]", "symlinks", "enum: allow | deny", "the site's", "Symlink policy here.", "reload", "site file", "6"},
        {"[[site.location]]", "handler", "enum: static | fastcgi | proxy | cgi | deny", "static (fastcgi with php, proxy with upstream)", "What answers here; deny answers 404 whatever exists.", "reload", "site file", "6"},
        {"[[site.location]]", "methods", "list", "what the handler implements", "Narrow the methods accepted (others get 405 with Allow).", "reload", "site file", "6"},
        {"[[site.location]]", "final", "bool", "false", "A prefix location that wins over suffix matches below it (nginx ^~): nothing PHP-like runs under it.", "reload", "site file", "6"},
        {"[[site.location]]", "deny_suffixes", "list", "[]", "Endings answered 404 here whatever exists (matched without regard to case or trailing dots).", "reload", "site file", "6"},
        {"[[site.location]]", "add_headers", "table", "{}", "Response headers added here (Cache-Control for assets, Strict-Transport-Security).", "reload", "site file", "6"},
        {"[[site.location]]", "priority", "bool", "false", "This location's upstream requests draw on priority_reserve.", "reload", "site file", "7"},
        {"[[site.location]]", "php", "table", "the site's", "php = { socket, ... }: FastCGI for this location.", "reload", "site file", "7"},
        {"[[site.location]]", "upstream", "URL or list", "(none)", "Proxy this location to an origin.", "reload", "site file", "12"},
        {"[[site.location]]", "proxy", "table", "the site's", "Proxy policy for this location.", "reload", "site file", "12"},
        {"[[site.location]]", "cgi", "table { interpreter, env }", "(none)", "Run scripts here as CGI processes (interpreter, extra environment).", "reload", "site file", "13"},
        {"tls = {}", "cert", "path", "(required with key)", "The certificate chain (PEM) a site presents; tls = \"auto\" obtains one instead.", "reload", "site-create (https = { cert, key })", "14"},
        {"tls = {}", "key", "path", "(required with cert)", "The private key (PEM) of that certificate; 0600, root's or the server's.", "reload", "site-create (https = { cert, key })", "14"},
        {"proxy tls = {}", "verify", "bool", "true", "Verify the origin's certificate (a self-signed origin needs false, or ca).", "reload", "site file", "12"},
        {"proxy tls = {}", "ca", "path", "\"\" (system store)", "A PEM bundle to verify the origin with.", "reload", "site file", "12"},
        {"proxy tls = {}", "server_name", "string", "the origin's host", "The SNI name and verification name for the origin.", "reload", "site file", "12"},
        {"cgi = {}", "interpreter", "path", "(the script itself)", "The program that runs the script (e.g. /usr/bin/python3).", "reload", "site file", "13"},
        {"cgi = {}", "env", "table", "{}", "Environment variables added for the script.", "reload", "site file", "13"},
    };
    return defs;
}

namespace {

std::string size_words(std::size_t bytes) {
    const std::size_t kb = 1024, mb = kb * 1024, gb = mb * 1024;
    if (bytes >= gb && bytes % gb == 0) return std::to_string(bytes / gb) + "GB";
    if (bytes >= mb && bytes % mb == 0) return std::to_string(bytes / mb) + "MB";
    if (bytes >= kb && bytes % kb == 0) return std::to_string(bytes / kb) + "KB";
    return std::to_string(bytes);
}

json::Value strings(const std::vector<std::string>& v) {
    json::Value a = json::Value::array();
    for (const auto& s : v) a.push(s);
    return a;
}

// The running value of a server-level key, or null for the rest (site keys are per site:
// sites_list and site_show carry those).
json::Value running_value(const Config& c, const std::string& table, const std::string& key) {
    using V = json::Value;
    if (table == "[server]") {
        if (key == "workers") return V(static_cast<double>(c.workers));
        if (key == "idle_timeout") return V(static_cast<double>(c.idle_timeout_s));
        if (key == "max_requests_per_connection") return V(static_cast<double>(c.max_requests_per_connection));
        if (key == "max_header_size") return V(size_words(c.max_header_size));
        if (key == "max_body_size") return V(size_words(c.max_body_size));
        if (key == "body_timeout") return V(static_cast<double>(c.body_timeout_s));
        if (key == "reuse_port") return V(c.reuse_port);
        if (key == "tcp_nodelay") return V(c.tcp_nodelay);
        if (key == "sendfile") return V(c.sendfile);
        if (key == "sendfile_max_chunk") return V(size_words(c.sendfile_max_chunk));
        if (key == "server_header") return V(c.server_header);
        if (key == "trusted_proxies") return V(static_cast<double>(c.trusted_proxies.size()));
        if (key == "user") return V(c.user);
        if (key == "group") return V(c.group);
        if (key == "pools") return V(c.pools_dir);
        if (key == "pools_run") return V(c.pools_run);
        if (key == "state_dir") return V(c.state_dir);
        if (key == "strict_users") return V(c.strict_users);
        if (key == "pid_file") return V(c.pid_file);
    } else if (table == "[server] acme") {
        if (!c.acme.enabled) return V("(acme not configured)");
        if (key == "email") return V(c.acme.email);
        if (key == "directory") return V(c.acme.directory);
        if (key == "ca") return V(c.acme.ca_file);
        if (key == "storage") return V(c.acme.storage);
    } else if (table == "top level") {
        if (key == "include") return strings(c.includes);
    } else if (table == "[cache]") {
        if (key == "max_file_size") return V(size_words(c.cache_max_file_size));
        if (key == "max_size") return V(size_words(c.cache_max_size));
        if (key == "evict_fraction") return V(c.cache_evict_fraction);
        if (key == "revalidate_interval") return V(static_cast<double>(c.cache_revalidate_s));
        if (key == "stream_chunk_size") return V(size_words(c.stream_chunk_size));
        if (key == "sendfile_min_size") return V(size_words(c.cache_sendfile_min_size));
        if (key == "max_open_files") return V(static_cast<double>(c.cache_max_open_files));
    } else if (table == "[log]") {
        if (key == "access") return V(c.log.access.empty() ? "off" : c.log.access);
        if (key == "format") return V(c.log.json ? "json" : "combined");
        if (key == "error") return V(c.log.error);
        if (key == "level") return V(c.log.level);
    } else if (table == "[control]") {
        if (!c.control.enabled) return V("(no [control] table)");
        if (key == "socket") return V(c.control.socket);
        if (key == "admins") return V(c.control.admins);
        if (key == "operators") return V(c.control.operators);
        if (key == "viewers") return V(c.control.viewers);
        if (key == "audit") return V(c.control.audit);
        if (key == "sites_root") return V(c.control.sites_root.empty() ? "/var/www" : c.control.sites_root);
        if (key == "provision") return V(c.control.provision);
        if (key == "install") return V(c.control.install);
        if (key == "install_private") return V(c.control.install_private);
        if (key == "install_ca") return V(c.control.install_ca);
        if (key == "upload_max") return V(size_words(c.control.upload_max));
        if (key == "site_limits") {
            const auto& l = c.control.site_limits;
            return V::object().set("max_body_size", size_words(l.max_body_size)).set("memory_limit", size_words(l.memory_limit))
                .set("max_execution_time", static_cast<double>(l.max_execution_time)).set("max_input_time", static_cast<double>(l.max_input_time))
                .set("children", static_cast<double>(l.children)).set("max_requests", static_cast<double>(l.max_requests));
        }
    }
    return V(nullptr);
}

}  // namespace

json::Value config_reference(const Config* running) {
    json::Value keys = json::Value::array();
    for (const auto& d : key_defs()) {
        json::Value v = json::Value::object().set("table", d.table).set("key", d.key).set("type", d.type).set("default", d.def)
                            .set("meaning", d.meaning).set("applies", d.applies).set("via", d.via).set("doc", std::string("docs/configuration.md section ") + d.doc);
        if (running) {
            const json::Value rv = running_value(*running, d.table, d.key);
            if (!rv.is_null()) v.set("running", rv).set("file", running->config_path.string());
        }
        keys.push(std::move(v));
    }
    return json::Value::object().set("keys", std::move(keys))
        .set("how_to_change", json::Value::object()
                                  .set("file", "root edits the main configuration file (running rows say which) and runs `agensio reload`, or `systemctl restart agensio` when applies says restart; the control plane never writes that file")
                                  .set("site file", "a site file under sites.d: a managed one (written by site-create) is rewritten by site-update, so hand edits need the managed marker removed; a hand-written one is edited by hand and reloaded")
                                  .set("site-create", "a field of site_create / site_update (the name in parentheses)")
                                  .set("settings", "site_update's settings object, within the ceilings [control] site_limits sets; site_settings_list has units, current values and ceilings"))
        .set("note", "Every key agensio reads is here, from the same table as docs/keys.md; a key that is not here does not exist.");
}

std::string reference_markdown() {
    std::ostringstream o;
    o << "# Configuration keys\n\n";
    o << "Generated from the table in `src/control/reference.cpp` by `agensio keys --markdown`; the\n"
         "integration suite fails when this file and the binary disagree. The MCP tool\n"
         "`config_reference` and `agensio ctl reference` serve the same table, with the running values.\n"
         "*applies*: whether a change takes effect on `agensio reload` or needs\n"
         "`systemctl restart agensio`. *via*: who changes it: **file** = root, in the main configuration\n"
         "file; **site file** = a site file under `sites.d` (a hand-written one, or a managed one after\n"
         "its marker is removed); **site-create** = a field of `site-create` / `site-update`;\n"
         "**settings** = `site-update --set`, within `[control] site_limits`. *doc* points at the\n"
         "section of `docs/configuration.md` that explains the key.\n\n";
    std::string table;
    for (const auto& d : key_defs()) {
        if (table != d.table) {
            table = d.table;
            o << "## `" << table << "`\n\n| key | type | default | meaning | applies | via | doc |\n|---|---|---|---|---|---|---|\n";
        }
        auto cell = [](std::string s) {
            std::string out;
            for (char c : s) { if (c == '|') out += "\\|"; else out.push_back(c); }
            return out;
        };
        o << "| `" << d.key << "` | " << cell(d.type) << " | " << cell(d.def) << " | " << cell(d.meaning) << " | " << d.applies << " | " << cell(d.via) << " | " << d.doc << " |\n";
        if (std::string_view(d.key) == "env" && std::string_view(d.table) == "cgi = {}") o << "\n";
    }
    return o.str();
}

}  // namespace agensio::control
