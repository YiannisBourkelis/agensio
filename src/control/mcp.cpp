#include "control/mcp.hpp"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <string>
#include <vector>

#include "config.hpp"
#include "control/client.hpp"
#include "control/roles.hpp"
#include "control/settings.hpp"
#include "services/json.hpp"
#include "services/tasks.hpp"

namespace agensio {

namespace {

constexpr const char* kProtocol = "2025-06-18";

struct Tool {
    const char* name;
    const char* title;
    const char* description;
    const char* method;  // GET or POST
    const char* path;    // "{name}" is replaced by the `name` argument
    bool read_only;
    bool destructive;
    Role needs;
    json::Value schema;  // inputSchema
};

json::Value prop(const char* type, const char* description) {
    return json::Value::object().set("type", type).set("description", description);
}

json::Value schema(std::vector<std::pair<std::string, json::Value>> props, std::vector<std::string> required) {
    json::Value p = json::Value::object();
    for (auto& [k, v] : props) p.set(k, std::move(v));
    json::Value req = json::Value::array();
    for (const auto& r : required) req.push(r);
    return json::Value::object().set("type", "object").set("properties", std::move(p)).set("required", std::move(req));
}

// The `app` values come from the preset table, so a new preset is a tool option at once.
json::Value app_enum() {
    json::Value values = json::Value::array();
    std::string text = "What runs there. A preset sets routing and PHP rules; call presets_list for what each value does:";
    for (const auto& a : app_presets()) {
        values.push(a);
        text += " " + a;
    }
    return json::Value::object().set("type", "string").set("enum", std::move(values)).set("description", text + ".");
}

// The per-site settings object, generated from the settings table so the schema can never
// advertise a key the server refuses or hide one it accepts.
json::Value settings_schema() {
    json::Value props = json::Value::object();
    for (const auto& d : control::setting_defs()) {
        json::Value p = json::Value::object();
        const std::string_view type = d.type;
        std::string text = d.meaning;
        if (type == "size") {
            p.set("type", json::Value::array().push("string").push("integer"));
            text += " A size: \"200MB\", \"512M\", \"1GB\" or bytes.";
        } else if (type == "enum") {
            json::Value opts = json::Value::array();
            for (const char* o : d.options) opts.push(o);
            p.set("type", "string").set("enum", opts);
        } else {
            p.set("type", "integer").set("minimum", 0);
            text += std::string(" In ") + d.unit + ".";
        }
        text += std::string(" Changing it costs: ") + d.applies + ".";
        if (*d.derives) text += std::string(" Derives: ") + d.derives + ".";
        if (d.pool) text += " Needs a PHP site with its own user (a generated pool; a proxy or static site has none).";
        props.set(d.key, p.set("description", text));
    }
    return json::Value::object().set("type", "object").set("properties", props).set("additionalProperties", false)
        .set("description", "Per-site limits, each within the ceiling [control] site_limits sets; site_settings_list shows units, defaults, current values and ceilings. A value above the ceiling is refused naming it. No other PHP ini key can be set here: extra, open_basedir and the like stay in the configuration file, root's.");
}

json::Value name_arg() { return prop("string", "The site's host name (any of its server_name values)."); }

// site_task's task and params, generated from the task table: a new row is an option at once,
// and no parameter the server would refuse is advertised.
json::Value task_enum() {
    json::Value values = json::Value::array();
    std::string text = "The task, by name (site_tasks_list shows the site's):";
    for (const auto& n : tasks::all_names()) {
        values.push(n);
        text += " " + n;
    }
    return json::Value::object().set("type", "string").set("enum", std::move(values)).set("description", text + ".");
}

json::Value task_params_schema() {
    json::Value props = json::Value::object();
    for (const tasks::Param* p : tasks::all_params()) {
        // One name may mean different things per task (version: a Rails 8 release for
        // gem_install_rails, any release for the pip rows): the pattern is advertised only when
        // every row agrees, else each row's is named in the text and the server checks it.
        std::string used, per_task;
        bool one_pattern = true;
        for (const auto& r : tasks::rows())
            for (const auto& q : r.params)
                if (std::string_view(q.name) == p->name) {
                    used += (used.empty() ? "" : ", ") + std::string(r.name);
                    per_task += (per_task.empty() ? "" : "; ") + std::string(r.name) + ": " + q.description + " (" + q.pattern + ")";
                    one_pattern = one_pattern && std::string_view(q.pattern) == p->pattern;
                }
        json::Value prop = json::Value::object().set("type", "string");
        if (one_pattern) prop.set("pattern", p->pattern).set("description", std::string(p->description) + " (" + used + ")");
        else prop.set("description", "Per task: " + per_task);
        props.set(p->name, std::move(prop));
    }
    return json::Value::object().set("type", "object").set("properties", std::move(props)).set("additionalProperties", false)
        .set("description", "The task's parameters, each a string matching its pattern; a task takes only its own (site_tasks_list). Never options or flags: those are fixed by the table.");
}
json::Value reason_arg() { return prop("string", "One line saying why, written to the server's audit log."); }
json::Value confirm_arg() {
    return prop("boolean", "Must be true. Only set it after the user has explicitly agreed to this change.");
}

std::vector<std::pair<std::string, json::Value>> site_fields() {
    return {
        {"domain", prop("string", "The site's main host name, e.g. example.com.")},
        {"aliases", json::Value::object().set("type", "array").set("items", prop("string", "host name")).set("description", "Other host names served by the same site, e.g. www.example.com. A site answers only the names it lists; \"*\" makes it the catch-all of its listener (every other Host, and requests by IP address).")},
        {"https", json::Value::object().set("description", "\"auto\" (certificate obtained and renewed automatically, needs port 80 reachable), \"none\" (plain HTTP only), or an object {\"cert\": path, \"key\": path} for a certificate you manage.")},
        {"redirect_http", prop("boolean", "With https: also redirect plain http to https (default true).")},
        {"hsts", prop("boolean", "Add Strict-Transport-Security on the https site (default false; only once https is known to work).")},
        {"encoded_slashes", json::Value::object().set("type", "string").set("enum", json::Value::array().push("deny").push("allow"))
                                .set("description", "What a path that spells a slash as a percent escape (%2F, %5C) gets on this site's files: deny (the default) answers 404 before anything is looked up, Apache's AllowEncodedSlashes Off, which stops spellings such as /x%2F..%2Fwp-login.php; allow decodes and looks it up, Apache's NoDecode in effect, for the rare PHP application behind a front controller that encodes a slash inside a path segment and reads REQUEST_URI. Offer allow only when such an application answers 404 to its own URLs; it weakens nothing but spelling. A proxy site passes the raw target to its origin either way, as nginx does, so a Rails or Node application needs nothing here.")},
        {"user", json::Value::object().set("type", json::Value::array().push("string").push("null")).set("pattern", "^[a-z_][a-z0-9_-]{0,31}$").set("description", "A system account the site runs under (isolates it from other sites): lower-case letters, digits, _ and -. Ask the user; suggest a short name derived from the domain. For no account send no_user: true (JSON null works too; the string \"null\" is refused).")},
        {"no_user", prop("boolean", "Run the site without its own system account (the server's account serves it). Use this instead of user: null when null cannot be sent. Refused together with a user value.")},
        {"group", json::Value::object().set("type", "string").set("pattern", "^[a-z_][a-z0-9_-]{0,31}$").set("description", "The account's group (default: its primary group).")},
        {"app", app_enum()},
        {"root", prop("string", "Document root (Laravel: the project directory, its public/ is served; Drupal: the project directory, its web/ is served when present; Rails: the project directory, where site_task runs, suggested as <sites_root>/<domain>/app; Django and Wagtail: the project directory, where manage.py lives, only its static/ and media/ served, suggested the same way; Node: the project directory, where package.json lives, nothing served from it). Required unless app is proxy.")},
        {"upstream", prop("string", "app = proxy, rails, redmine, django, wagtail or node: where the application server listens, e.g. http://127.0.0.1:3000 (keep it on loopback).")},
        {"entry", json::Value::object().set("type", "string").set("pattern", "^[A-Za-z0-9_][A-Za-z0-9_./-]{0,254}\\.(js|mjs|cjs)$").set("description", "app = node: the file node runs, relative to the project directory (server/server.js), which the rendered unit starts. It can wait: site_install's facts guess it from package.json (entry_guess), then site_update sets it.")},
        {"project", json::Value::object().set("type", "string").set("pattern", "^[a-z_][a-z0-9_]{0,63}$").set("description", "app = django or wagtail (required there): the project's Python package, NAME/settings and NAME/wsgi.py. A new project (startproject) is created under this name; an installed one must match its own (the directory holding wsgi.py). Ask the user; suggest a short name from the domain.")},
        {"php_socket", prop("string", "PHP without a site user: the php-fpm socket to use (unix:/path or host:port).")},
        {"php_children", prop("integer", "PHP with a site user: pool size of the generated pool (default 8); the same as settings.children.")},
        {"settings", settings_schema()},
        {"rules", json::Value::object().set("type", "object").set("additionalProperties", false)
                      .set("properties", json::Value::object()
                                             .set("private", json::Value::object().set("type", "array").set("items", prop("string", "a URL path below the root: a directory (ending in /) or one file"))
                                                                 .set("description", "Paths answered 404 whatever exists, never served and never run: an application's private directories (/app/, /data/, /vendor/) and files (/composer.json, /web.config). A directory is final: nothing below it reaches PHP."))
                                             .set("entry_points", json::Value::object().set("type", "array").set("items", prop("string", "an exact .php path, e.g. /index.php"))
                                                                      .set("description", "PHP presets only: the only .php files that run; every other .php answers 404. Kanboard: /index.php, /jsonrpc.php, /healthcheck.php. Empty: the preset's own rule stands."))
                                             .set("cache", json::Value::object().set("type", "array")
                                                               .set("items", json::Value::object().set("type", "object").set("additionalProperties", false)
                                                                                 .set("properties", json::Value::object().set("path", prop("string", "a directory, ending in /")).set("max_age", prop("integer", "seconds, 0 to 31536000")))
                                                                                 .set("required", json::Value::array().push("path").push("max_age")))
                                                               .set("description", "PHP and static presets only: directories served from disk with Cache-Control: public, max-age=N, where no PHP spelling and no backup ending is ever served (/assets/ for a week: 604800)."))
                                             .set("front_controller", prop("string", "PHP presets only: one of entry_points; a path the site has nothing to serve for is routed to it with the query string (nice URLs: try_files $uri $uri/ /index.php?$query_string): no file, and no directory with an index it serves, so a directory whose index.php is not an entry point reaches the front controller too (TYPO3 13's /typo3/: list /index.php and /typo3/install.php, not the deprecated /typo3/index.php)."))
                                             .set("refuse", json::Value::object().set("type", "array").set("maxItems", 64)
                                                                .set("items", prop("string", "a gitignore-style path pattern: /vendor/ from the root, composer.json or *.yaml a name in any directory, * within one segment (/ext/*/Resources/Private/), ** any number of directories (/fileadmin/templates/**/*.ts)"))
                                                                .set("description", "Any app: paths answered 404 whichever location would serve them, the denials an application's official server configuration lists, translated (nginx location ~* \\.(yaml|yml)$ { deny all; } is *.yaml and *.yml; RewriteRule ^(vendor)/ - [F] is /vendor/; an unanchored location ~ _(recycler|temp)_/ is _recycler_/ and _temp_/). No regex, no order, no exception: a match is a 404. A '/' inside needs a leading '/' (or **/ for any depth); only * and ** are wildcards (one pattern per alternative); at most 64. A pattern may not refuse the site's index, its front controller or an entry point. Check the result with path_check."))
                                             .set("admin", json::Value::object().set("type", "object").set("additionalProperties", false)
                                                               .set("properties", json::Value::object()
                                                                                      .set("allow", json::Value::object().set("type", "array").set("items", prop("string", "an address, a range, a set root named in [addresses] (@office)")))
                                                                                      .set("login", prop("boolean", "the login page too (WordPress /wp-login.php, Drupal /user/login): only when the user says no visitor logs in there, since a shop's or a members site's customers do. Tell the user what it does not cover: WordPress also takes passwords at /xmlrpc.php (the mobile app and Jetpack use it; restricted can name it when nothing does), and a Drupal User login block placed on public pages posts to those pages (remove the block)"))
                                                                                      .set("languages", json::Value::object().set("type", "array").set("items", prop("string", "a Drupal language prefix as Drupal writes it: fr, pt-br")).set("description", "Drupal: the admin and login under each prefix too (/fr/admin); ask whether the site is multilingual"))
                                                                                      .set("mode", json::Value::object().set("type", "string").set("enum", json::Value::array().push("enforce").push("report"))))
                                                               .set("required", json::Value::array().push("allow"))
                                                               .set("description", "The preset's administration kept to the addresses in allow (app = wordpress: /wp-admin, while admin-ajax.php and the login page's own files under wp-admin/css, js and images stay open for the public site; drupal: /admin, update.php, core/install.php, core/authorize.php, core/rebuild.php). Admin panels are open to everyone by default and stay so unless the user asks for this; presets_list shows each preset's admin_paths. Before applying, run access_check with the user's own address, and offer mode report first so the error log names any visitor the rule would refuse (a front-end form posting to admin-post.php, a plugin's asset under /wp-admin/). Drupal: path aliases can name an admin page under another path, which Drupal's own permissions keep guarding."))
                                             .set("auth", json::Value::object().set("type", "array").set("maxItems", 16)
                                                              .set("items", json::Value::object().set("type", "object").set("additionalProperties", false)
                                                                                .set("properties", json::Value::object()
                                                                                                       .set("path", prop("string", "a URL path: /staging covers it and everything below it, any capitalisation; / is the whole site"))
                                                                                                       .set("match", json::Value::object().set("type", "string").set("enum", json::Value::array().push("prefix").push("exact")).set("description", "prefix (default): the path and everything below it; exact: this path, and the requests agensio runs as that script (/wp-login.php/x runs /wp-login.php through PHP; a CGI script run with path info), never other paths; on a proxied location the path alone"))
                                                                                                       .set("open", prop("boolean", "true: no password on this path, below a protected one (a health check, an API callback, a webhook); takes nothing else"))
                                                                                                       .set("realm", prop("string", "the name the browser's password dialog shows, 1 to 64 characters without quotes (default: the site's name)"))
                                                                                                       .set("skip_for", json::Value::object().set("type", "array").set("items", prop("string", "an address, a range or a set root named in [addresses] (@office); never any")).set("description", "addresses let in without a password (the office, a monitor); everyone else is asked"))
                                                                                                       .set("plain_http", prop("boolean", "true: ask for the password over plain HTTP from other hosts too, where anyone on the network can read it; only when the user asks for it and knows that (a tool on a trusted LAN). Without it a plain-HTTP request from another host gets 403, never a prompt")))
                                                                                .set("required", json::Value::array().push("path")))
                                                              .set("description", "Passwords (docs/configuration.md 19b): the paths a browser asks a password for, checked before the site's locations, on every internal redirect and on a directory's index, so nothing below steps around them; the users are the site's own file, which site_auth_user_set fills and site_auth_users lists. Refused until the site has a user (add one first: site_auth_user_set with generate: true) and on site_create (the first user comes after the site). Use it for a staging copy (path /), an admin area of a tool with no login of its own, a client's preview; never put one in front of a WordPress or Drupal admin unless the user asks (their logins are there already; on WordPress admin-ajax.php and the login page's files under /wp-admin stay open for the public site). The longest rule decides; open frees a path below a protected one. Every protected answer is Cache-Control: private whatever the application says (its public and s-maxage removed, CDN-Cache-Control and Surrogate-Control dropped), so no CDN or caching proxy keeps it; PHP gets REMOTE_USER; Authorization reaches PHP and is stripped before any other application. Failed passwords are counted by the agensio-auth fail2ban jail (protection_show)."))
                                             .set("restricted", json::Value::object().set("type", "array")
                                                                    .set("items", json::Value::object().set("type", "object").set("additionalProperties", false)
                                                                                      .set("properties", json::Value::object()
                                                                                                             .set("path", prop("string", "a URL path: /wp-admin covers it and everything below it (never /wp-administrator, any capitalisation); / is the whole site"))
                                                                                                             .set("allow", json::Value::object().set("type", "array").set("items", prop("string", "an address (203.0.113.7), a range (203.0.113.0/24, 2001:db8:5::/64), a set root named in [addresses] (@office), or any")))
                                                                                                             .set("match", json::Value::object().set("type", "string").set("enum", json::Value::array().push("prefix").push("exact")).set("description", "prefix (default): the path and everything below it; exact: this path, and the requests agensio runs as that script (/wp-login.php/x runs /wp-login.php through PHP; a CGI script run with path info), never other paths; on a proxied location the path alone"))
                                                                                                             .set("mode", json::Value::object().set("type", "string").set("enum", json::Value::array().push("enforce").push("report")).set("description", "enforce (default): others get 403; report: everyone is served and the error log names who would have been refused")))
                                                                                      .set("required", json::Value::array().push("path").push("allow")))
                                                                    .set("description", "Access by client address, on any app: only the addresses in allow reach path; everyone else gets 403 with the address the server saw. Checked before the site's locations, so a .php file or a proxied path below it is covered too. The longest rule covering a path decides, and [\"any\"] on a longer path reopens it (WordPress keeps /wp-admin/admin-ajax.php open by itself when /wp-admin is restricted, for its public pages). Behind a CDN or another proxy the address is the client only when root lists the proxy in [server] trusted_proxies; otherwise every request comes from the proxy (health_check warns). Before a rule that covers the user's own access, ask for their address and run access_check with it, so they are never locked out; mode report shows who would be refused without refusing. The sets root defined are in config_reference (key addresses, running: each set with its entries); the control plane cannot change them. At most 32 rules, 64 addresses each; longer lists belong in the firewall.")))
                      .set("description", "An application's own server rules, the ones its documentation or .htaccess files ask for, for a site without a preset of its own (app = php) or on top of one. Bounded: every rule makes the site serve less, never more, so an agent can apply what the application documents. For an application without a preset (TYPO3, Kanboard, phpBB, Nextcloud...), read its official web server configuration (the nginx or Apache configuration its documentation publishes, for the version the user runs) and translate it: the .php files it runs (entry_points), where a missing path goes (front_controller), its directories that are never served (private) and every deny rule (refuse, as gitignore-style patterns). Sent whole: the object replaces the site's rules, restricted included, so to add one send the site's current rules (site_show) with it; {} clears them. presets_list and site_show say what a preset refuses already; site_install's facts list the directories the archive's .htaccess files deny (htaccess_denied), ready for private.")},
        {"login_paths", json::Value::object().set("type", "array").set("items", prop("string", "a URL path, e.g. /login or /api/token, or a path with the start of its query, e.g. /?controller=AuthController&action=check (letters, digits and ._~/=&+:- in the query; no %, spaces or quotes)"))
                            .set("description", "Where the application's login form or authenticating API is posted to, on top of the preset's known paths (wordpress /wp-login.php and /xmlrpc.php, drupal /user/login, laravel /login, grav /admin, redmine /login, django and wagtail /admin/login/). Nothing is served or refused by it: the fail2ban jail protection_show renders counts attempts there (ten in ten minutes bans for an hour). An application that routes its login through the query string is named with it, matched from the query's start with anything after: Kanboard /?controller=AuthController&action=check, Roundcube /?_task=login, phpBB /ucp.php?mode=login; never the bare / (every form post would count). The jail matches each path in every spelling the server accepts (percent-encoding, repeated slashes, dot segments, case, a trailing slash, an /index.php front controller, a .format suffix, query parameters in any order), so one canonical spelling here is enough. For an application without a preset of its own (app = php, rails, node, proxy) ask the user where it posts credentials, or read its documentation, then set it here and render the jail again. Sent whole: the list replaces the site's; [] clears it. At most 16.")},
        {"php_version", prop("string", "PHP version for the generated pool, e.g. \"8.3\" (default: newest installed).")},
        {"listen_plain", prop("string", "Plain listener address (default 0.0.0.0:80).")},
        {"listen_tls", prop("string", "TLS listener address (default 0.0.0.0:443).")},
        {"dry_run", prop("boolean", "Check everything and show the file that would be written, without writing or reloading: the answer lists every problem at once (missing account, directory, certificate, a port that needs a restart) with the command for each.")},
        {"confirm", confirm_arg()},
        {"reason", reason_arg()},
    };
}

std::vector<Tool> tools() {
    std::vector<Tool> t;
    t.push_back({"server_status", "Server status", "Version, pid, uptime, workers, open connections, the per-worker connection ceiling (max_connections: server.max_connections or derived from the open-file limit), connections_refused at it since start, connections_idle (HTTP/1 and HTTP/2 connections idle 2 s or more) and under workers_detail each worker's connections, idle ones, refusals, and the addresses and listeners the refusals came from and when; health reports refusals with a fix that follows from their shape (most from one address: the firewall's job; workers full of idle connections: slow or stuck clients; many addresses and busy workers: raise the limit), listeners with the protocols each offers (h2 and h1 on TLS listeners, through ALPN; h1 on plain ones, plus h2c when [server] protocols lists it), sites and the caller's role. Each listener names its catch_all site (the one with server_name [\"*\"] or default = true) or null: a listener with none answers 421 Misdirected Request to any Host its sites do not list, including the IP address; on TLS a connection also answers 421 for a Host the certificate it presented does not cover (each site's own certificate bounds what its connections serve; a SAN or wildcard certificate covers every site it names).", "GET", "/v1/status", true, false, Role::viewer, schema({}, {})});
    t.push_back({"sites_list", "List sites", "Every configured site with its listeners, root, app, user, redirect, whether it is the catch_all of its listener, and certificate state (issuer, days left, whether it is still the placeholder). A site answers only the names it lists unless it is the catch-all.", "GET", "/v1/sites", true, false, Role::viewer, schema({}, {})});
    t.push_back({"site_show", "Show one site", "One site in full: effective locations after the preset expanded (each with from: preset:<app>, rules, or root:<file>; none for a hand-written one), PHP pool, upstreams, certificate, login_paths (the preset's known login paths plus the site's own, which the fail2ban jail protection_show renders counts attempts on); access (the access-by-address rules in force, longest path first, each with from: rules, preset:wordpress, or nothing for a hand-written one; access_check answers what one of them decides for an address); refuse (the path patterns answered 404, as written; path_check says what one path meets); auth (the password rules in force, longest path first, each with from: rules, preset:wordpress or nothing for a hand-written one, its realm, its users file, users_count and usable, the users who can log in now, skip_for and plain_http; the names are site_auth_users'); for a managed site its rules in force and root_additions: the root-owned file beside the managed one (sites.d/<domain>.root.toml) where root extends the site with locations no field of site_update covers, whether it exists and what it added. When the user wants such a change (a redirect, a header on one path, an alias outside the root, another upstream for a path, CGI), hand them the exact [[location]] block for that file and `agensio reload`; the site stays managed.", "GET", "/v1/sites/{name}", true, false, Role::viewer, schema({{"name", name_arg()}}, {"name"})});
    t.push_back({"config_validate", "Validate configuration", "Loads the configuration file on disk again and runs the hosting rules; reports errors and the restart-only settings that differ from the running server.", "GET", "/v1/config/validate", true, false, Role::viewer, schema({}, {})});
    t.push_back({"logs_query", "Query logs", "Recent lines from the error log and the access logs. Use it for questions like 'any errors in the last 3 hours?'. Summarise for the user; do not paste hundreds of lines. Each line's source says where it came from: error (the error log), access (the server-wide access log, [log] access, which every site without an access_log of its own writes into: the catch-all site, the http-to-https redirects, scanners hitting the bare address; a combined line there carries no host name, so it belongs to no site in particular, never read it as one site being attacked), or a site's name (a log that site alone writes). sources lists every file read with its source and the sites writing into it. A query for a site that shares the server-wide log answers shared: true with a note: JSON logs are filtered to the site's host names, combined lines cannot be, so the answer is the whole shared log; give the site its own access_log to separate it. A site name that does not exist is a 404, not an empty answer. Lines are always valid text: a byte a client sent that is not UTF-8 appears as \\xHH. An access rule's refusals are warn lines of the error log: access refused: (site, rule, the client tested, the request), at most one a second per worker, with the refusals held back counted as N more refusals since the last such line (the access log has each 403 with its client); and access would refuse: for a rule in report mode, each rule and client named once a minute, so these lines list who the rule would lock out.", "GET", "/v1/logs", true, false, Role::viewer,
                 schema({{"site", prop("string", "A site's host name; omit for every site plus the error log. A site without an access_log of its own shares the server-wide log: see shared and note in the answer.")},
                         {"since", prop("string", "How far back: 3h, 45m, 2d, 1w, seconds, or a local YYYY-MM-DDThh:mm:ss (default 1h).")},
                         {"level", json::Value::object().set("type", "string").set("enum", json::Value::array().push("error").push("warn").push("info")).set("description", "Error-log level filter (default warn = error and warn).")},
                         {"status", prop("string", "Access-log filter: 5xx (default), 4xx, all, or a number for that status and above.")},
                         {"limit", prop("integer", "Newest lines to return (default 200, max 5000).")}},
                        {})});
    t.push_back({"config_reference", "Configuration reference", "Every configuration key agensio reads, in one table: its table ([server], [cache], [log], [control], [[site]], php = {}, proxy = {}, [[site.location]]), type, default, meaning, whether a change applies on reload or needs a restart, who changes it (via: file = root in the main configuration file; site file = a hand-written site file, or for a managed site its root additions file; root additions = that file's own key; site-create = a field of site_create/site_update; settings = site_update's settings), the section of docs/configuration.md that explains it, and for server-level keys the running value and the file it comes from. Use it to answer 'how do I change X' and 'what is X set to'. Read via as which tool does it: settings and site-create mean site_update (or site_create), and you do it here; only via = file (root's main configuration) and via = site file have no tool, and only then give the user the exact TOML line, the file, and `agensio reload` or `systemctl restart agensio` as applies says, stating that agensio does not edit that file itself. A [[site.location]] key on a site the tools manage goes into the site's root additions file (site_show names it under root_additions, with the first line it needs), never into the managed site file, which site_update regenerates. A key that is not listed does not exist.", "GET", "/v1/config/reference", true, false, Role::viewer, schema({}, {})});
    t.push_back({"site_settings_list", "Site settings", "The per-site limits site_create and site_update accept under settings, from the same table as the schema: for each key its type, unit and accepted spellings, meaning, default and where it comes from, minimum, the ceiling [control] site_limits sets (root raises it in the configuration file), what changing it costs (agensio reload, php-fpm reload) and what it derives (max_body_size drives the pool's upload_max_filesize and post_max_size). With name, also each key's current effective value and its source (site, server, default). Use it before changing a limit, and to answer 'what is this site's upload limit'.", "GET", "/v1/settings", true, false, Role::viewer,
                 schema({{"name", prop("string", "A site's host name: adds the current values. Omit for the table alone.")}}, {})});
    t.push_back({"protection_show", "Host protection: firewall limits and fail2ban", "What the server does not do itself (docs/configuration.md 18), rendered for this host and checked: per-address connection and rate limits on the web ports belong to the kernel's firewall, brute force on logins to fail2ban over the access logs. The answer carries firewall.ruleset (an nftables table of its own, inet agensio, for this host's public ports, with a QUIC handshake limit when h3 is on; it touches nothing else, no other table and no policy, so a panel's rules, ufw and firewalld keep theirs), firewall.trial (root's commands: write the file, load it into the kernel only, and a systemd timer that removes it again after ten minutes, so a mistake undoes itself), firewall.keep (cancel the timer, enable agensio-firewall.service so it loads at boot), firewall.remove; fail2ban.jail (the jails over this host's access logs: agensio-login counts credentials posted to the sites' login paths, the presets' known ones plus each site's login_paths, in every spelling the server accepts, ten in ten minutes bans for an hour, one such jail per access log (login_jails lists them: agensio-login for the server-wide log, agensio-login-<site> for a site's own); and the failure tier, failure_jails: for a preset whose application logs its own failed logins, a jail over that log with the filter fail2ban or the application ships, counting failures rather than attempts: WordPress through the WP fail2ban plugin (agensio-wordpress-soft and -hard over the auth log with the plugin's filters), Drupal through its Syslog module (agensio-drupal-auth with fail2ban's own filter); on a host where no syslog daemon writes files (journald only) the jail reads the journal with a journalmatch on each site account's _UID (a field journald sets from the sender's credentials, with the php-fpm unit for WordPress and the identity drupal for Drupal; never the identity alone, which any process may claim) and needs no log file, a site without an account of its own is listed under unidentified and not read until it gets one (site_update user), and journal_seen says whether the journal holds a line of the application from the last 30 days (false: the module or the plugin is not writing yet, so health keeps its finding); each rendered enabled only when its filter file exists (and, with a syslog daemon, its log), else disabled with needs: what the user does in the application's admin panel and what root copies (the WordPress filters from the plugin's release, not from the site's writable directory). Never install a plugin or change an application yourself: say what needs doing, that is where agensio's work ends; agensio-auth: failed passwords on the sites' [[site.auth]] paths, read from the error log's auth failed lines (a wrong password, an unknown or locked user), never a 401, which is the challenge every browser meets first, so the people with the password are not banned; it needs the error log in a file at warn, the package's default, and auth says which sites have a password, the log it reads, counted (a jail reads it) and needs (root's line when the log is on stderr or at level error); agensio-denied bursts of 403 (an address outside a site's access rule, an application refusing); agensio-scan bursts of 404; agensio-post bursts of POST to any path, the catch-all for an unnamed login), fail2ban.filters (the five static filter files) and fail2ban.install (root's commands). firewall.detected and fail2ban.detected say what is in place now, read by the root helper with fixed arguments (nft -j list ruleset, systemctl show, fail2ban-client status): whether every public port has a per-source limit in any table (a panel's or the administrator's own counts as protection), whether the agensio table is loaded, on trial or enabled at boot, each of its rules' hit counter, which jails read agensio's logs and how many addresses they banned; fail2ban.installed_jail says whether the jail file on disk matches this rendering (stale after a site, a log or a login path was added), fail2ban.installed_filters whether the five filter files on disk are this build's text (stale after an upgrade that changed one: the jails then match what the older build matched, and the fix starts with the install line). summary says it in one sentence; findings are the ones health_check reports (firewall_limits_missing, firewall_limits_trial, firewall_limits_unsaved, firewall_quic_unlimited, fail2ban_missing, fail2ban_jail_stale, fail2ban_filter_stale, fail2ban_failures_unseen, fail2ban_auth_unseen: a site has a password and nothing counts its failed logins, fail2ban_auth_challenges: the installed agensio-auth filter is an older build's that counted every 401 and so bans the site's own users, fix at once, fail2ban_log_format, fail2ban_blind, protection_unchecked). Use it when health_check reports one of those, when the user asks about rate limiting, brute force, bots or DDoS, and after root ran the commands, to confirm. The procedure for the user: show the trial commands exactly, tell them to check that the site and their SSH session still answer, then show the keep commands; never skip the trial, and never present the firewall as something agensio applies: root runs every command. On a host without the root helper detected is unchecked and the files are still rendered. An empty login_paths list means the login jail is rendered disabled: ask the user where each site without a preset posts credentials and set site_update login_paths first. [control] host_protection = \"external\" (root's) makes the findings informational on a host whose firewall a panel manages; \"off\" skips the check.", "GET", "/v1/protection", true, false, Role::viewer, schema({}, {})});
    t.push_back({"site_tasks_list", "List a site's tasks", "The named tasks site_task can run on this site, from its preset's table: for app = \"rails\" gem_install_rails, rails_new, bundle_install, db_prepare, db_migrate, assets_precompile; for \"django\" and \"wagtail\" venv_create, pip_install (any packages, confirmed by the user in person: user_confirmation), startproject (the preset's own: django-admin startproject or wagtail start), pip_install_requirements, django_settings, migrate, collectstatic, createsuperuser, check_deploy; for \"node\" npm_ci and npm_run. Each with what it does, its parameters (name, pattern, required), whether it downloads (refused when root set [control] task_network = false), whether the site's directory must be empty, its effective time limit, and its interpreter: the program it would run, whether the interpreter rule accepts it, and when not the reason and the package command. run_as_root at the top lists every missing package once (python3-venv when the Python cannot make virtualenvs): call this before the first task and ask the user to install them then, not after a task fails. Also the account that runs the tasks, the directory, for a Django site its project and virtualenv, and the task running now if any. Sites of other presets have none, and agensio runs no other command.", "GET", "/v1/sites/{name}/tasks", true, false, Role::viewer, schema({{"name", name_arg()}}, {"name"})});
    t.push_back({"presets_list", "Application presets", "What each `app` value does: which directory is served, which .php runs (every one, only the front controller, or, for drupal, only a script directly in the root or in core/ as Drupal's .htaccess says), what is refused, which directories never run PHP, which serve certain endings alone (`serves_only`: Grav's user/accounts avatars, user/data media), which files are never served (and, the note says, refused in every backup spelling too: wp-config.php.bak, wp-config.php~, .wp-config.php.swp, wp-config.txt, so a user asking whether a backup of the credentials file is exposed can be answered without a terminal), `admin_paths`: what site_update rules.admin restricts when the user asks for it (wordpress, drupal; open to everyone by default), and `source`: the official archive site_install takes when it has one (wordpress, drupal, grav). Use it to answer 'which applications are supported', to pick app for site_create and to know whether site_install can fetch the application itself; the site_show tool shows the expanded locations of a real site.", "GET", "/v1/presets", true, false, Role::viewer, schema({}, {})});
    t.push_back({"health_check", "Health check", "What an administrator should look at: certificates, missing redirects, port 80 for ACME, recent errors, settings waiting for a restart, root, shared accounts, stale pools, php-fpm reloading without process_control_timeout (which cuts PHP requests on every site whenever a pool is written), and php_pool_resident: every static or dynamic pool with the PHP processes it keeps while idle and their memory (the answer to 'why so many php-fpm processes' or 'the machine is full': site_update with settings: {pm: \"ondemand\"} frees it; static stays right for a site that must not pay a fork on its first request), judged from the pool file php-fpm runs, so a pool left static on disk after the configuration changed is named as a warning whose fix is agensio pools plus a php-fpm reload. preset_mismatch: the files under a site's directory belong to another application than its app says (Grav on the drupal preset: the borrowed refusals do not fit, and its backup archive was public); the fix is site_update with the detected app. archives_in_root: backup archives and database dumps (.zip, .tar.gz, .sql) inside a served tree, one preset or one path away from public; the fix is moving them out. site_env_unsafe: the directory of the sites' environment files, or one site's file (named by site), is open to others, not root's or has a second link, which stops that site's tasks until fixed; the fix is the chown/chmod line (what is only readable by others is tightened at the next task, info); or values that were readable by others and have not changed since (a warning that stays until they change): tell the user those secrets may have leaked and help rotate them with site_env_set (unset and generate for SECRET_KEY_BASE, new values for the rest, changed where they are used too). site_env_orphan: the environment file of a site that no longer exists, its secrets; the fix is its rm -f line when the site is gone for good. site_env_unchecked: the helper was running a task; ask again later. firewall_limits_missing and fail2ban_missing (on a host with a public listener): no per-address limit on the web ports in the kernel's firewall, or no fail2ban jail reading agensio's access logs; the fix is the trial and keep commands for root, which protection_show carries in full with the files; firewall_limits_trial: the ruleset is loaded on trial and a timer will remove it unless root keeps it; firewall_limits_unsaved: loaded but not enabled at boot; fail2ban_jail_stale: a site, a log or a login path was added since the jail file was installed, render it again; fail2ban_filter_stale: an upgrade changed a shipped filter and the installed copy is the old one, reinstall the filters (the fix's first line) before anything else; fail2ban_failures_unseen: a WordPress or Drupal site's failed logins are counted only as attempts because the application's side is not in place (the WP fail2ban plugin and its filters, Drupal's Syslog module, or the log file; on a journald-only host the jail is enabled but the journal holds no line of the application from the last 30 days, which says the module is still off or the plugin not active; or a site there has no account of its own, so no trusted journal field tells its lines apart and the jail does not read them), the fix lists the user's steps in the admin panel and root's lines, none of them a tool's; fail2ban_auth_unseen: a site has a password ([[site.auth]]) and no jail counts its failed logins, because the error log is on stderr or at level error, or the installed jail file is an older build's; fail2ban_auth_challenges (warn, urgent): the installed agensio-auth filter is an older build's that counts every 401, and every visitor's first request to a password-protected path is one, so fail2ban bans the site's own users: give root the fix's lines at once; auth_users_unloadable (error): a password rule's users file the next load would refuse (gone, another owner, a wrong mode, a line it cannot read): the running server still asks with the users it loaded, but a reload is refused and a restart does not start the server: give root the fix at once; auth_no_valid_user: every user of a rule is locked or expired, so every login fails; auth_users_expired: users who can no longer log in (site_auth_user_delete those who are gone); auth_plain_http: a rule asks for passwords over plain HTTP on a listener the network reaches; auth_users_orphan: a users file no site owns (a deleted site's: a site created again under the name with a password rule would let them in); fail2ban_log_format: the access logs are JSON, which the filters do not read; fail2ban_blind: sites without an access log; protection_unchecked: the check needs the root helper. Access by client address: access_allows_proxy (a rule allows a range holding a trusted proxy, so a request the proxy sends without X-Forwarded-For passes), access_loopback (a rule allows 127.0.0.1 or ::1 while no local proxy is trusted: a tunnel or local proxy would make everyone pass), access_ipv4_only and access_single_ipv6 (IPv6 clients refused, or one daily-changing IPv6 address allowed), access_site_restricted (a whole site answers only its allowed addresses: meant for staging). Informational when root set [control] host_protection = \"external\" (a panel manages the firewall). Each finding has a severity and a fix. Run this first on a server you do not know.", "GET", "/v1/health", true, false, Role::viewer, schema({}, {})});
    t.push_back({"reload", "Reload configuration", "Validate the configuration on disk and switch to it without dropping a connection. Refused with the reason when it does not validate; nothing changes then.", "POST", "/v1/reload", false, false, Role::operator_, schema({{"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"confirm", "reason"})});
    t.push_back({"logs_reopen", "Reopen logs", "Reopen every log file after rotation.", "POST", "/v1/logs/reopen", false, false, Role::operator_, schema({{"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"confirm", "reason"})});
    t.push_back({"site_create", "Create a site", "Writes a new site file, validates and reloads. A new site is HTTPS-only with a redirect from http unless https is \"none\". Until https, root (or upstream), app and user are decided the server answers with the open questions and a suggestion each: ask the user each question, then call again with every field. When the server has its provisioning helper (started as root, the default), the account, the directories, the site's log and the php-fpm pool are created by this call and listed under done; only then is nothing left for a terminal. If it answers with commands to run as root instead (no helper, or the helper refused something), show them to the user, wait until they confirm they ran them, then call again with the same fields. The success answer may carry warnings: tell the user each one (for example that the site answers only its own names and a monitor checking the IP address needs the hostname, or a catch-all site with server_name [\"*\"]). A staging copy kept to the team can be created with rules.restricted on / at once (check the user's address with access_check right after).", "POST", "/v1/sites", false, false, Role::admin, schema(site_fields(), {"domain", "confirm", "reason"})});
    {
        auto fields = site_fields();
        fields.insert(fields.begin(), {"name", name_arg()});
        t.push_back({"site_update", "Update a site", "Changes fields of a site that site_create wrote (aliases, https, user, app, root, upstream, PHP pool, and the per-site limits under settings: raising a WordPress site's upload limit is settings: {max_body_size: \"200MB\"}; and the application's own server rules under rules: private paths, the only .php that run, cached directories, a front controller for nice URLs, refuse (the application's deny rules as gitignore-style path patterns, answered 404; check them with path_check), and restricted, the paths (or the whole site) only some client addresses reach, and admin, a WordPress or Drupal site's administration kept to some addresses when the user asks (it is open by default), and auth, the paths a browser asks a password for, with the site's own users (refused until the site has one: site_auth_user_set first), all of which only make the site serve less, so an application with its own server guidelines and no preset, Kanboard or TYPO3 for one, is secured with app = php plus rules translated from its official server configuration; site_show shows the rules in force; and login_paths, where the application posts credentials, for the fail2ban jail protection_show renders: set it for a site whose preset does not know its login path, after asking the user; when the installed fail2ban jail or firewall ruleset is then older than the sites, next_steps carries root's re-render line, and the new paths are not counted until root ran it). The answer lists under done what was written and reloaded (the site file and agensio; the php-fpm pool and php-fpm, which briefly affects every PHP site unless process_control_timeout is set). Hand-written site files are refused; tell the user to edit those directly. What no field here covers (a redirect, a header on one path, an alias outside the root, another upstream for a path, CGI, odd try_files) is root's: hand the user the exact [[location]] block for the site's root additions file (site_show names it) and `agensio reload`; that keeps the site managed, editing the managed file does not.", "POST", "/v1/sites/{name}", false, false, Role::admin, schema(fields, {"name", "confirm", "reason"})});
    }
    t.push_back({"site_disable", "Disable a site", "Stops serving the site (its file is renamed to .disabled) and reloads. Reversible with site_enable.", "POST", "/v1/sites/{name}/disable", false, false, Role::admin, schema({{"name", name_arg()}, {"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"name", "confirm", "reason"})});
    t.push_back({"site_enable", "Enable a site", "Brings a disabled site back and reloads.", "POST", "/v1/sites/{name}/enable", false, false, Role::admin, schema({{"name", name_arg()}, {"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"name", "confirm", "reason"})});
    t.push_back({"site_delete", "Delete a site", "Removes the site's configuration and reloads. Without files (the default) the configuration goes and nothing else: the site file becomes .bak, and the site's root additions file (root's, sites.d/<domain>.root.toml) is renamed .bak beside it (root_additions_set_aside in the answer; tell the user), while the site's files and account are never touched; for a Rails or proxy site the answer then names its environment file when it has one (kept, with the root line that removes it), and under exposed any values in it others could read that were never rotated: tell the user, since bringing the site back with that file brings those values back. With files: true everything of the site is moved into root's trash (<sites_root>/.trash/<domain>-<stamp>, 0700, read by nobody else): the site's directory, the account's state directory (its gems, virtualenvs, sessions; the site's virtualenv alone when another site shares the account), its access log with its rotations, its environment file with its secrets, and the configuration's text in the entry's manifest. Nothing is copied or deleted: the entry stays [control] trash_keep days (60 by default; trash_list shows when), then the hourly expiry removes it, and site_restore brings everything back until then. The account is kept, since the files carry its uid (trash_list says when no site uses it any more, for root's userdel). Refused while the site's application service still runs (the answer carries the systemctl lines for root: stop it first, or the running process would write into the trash) and for a site whose directory is not below sites_root; a reload that fails afterwards puts everything back. Ask the user which of the two they mean, and say what files: true moves; it is the one to use when the user wants the site gone.", "POST", "/v1/sites/{name}/delete", false, true, Role::admin,
                 schema({{"name", name_arg()},
                         {"files", prop("boolean", "Also move the site's files (directory, account state, logs, environment file) into root's trash, recoverable with site_restore for trash_keep days. Default false: the configuration alone.")},
                         {"confirm", confirm_arg()},
                         {"reason", reason_arg()}},
                        {"name", "confirm", "reason"})});
    t.push_back({"trash_list", "List the trash", "The sites deleted with their files (site_delete with files: true), one entry each, <domain>-<date>-<time>: the site, its preset, its account and whether any site still uses it (false: root may remove it with userdel once the entry is gone), when it was deleted, when the hourly expiry removes it (null: never, trash_keep = 0), whether it has expired, its size and file count, and the pieces it holds with their original paths. Use it before site_restore or trash_delete, and to answer 'what did we delete'. Admin only.", "GET", "/v1/trash", true, false, Role::admin, schema({}, {})});
    t.push_back({"site_restore", "Restore a deleted site", "Brings a site deleted with its files back from the trash: every piece to its original path, the configuration file rewritten from the entry's manifest, then a reload. Only into an empty place: refused when the site exists again, when its configuration file is there, or when any original path exists and is not empty (nothing is ever merged); refused too when the account is gone or has another uid (the files carry it; the answer gives root the useradd line with --uid). The application's service is not restored: site_service_unit renders it again for root. Entries come from trash_list.", "POST", "/v1/trash/{entry}/restore", false, false, Role::admin,
                 schema({{"entry", prop("string", "A trash entry's name from trash_list, <domain>-<date>-<time>.")}, {"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"entry", "confirm", "reason"})});
    t.push_back({"trash_delete", "Remove a trash entry for good", "Removes one entry of the trash now, with every file in it, instead of waiting for the expiry: irreversible. Only after the user named the entry and agreed; never to make room without being asked. Entries come from trash_list.", "POST", "/v1/trash/{entry}/delete", false, true, Role::admin,
                 schema({{"entry", prop("string", "A trash entry's name from trash_list, <domain>-<date>-<time>.")}, {"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"entry", "confirm", "reason"})});
    t.push_back({"access_check", "Check access by client address", "Which access rule (rules.restricted, [[site.access]]) decides one path of a site for one client address, and whether that client is served or refused with 403: decision allowed, refused or report (a rule in report mode: served, logged as refused), rule (path, match, allow, mode, from: rules, preset:wordpress, or nothing for a rule written by hand), and summary, one line to tell the user. The path as a browser sends it; the address as the server sees the client (the 403 page names it; behind a trusted proxy it is the forwarded client). Use it before site_update adds or changes a restricted rule, with the user's own address, so they are never locked out; and when a user reports a 403, with the address their 403 page shows. site_show lists a site's rules (access), config_reference root's address sets (key addresses) and the trusted proxies (key trusted_proxies), and logs_query the refusals (warn lines access refused:).", "GET", "/v1/sites/{name}/access", true, false, Role::viewer,
                 schema({{"name", name_arg()}, {"path", prop("string", "The request path, e.g. /wp-admin/post.php")}, {"address", prop("string", "The client's IPv4 or IPv6 address, e.g. 203.0.113.7")}}, {"name", "path", "address"})});
    t.push_back({"path_check", "Check what a site does with a path",
                 "What one site does with a GET for one path, and why, in the order the server decides it: decision refused (404 by a refuse pattern, named in refused_by, or by a location's refusal by name: a hidden file, a refused ending, a backup of a protected name), static (the file served, in file), runs (the script that runs, through FastCGI or CGI, with PATH_INFO), proxied (the application answers; upstream), redirect (301 to the slash form), forbidden (403: a directory without an index) or not_found; status when the server decides it; location (path, match, handler, from: preset:<app>, rules or root:<file>); script when PHP or CGI runs the path as another path (/wp-login.php/x runs /wp-login.php), which exact access and password rules judge too; steps, every decision on the way (try_files, a directory's index, each internal redirect); access when an access rule covers the path (access_check decides it for a client address); auth when a password rule covers it (its path, realm, users file, how many users can log in, skip_for, from; an exact rule on the script the path runs counts, see script), with auth_note saying what a request without the password meets, or that the path is open below a protected one; summary, one line to tell the user. A description, not a request: nothing is fetched from the application. Use it after translating an application's official server configuration into site_update rules (refuse, private, entry_points, front_controller): check every path the documentation names, one that must be refused and one that must still be served, and show the user the summaries before and after applying. Also when a user asks why a URL answers 404 or which file it serves.",
                 "GET", "/v1/sites/{name}/path", true, false, Role::viewer,
                 schema({{"name", name_arg()}, {"path", prop("string", "the request path as a browser sends it, starting with '/', e.g. /typo3conf/ext/news/Configuration/TypoScript/setup.typoscript")}}, {"name", "path"})});
    t.push_back({"cert_renew", "Renew certificate", "Orders the site's automatic certificate again now. Watch site_show and logs_query for the result.", "POST", "/v1/sites/{name}/renew", false, false, Role::operator_, schema({{"name", name_arg()}, {"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"name", "confirm", "reason"})});
    t.push_back({"uploads_list", "List uploads", "Archives stored on the server with `agensio ctl upload NAME < file` (run by the user on the server, or over ssh: `ssh admin@host agensio ctl upload NAME < file`), ready for site_install with file: NAME. This bridge cannot carry files itself: when the user has an archive on their own machine, give them that command.", "GET", "/v1/uploads", true, false, Role::viewer, schema({}, {})});
    t.push_back({"upload_delete", "Delete an upload", "Removes a stored upload once it is installed or not needed.", "POST", "/v1/uploads/{file}/delete", false, true, Role::operator_, schema({{"file", prop("string", "The upload's name as uploads_list shows it.")}, {"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"file", "confirm", "reason"})});
    t.push_back({"site_install", "Install an application", "Puts an application's files into the site's directory, as the site's own account, from one of three sources: the preset's official archive (presets_list shows which presets have one: wordpress, drupal, grav; version picks a release, default the newest), any https URL the user gives (url), or an archive the user uploaded (file, see uploads_list). The whole application goes into the site's directory, which must be empty; a plugin, theme or module goes into path (e.g. wp-content/plugins/NAME, web/modules/contrib/NAME) with create_path: true, which makes the missing directories as the site's account below the site's directory (never through a symlink, never in another account's directory); a single top directory in the archive (wordpress/, NAME/) is unwrapped. Rules the server enforces and reports: https only, no private, loopback or link-local address on any hop, size caps, no symlinks, hard links or devices inside an archive, optional sha256 check; on any refusal nothing is left behind. The preset's credential files (presets_list, secrets: wp-config.php, Drupal's settings.php, Rails' config/master.key) are made 0600, a credential directory (.git, Rails' storage/) loses its group's read and write, and both are listed under secured, and the configuration is validated after the install: an answer is never ok when agensio -t would refuse the result (a 409 with written: true and errors says what to fix). dry_run: true runs the same checks (target, account, what would be created) without installing. Tell the user the source and the sha256 from the answer, then the application's own setup remains (database, admin account), done in the browser. Laravel has no archive: it is created with composer. A new Rails application is not an archive either: site_task rails_new makes it; an existing Rails application installed from an archive (a GitHub release tarball, an upload) is then prepared with site_task (bundle_install, db_prepare, assets_precompile), and the answer's next_steps say so instead of the browser step, with the Ruby version the application pins (.ruby-version) when it has one. A Django or Wagtail project from an archive (manage.py at its top) gets DJANGO_SECRET_KEY generated into the site's environment the same way, next_steps from venv_create on (with pip_install for Gunicorn, which the user confirms), and a warning when its package (the directory holding wsgi.py, facts wsgi_packages) is not the site's project. A Rails archive that came without credentials (config/credentials.yml.enc: every ONCE application such as Writebook) reads SECRET_KEY_BASE from its environment, so this call also generates one into the site's environment (site_env), listed under done. For a WordPress or Drupal install next_steps also says what makes fail2ban count the site's failed logins (the WP fail2ban plugin from the admin panel and root's copy of its filters; Drupal's Syslog module): tell the user, never install a plugin or change the application yourself. facts also lists under htaccess_denied the directories the archive's own .htaccess files deny to the web (a Require all denied or Deny from all for the whole directory; agensio never reads .htaccess when serving), and next_steps carries the matching site_update rules: {private: [...]}: apply it after the user agreed, and add rules.entry_points when the application documents which .php files run. facts says what the archive holds (gemfile, credentials, database_yml, database_yml_example, redmine, the pinned Ruby); without config/database.yml the next steps start with DATABASE_URL and site_task database_config, and a Redmine archive on a rails site gets a warning to switch it to app = \"redmine\". Redmine itself: app = \"redmine\" with version (e.g. 7.0.1) and the sha256 redmine.org publishes; there is no newest-release address. next_steps also state the site's request-body limit: tell the user before the first upload meets it.", "POST", "/v1/sites/{name}/install", false, false, Role::admin,
                 schema({{"name", name_arg()},
                         {"url", prop("string", "An https URL of a .tar.gz, .tar or .zip archive. Omit it to use the preset's official archive, or give file instead.")},
                         {"file", prop("string", "The name of a stored upload (uploads_list). Use it when the user has the archive on their machine or a download is refused by the server's rules.")},
                         {"version", prop("string", "With the preset's official archive: the release to install, e.g. \"6.7.1\"; default the newest.")},
                         {"sha256", prop("string", "Expected sha256 of the archive (64 hex digits); the install is refused when it differs. Use it when the user or the publisher gives one.")},
                         {"path", prop("string", "A subdirectory below the site's directory to install into, e.g. wp-content/plugins/NAME for a plugin (default: the site's directory itself). It must be empty, or missing with create_path.")},
                         {"create_path", prop("boolean", "Create the missing directories of path as the site's account (parent's ownership pattern and mode). Without it a missing path is refused. Existing directories are never emptied.")},
                         {"strip", prop("integer", "1 unwraps a single top directory, 0 keeps it; default: unwrap when the archive has exactly one.")},
                         {"dry_run", prop("boolean", "Run the same checks as the real call (target, account, what would be created) without downloading or writing anything; a refusal shows as it would for real.")},
                         {"confirm", confirm_arg()},
                         {"reason", reason_arg()}},
                        {"name", "confirm", "reason"})});
    t.push_back({"site_copy", "Copy a file within a site", "Copies one regular file of the site to another path of the same site, as the site's account: the drop-in files applications ship as templates, e.g. WordPress's wp-content/db.php from wp-content/plugins/sqlite-database-integration/db.copy (the SQLite plugin does not work until that copy exists), advanced-cache.php or object-cache.php from a caching plugin, Drupal's sites/default/settings.php from default.settings.php. Both paths are relative to the site's directory and must stay inside it (no '..', no symlink on the way, no other account's directory); from must be an existing regular file; the destination's directory must already exist (site_install with create_path makes one); an existing destination is refused unless overwrite: true, and then the answer reports what was replaced. The new file gets the directory's pattern (0640 in a 2750 directory), except a credential file of the preset (wp-config.php, Drupal's settings.php), which is 0600 (secured: true); the configuration is validated afterwards and the answer is never ok when agensio -t would refuse it. Nothing can be copied across sites, no content can be supplied, no directory copied, no chmod or chown: those are not offered on purpose. dry_run: true runs the same checks and reports what would happen.", "POST", "/v1/sites/{name}/copy", false, false, Role::admin,
                 schema({{"name", name_arg()},
                         {"from", prop("string", "The existing file, relative to the site's directory, e.g. wp-content/plugins/sqlite-database-integration/db.copy.")},
                         {"to", prop("string", "The destination file, relative to the site's directory, e.g. wp-content/db.php. Its directory must exist.")},
                         {"overwrite", prop("boolean", "Replace an existing destination file (default false: an existing file is refused).")},
                         {"dry_run", prop("boolean", "Run the same checks without writing; the answer shows the resolved paths, the account and the mode, or the refusal.")},
                         {"confirm", confirm_arg()},
                         {"reason", reason_arg()}},
                        {"name", "from", "to", "confirm", "reason"})});
    t.push_back({"site_task", "Run a site task", "Runs one named task of the site's preset as the site's own account, in the site's directory (its root): a fixed command from the preset's table (site_tasks_list), never a command line. For a Ruby on Rails site (app = \"rails\") a new application is made in this order: gem_install_rails (Rails into the account's own gem directory; minutes), rails_new with params {\"name\": \"...\"} (the application, with SQLite, in the empty site directory, its gems in vendor/bundle; minutes), db_prepare, assets_precompile. Later: bundle_install after the Gemfile changed or after an application was installed from an archive (site_install), db_migrate after new migrations. An application from an archive that ships no config/database.yml (only database.yml.example; Redmine) gets it from database_config: a fixed template, not a command, written as the site's account only when missing, that takes the database from DATABASE_URL in the site's environment (site_env_set it first: sqlite3:db/production.sqlite3, or postgresql://USER:PASSWORD@HOST/NAME, so the password stays out of the tree); then bundle_install, which bundles the matching driver. A Redmine site (app = \"redmine\") also has gemfile_local (a fixed Gemfile.local adding Puma, which Redmine keeps in its test group), load_default_data with params {\"lang\": \"en\"} (trackers, statuses, roles; once, after db_migrate) and plugins_migrate (after a plugin's site_install into plugins/NAME and bundle_install); its order is database_config, gemfile_local, bundle_install, db_migrate, load_default_data, assets_precompile. A Django site (app = \"django\") or a Wagtail site (\"wagtail\") runs every task in a virtualenv of its own (<home>/venvs/<site>, outside the served tree; root's python3 of [control] runtimes started under the virtualenv's name, so the packages are the site's and the program is root's): a new Wagtail site is venv_create, pip_install with params {\"packages\": \"wagtail gunicorn\"}, startproject (wagtail start, the project named by the site's project, in the empty directory), pip_install_requirements, then site_env_set with generate: [\"DJANGO_SECRET_KEY\"], django_settings (a fixed agensio_settings.py that agensio runs the project with: the project's production settings plus DEBUG off, the secret from the site's environment, ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS from the site's names, the forwarded https, https-only cookies on a TLS site, STATIC_ROOT and MEDIA_ROOT where agensio serves /static/ and /media/, DATABASES from DATABASE_URL when set, and check_deploy's warnings for what agensio does at the edge silenced only where the site has it: the https redirect, HSTS; run again, it replaces agensio's own earlier version, kept as .bak), migrate, collectstatic, then site_env_set with generate: [\"DJANGO_SUPERUSER_PASSWORD\"] and createsuperuser with params {\"username\": \"admin\", \"email\": \"...\"} (the password never passes through this conversation; site_env with reveal shows it when the user asks). check_deploy lists what the production settings still get wrong, its summary naming each warning (security.W004 on a TLS site without hsts: site_update with hsts: true). A plain Django project is the same with packages \"django gunicorn\" (its startproject runs django-admin startproject); a project from an archive starts at venv_create, pip_install_requirements and pip_install with packages \"gunicorn\". pip_install installs any package the site's account may install, named by you, so the user confirms every run in person: this bridge asks them in the client's own dialog before it sends the task, with the names and a warning to check them on pypi.org, and your confirm is not enough. Propose only packages the user asked for or the application's documentation names, spelled exactly, and say why each is needed. When the client cannot ask (no elicitation; Claude Code's VS Code extension declines every question) or the user declines, the answer carries the agensio ctl command for the user to run in a terminal on the server: show it with the warning and never retry the call. On Debian venv_create needs python3-venv (run_as_root says so). A Node site (app = \"node\") has npm_ci (npm ci --omit=dev: the dependencies exactly as the application's package-lock.json pins them, into node_modules/; their install scripts run as the site's account) and npm_run with params {\"script\": \"NAME\"} (one script of the project's package.json by name: a post-install step the application documents, such as Uptime Kuma's download-dist); npm and node come from [control] runtimes.node, npm's cache and configuration are the account's own. The interpreter comes from [control] runtimes in root's file (ruby, gem and bundle in /usr/bin by default) and must be root's; when it is missing the answer carries run_as_root with the package command: show it, say the task waits for it, continue when the user ran it. The answer reports the exact argv that ran, the account, the directory, the exit status, the duration, a summary when the output has one (the migrations applied, Bundle complete!, the files now in public/assets) and a part of the program's output: on success its last 4 KB, on a failure its first 4 KB and last 12 KB, with truncated: true when it printed more; site_task_output reads the rest in slices, only when the part shown does not explain the result. Read the output to explain a failure and fix its cause, then run the task again. After a task that changes what a running application loads (bundle_install, db_migrate, db_prepare, plugins_migrate, assets_precompile), next_steps carries the root line that restarts its service. A task that needs an earlier one's result is refused before it runs, dry run included, naming the missing file and what to run (rails_new needs the rails command gem_install_rails installs; the bundle tasks need the application's Gemfile); a task that exits 0 without leaving what the next one needs answers 409 saying so. The account's gems are its own: gems root installed system-wide are invisible to the tasks. A task is stopped at its time limit ([control] task_limits.timeout, 20 minutes by default); one task per site at a time (409 names the running one). Credential files the task wrote (config/master.key, config/database.yml, storage/ with the SQLite databases, .env) are made the site's alone and listed under secured, and the configuration is validated before the answer. dry_run: true shows the argv, account, directory, environment and limits without running anything. Every task also gets the site's environment (site_env: SECRET_KEY_BASE, DATABASE_URL and the like) after the variables agensio sets, shown as NAME=<site environment>, never the value. A failure with a known cause carries hint: a Rails application without credentials that stops on \"Missing secret_key_base\" (site_env_set with generate: [\"SECRET_KEY_BASE\"], then run the task again), a Gemfile that pins another Ruby than [control] runtimes gives (root installs that Ruby under /opt and points runtimes at it; agensio reload applies it), no config/database.yml (database_config). bundle_install that exits 0 while the application says it found no database configuration answers 409, since that bundle has no database driver. No task starts the application server (Puma, Gunicorn): until agensio manages it, site_service_unit renders the site's systemd unit (its account, directory, upstream port and the runtime of [control] runtimes) with the root commands that install it, site_service_status tells whether it runs and site_service_logs why it does not.", "POST", "/v1/sites/{name}/task", false, true, Role::admin,
                 schema({{"name", name_arg()},
                         {"task", task_enum()},
                         {"params", task_params_schema()},
                         {"dry_run", prop("boolean", "Report the exact argv, the account, the directory, the environment and the limits without running anything; a refusal (missing interpreter, a directory that is not empty) shows as it would for real.")},
                         {"confirm", confirm_arg()},
                         {"reason", reason_arg()}},
                        {"name", "task", "confirm", "reason"})});
    t.push_back({"site_env", "Show a site's environment", "The application environment of a site with app = \"rails\", \"redmine\", \"django\", \"wagtail\", \"node\" or \"proxy\": the variables its site tasks and its application service get (SECRET_KEY_BASE, DJANGO_SECRET_KEY, DATABASE_URL, an API key), from the site's environment file (root's, 0600, <directory of the main configuration>/env/<site>.env, read by the root helper). Each variable comes with its name, its length and a fingerprint (16 hex digits of a keyed hash: the same fingerprint means the same value, so 'is it the same secret?' is answered without showing it), and no value. A value is returned only for the names in reveal, and reveal is used only when the user explicitly asked to see that value: never to check that a name is set, never 'to be sure', never for more names than asked; each revealed value is recorded in the audit log as a secret read, and once shown it is in this conversation. exists: false means the site has no file yet (site_env_set creates it). Admin only; every call is audited with the names returned. site_env_set changes them.", "GET", "/v1/sites/{name}/env", true, false, Role::admin,
                 schema({{"name", name_arg()},
                         {"reveal", json::Value::object().set("type", "array").set("items", prop("string", "a variable's name"))
                                        .set("description", "Names whose values to return, only when the user explicitly asked to see them; omit it otherwise.")}},
                        {"name"})});
    t.push_back({"site_env_set", "Change a site's environment", "Sets, removes or generates variables of a site's application environment (app = \"rails\", \"redmine\", \"django\", \"wagtail\", \"node\" or \"proxy\"): the file its site tasks and its application service read, root's and 0600, written by the root helper. set: {NAME: value} adds or replaces; unset: [NAME] removes; generate: [NAME] puts a random 128-hex-digit secret under a name that is missing and keeps an existing one (to rotate, give the name in both unset and generate; a new SECRET_KEY_BASE signs every user out and invalidates signed links). A Rails application without credentials (config/credentials.yml.enc; every ONCE application such as Writebook, every Kamal deployment) reads SECRET_KEY_BASE from here: site_install generates it once for an archive that came without credentials, and when a task fails with \"Missing secret_key_base\" its answer says to generate it. A Django or Wagtail site reads DJANGO_SECRET_KEY (generate it before django_settings; site_install generates it for a project from an archive) and its first admin's password DJANGO_SUPERUSER_PASSWORD (generate it before createsuperuser, so the password never passes through this conversation). Names: upper-case letters, digits and _, never one agensio sets or one that changes which program runs (PATH, HOME, RAILS_ENV, GEM_*, BUNDLE_* except a gem source's credentials such as BUNDLE_GEMS__CONTRIBSYS__COM, LD_*, RUBYOPT, NODE_OPTIONS, NPM_CONFIG_*, GIT_*, PYTHON*, PIP_*, VIRTUAL_ENV, DJANGO_SETTINGS_MODULE, AGENSIO_*; on a Node site also HOST, PORT and NODE_ENV, which the unit sets): those are refused with the reason. Values: one line of UTF-8, at most 4 KB. The answer and the audit log carry names only; still_exposed names the values that still hold what others could read (a value set to itself, or the ones not rotated yet): tell the user they still need new values. The tasks read the file from their next run; the application reads it when its service restarts (the unit site_service_unit renders loads it with EnvironmentFile=), which is a root step until agensio manages the service: give the user the systemctl restart line from next_steps.", "POST", "/v1/sites/{name}/env", false, false, Role::admin,
                 schema({{"name", name_arg()},
                         {"set", json::Value::object().set("type", "object").set("additionalProperties", json::Value::object().set("type", "string"))
                                     .set("description", "Variables to add or replace, NAME: value, e.g. {\"DATABASE_URL\": \"postgres://...\"}.")},
                         {"unset", json::Value::object().set("type", "array").set("items", prop("string", "a variable's name")).set("description", "Names to remove.")},
                         {"generate", json::Value::object().set("type", "array").set("items", prop("string", "a variable's name"))
                                          .set("description", "Names to fill with a new random secret when missing, e.g. [\"SECRET_KEY_BASE\"]; an existing value is kept unless the name is also in unset.")},
                         {"confirm", confirm_arg()},
                         {"reason", reason_arg()}},
                        {"name", "confirm", "reason"})});
    // A managed site's password users (2026-10-09, design section 25, step 4b).
    t.push_back({"site_auth_users", "List a site's password users",
                 "The users who may log in where a managed site asks for a password ([[site.auth]], docs/configuration.md 19b), from the site's users file "
                 "(<directory of the main configuration>/auth/<site>.users: root's, the server's group, 0640, read by the root helper). Each user with name, "
                 "method (the hash's kind: yescrypt for every password these tools make), expires (YYYY-MM-DD: from that day, UTC, the login is refused) and "
                 "expired, note (whose login it is) and locked (every login refused, the password kept); never a hash. used says whether a [[site.auth]] "
                 "rule of the running configuration reads the file: until one does, nobody is asked for these passwords. Admin only; every read is audited "
                 "with the names. A hand-written site is refused: its rules name their own files, root's.",
                 "GET", "/v1/sites/{name}/auth-users", true, false, Role::admin, schema({{"name", name_arg()}}, {"name"})});
    t.push_back({"site_auth_user_set", "Add or change a site's password user",
                 "Adds a user to a managed site's password file, or changes one. generate: true gives the user a new password made by the server (sixteen "
                 "lower-case letters and digits in four groups, xxxx-xxxx-xxxx-xxxx, nothing that looks alike), answered in password this one time and kept "
                 "nowhere: relay it to the user once, with the user name, and never repeat it later in the conversation or write it into a file, a ticket or "
                 "a commit; a lost password is replaced with generate again, never recovered, and the old one stops working at once. A password is never an "
                 "argument: when the user wants to choose their own, give them the command agensio ctl site-auth-user-set SITE USER --prompt --yes --reason "
                 "\"...\" to run on the server, which asks on their terminal and sends only its hash. A new user needs generate. expires: YYYY-MM-DD, from "
                 "that day (UTC) the login is refused, for a contractor or a client's review; \"\" removes it. note: whose login it is (\"Anna, Acme\"); "
                 "\"\" removes it. locked: true refuses every login of the user and keeps the password, locked: false gives it back: the reversible "
                 "alternative to site_auth_user_delete. User names: 1 to 64 letters, digits and . _ @ + -, starting with a letter or a digit. Ask the user "
                 "for the name, and for an end date when the access is temporary, before calling. When a [[site.auth]] rule reads the file the server "
                 "reloads at once (done says so) and a login remembered with an old password stops matching; until a rule reads it, nobody is asked. The "
                 "audit log names the user and what changed, never a password or a hash.",
                 "POST", "/v1/sites/{name}/auth-users", false, false, Role::admin,
                 schema({{"name", name_arg()},
                         {"user", prop("string", "The user name, e.g. anna or anna@acme.example.")},
                         {"generate", prop("boolean", "true: a new password made by the server, answered once (required for a new user).")},
                         {"expires", prop("string", "YYYY-MM-DD: refused from that day (UTC); \"\" for no end.")},
                         {"note", prop("string", "Whose login it is, one line of up to 200 bytes; \"\" removes it.")},
                         {"locked", prop("boolean", "true: every login refused, the password kept; false: the password works again.")},
                         {"confirm", confirm_arg()},
                         {"reason", reason_arg()}},
                        {"name", "user", "confirm", "reason"})});
    t.push_back({"site_auth_user_delete", "Remove a site's password user",
                 "Removes a user from a managed site's password file. When a [[site.auth]] rule reads the file the server reloads and the user's next "
                 "request is refused; the last user of a file a rule reads is kept (lock it with site_auth_user_set locked: true instead). Locking is the "
                 "reversible way: prefer it when the user may come back.",
                 "POST", "/v1/sites/{name}/auth-users/delete", false, true, Role::admin,
                 schema({{"name", name_arg()}, {"user", prop("string", "The user name to remove.")}, {"confirm", confirm_arg()}, {"reason", reason_arg()}},
                        {"name", "user", "confirm", "reason"})});
    t.push_back({"site_service_unit", "Render a site's application unit", "The systemd unit that runs a Rails or Redmine site's Puma, a Django or Wagtail site's Gunicorn, or a Node site's node, until agensio manages it itself: rendered from the site (its account, its directory, the loopback port of its upstream, a Django site's project and names, a Node site's entry with HOST and PORT), the runtime of [control] runtimes (the Ruby its bundle was built with; the python3 whose virtualenv the site has, started under the virtualenv's name; root's node) and its environment file, never from anything the caller gives. A Django unit loads agensio_settings (django_settings) and keeps DJANGO_SUPERUSER_PASSWORD from the application (UnsetEnvironment=). The answer carries the unit's text and run_as_root: `agensio ctl site-unit NAME --raw > /etc/systemd/system/agensio-app-USER.service`, `systemctl daemon-reload`, `systemctl enable --now ...`. That is root's step: show the commands, say the site waits for them, and continue when the user ran them. The unit runs the application server as the site's account with the tasks' environment, never as root. Refused with the reason for a site without its own account, or whose upstream is not http on loopback. After a change of the runtime in [control] runtimes, or of a Django site's names (an alias), root renders and installs it again.", "GET", "/v1/sites/{name}/unit", true, false, Role::viewer, schema({{"name", name_arg()}}, {"name"})});
    t.push_back({"site_service_status", "Show a site's service state", "Whether the application service of a Rails, Redmine, Django, Wagtail or Node site runs: its unit (agensio-app-USER.service, the one site_service_unit renders) as systemd reports it, read by the root helper with systemctl show: LoadState (not-found when root has not installed it), ActiveState and SubState, Result and ExecMainStatus of a failure, since when, its main pid, memory, restart count and whether it starts at boot, with summary and next_steps. Use it when the site answers 502, after root installed or restarted the unit, and before telling the user the application is up. Failed or stopped: site_service_logs shows why; starting, stopping and restarting the unit is root's (systemctl), never a tool's, so give the line from next_steps and continue when the user ran it. health_check reports every such site whose service is missing, stopped or failing. 503 with busy: the helper is running a task or an install, ask again after it. 409 for a site without its own account or of another preset, and on a server without the provisioning helper (agensio not started as root).", "GET", "/v1/sites/{name}/service", true, false, Role::viewer, schema({{"name", name_arg()}}, {"name"})});
    t.push_back({"site_service_logs", "Read a site's service journal", "The last lines of a Rails, Redmine, Django, Wagtail or Node site's application service journal (journalctl -u agensio-app-USER.service, run by the root helper with fixed arguments; the unit comes from the site's account, never from the call): the server's start-up lines (Puma, Gunicorn), the exception that stopped it, 'Address already in use', a missing gem or module, a database it cannot open. Use it when site_service_status or health_check says the service failed or is stopped, and after a restart to see that it booted. Summarise the cause for the user and quote the few lines that show it; do not paste the journal. The site's own requests and 502s are in logs_query, not here. Admin only and every read audited, since an application may print what it should not. Same refusals as site_service_status.", "GET", "/v1/sites/{name}/service/logs", true, false, Role::admin,
                 schema({{"name", name_arg()},
                         {"lines", prop("integer", "How many of the newest lines, 1 to 1000 (default 200).")},
                         {"since", prop("string", "Only lines from this far back: a number and s, m, h or d, e.g. 30m, 3h, 2d (default: no bound).")}},
                        {"name"})});
    t.push_back({"site_task_output", "Read a site task's whole output", "The whole output of the site's last task, in slices: site_task answers with a summary and a part of the output (on success the last 4 KB, on a failure the first 4 KB and the last 12 KB) and truncated: true when it cut something. Read more only when that part does not explain the result, and look for the lines that do instead of relaying the output. offset is where to start, the previous answer's next_offset for the next slice (null when there is no more); length up to 65536 (the default). The output is kept per site until its next task or a restart of agensio; a task keeps at most 1 MB of what it printed, its first 256 KB and last 768 KB (kept_all: false when it printed more). Admin only, like the task.", "GET", "/v1/sites/{name}/task-output", true, false, Role::admin,
                 schema({{"name", name_arg()},
                         {"offset", prop("integer", "Byte offset to start at (default 0; the previous answer's next_offset).")},
                         {"length", prop("integer", "Bytes to return, at most 65536 (the default).")}},
                        {"name"})});
    return t;
}

const char* kInstructions =
    "You are connected to an agensio web server through its control socket, as the account that "
    "started this bridge. RULE ONE: whenever a tool here can do the job, do it through the tool, over this "
    "connection, and never send the user to a terminal for it. Creating and changing sites, their "
    "HTTPS, their user, their limits (settings), installing an application or a plugin, copying a drop-in, "
    "reloading, renewing a certificate, reading logs and health: all of that is tools. A terminal command "
    "or a file edit is offered only when no tool covers the change: when the server itself answers with "
    "run_as_root commands (no provisioning helper), or when config_reference says via = file (the "
    "root-owned main configuration) or via = site file (a hand-written site file). Then give the exact "
    "command or line, say why no tool can do it, and say what follows (agensio reload or a restart). "
    "On a site the tools manage, anything no field of site_update covers (a redirect, a header on one path, an alias "
    "outside the root, another upstream for a path, CGI, odd try_files) goes into the site's root additions file, which "
    "site_show names under root_additions (sites.d/<domain>.root.toml, root's, 0644: `site = \"<domain>\"` on the first "
    "line, then [[location]] tables with the keys config_reference lists for [[site.location]]): give the user the exact "
    "file content, say that only root writes it and that `agensio reload` applies it, then read the result back with "
    "site_show. Never tell the user to edit the managed site file itself: site_update regenerates it and refuses an edited one. "
    "Admin panels (WordPress, Drupal) are reachable from anywhere by default and stay so: restrict one only when the user "
    "asks, with site_update rules.admin (the preset's admin paths in one field, the login page only with login: true). "
    "Keeping another path or a whole site to some client addresses (a staging copy to the team) is rules.restricted. Either is "
    "sent with the site's other rules: ask the user for the addresses, run access_check with the user's own address before "
    "applying so they keep access, and offer mode report to try the rule first. Root's named sets (config_reference, key addresses, lists them with their entries) are named @name. Behind a "
    "CDN or another proxy the rule judges the client only when the proxy is in [server] trusted_proxies (root's main file: "
    "give the line). A user refused with 403 sees the address the server tested on the page: run access_check with it; "
    "refusals are warn lines in logs_query (access refused:, access would refuse: for a rule in report mode). "
    "Passwords ([[site.auth]], docs/configuration.md 19b): a password in front of a path is site_update rules.auth, with the "
    "site's own users. Offer it for a staging copy (path /, often with skip_for the office), a tool without a login of its "
    "own, a client's preview; never in front of a WordPress or Drupal admin unless the user asks for it (their logins are "
    "there already). The order: the site exists, site_auth_user_set adds its first user with generate: true (the "
    "password answered once: relay it to the user once with the user name and never repeat it; expires for temporary "
    "access; locked to suspend), then site_update with rules.auth (refused before a user exists, and on site_create). "
    "Free a health check or a callback below a protected path with open: true and check the result with path_check. "
    "plain_http only when the user asks for it, after telling them the password then crosses the network readable; "
    "without it a plain-HTTP request from another host gets 403. site_auth_users lists the users (never a hash), "
    "site_auth_user_delete removes one. A password is never a tool argument: a user who wants to choose their own runs "
    "agensio ctl site-auth-user-set SITE USER --prompt on the server; give them that line. A lost password is replaced, "
    "never recovered. "
    "An application without a preset of its own (presets_list has none for it: TYPO3, Kanboard, phpBB, Nextcloud) runs on "
    "app = php with the server rules its own documentation gives, never with another application's preset. Find the "
    "application's official web server configuration for the version the user runs (its nginx and Apache examples) and "
    "translate it into site_update rules: entry_points (the .php it runs), front_controller (where a missing path goes), "
    "private (directories never served) and refuse (every deny rule, as gitignore-style patterns: an nginx location ~* "
    "\\.(yaml|yml)$ { deny all; } is *.yaml and *.yml; a regex anchored as ^vendor is /vendor/ in intent, though as nginx writes "
    "it it matches nothing). Show the user the rules with the documentation you took them from, send them with dry_run, "
    "then check with path_check one path each rule must refuse and the paths that must still work (the front page, the "
    "admin, an asset), and apply only after the user agrees; check the same paths again afterwards. Anything the rules "
    "cannot express (a second front controller under a path, a redirect) belongs in root additions (see above); say so. "
    "Start a session on a server you do not know with health_check and "
    "server_status, then explain the findings in plain words and offer the usual jobs: create a "
    "site (HTTPS by default, ask about the site user and what runs there; writing its php-fpm pool reloads "
    "php-fpm, which briefly affects every PHP site on the host unless process_control_timeout is set, see "
    "health_check), inspect a site, look "
    "at recent errors, install an application into a site. Every change needs the user's explicit agreement first (confirm: true) "
    "and a one-line reason. When the server answers with commands to run as root, show them "
    "exactly, say that the server waits for them, and continue only when the user says they ran "
    "them. On a server whose helper is present, site_create does that root work itself and reports it under done. "
    "After a site exists, site_install fills it: the preset's official archive (wordpress, drupal, grav), an https URL "
    "the user names, or an archive the user uploaded with `agensio ctl upload NAME < file` (this bridge carries no files; "
    "give the user that command when the archive is on their machine, and also when the server refuses a download by its "
    "rules). The install runs as the site's account into an empty directory and refuses symlinks, private addresses and "
    "oversize archives, leaving nothing behind on a refusal; report the source and sha256 it answers with. "
    "site_install and site_copy make the preset's credential files 0600 and validate the configuration "
    "before answering; a 409 with written: true means the files are there but health lists what to fix. "
    "A plugin or theme goes into its own directory with site_install's path and create_path; a drop-in file an "
    "application ships as a template (WordPress's wp-content/db.php from the SQLite plugin's db.copy, Drupal's "
    "settings.php) is put in place with site_copy, which copies one file within the same site and nothing else. "
    "A Ruby on Rails site is app = \"rails\" (root: the project directory, suggested <sites_root>/<domain>/app; upstream: "
    "where Puma listens, on loopback). Its application is made and prepared with site_task, the preset's named commands "
    "run as the site's account in that directory (site_tasks_list shows them): gem_install_rails, rails_new, db_prepare, "
    "assets_precompile; bundle_install and db_migrate later. An existing Rails application comes with site_install (an "
    "https archive such as a GitHub release tarball, or an upload), then site_task bundle_install, db_prepare, "
    "assets_precompile. A task's answer carries its output and, for a known cause, a hint: read both to explain a "
    "failure. An application's secrets and settings (SECRET_KEY_BASE, DATABASE_URL, API keys) go into the site's "
    "environment with site_env_set, never into a file of the application and never into a unit file by hand: the "
    "tasks and the application's service read that file (site_env shows names, lengths and fingerprints; a value only "
    "with reveal, and reveal only when the user asks to see that value). No tool runs any other command, so never offer one, and never ask the user for a shell command a task "
    "covers. Redmine is app = \"redmine\": site_install with version and sha256, site_env_set DATABASE_URL, then site_task "
    "database_config, gemfile_local, bundle_install, db_migrate, load_default_data, assets_precompile. A Django project is "
    "app = \"django\" and a Wagtail site app = \"wagtail\" (root: the project directory, where manage.py lives; project: "
    "its Python package, which site_create asks for; upstream: where Gunicorn listens, on loopback). agensio serves their "
    "/static/ and /media/ from the project directory and sends the rest to Gunicorn; the tasks run in a virtualenv of the "
    "site's own: a new Wagtail site is site_task venv_create, pip_install with packages \"wagtail gunicorn\", startproject, "
    "pip_install_requirements, site_env_set generate DJANGO_SECRET_KEY, django_settings, migrate, collectstatic, site_env_set "
    "generate DJANGO_SUPERUSER_PASSWORD, createsuperuser (username and email as params). A Node application is app = \"node\" "
    "(root: the project directory, where package.json lives; entry: the file node runs, which site_install's facts guess; "
    "upstream: on loopback): site_install its release archive, site_task npm_ci, then the post-install steps it documents "
    "through npm_run (Uptime Kuma: download-dist), site_update with entry, then site_service_unit; the unit runs root's node on "
    "the entry with HOST and PORT from the upstream, which the site's environment cannot override. An application that creates "
    "its admin in the browser on the first visit (Uptime Kuma) is claimed by whoever opens it first: tell the user to open it "
    "as soon as the service starts. pip_install takes any package, so the "
    "user confirms each run in a dialog this bridge opens in the client (not through you); where the client cannot show it, "
    "give the user the terminal command the answer carries. The admin's password stays in the site's "
    "environment: tell the user it is there and reveal it only when they ask. The application server (Puma, Gunicorn) is not "
    "started by a tool yet: site_service_unit renders the site's systemd unit with the root commands that install it (it "
    "loads the site's environment file and runs the runtime of [control] runtimes), the one step left for a terminal; say "
    "so, with its restart after an environment change or after a task that changes the application (the task's next_steps "
    "carry the line). site_service_status says whether that service runs and site_service_logs shows its journal when it "
    "does not (a 502 from a Rails or Django site starts there); health_check lists every such site whose service is missing, stopped "
    "or failing. A task's answer is a summary and a part of its output; site_task_output reads the rest when needed. "
    "An application with its own server guidelines and no preset (Kanboard, a plain PHP application) runs under app = php with "
    "the site's rules (site_update's rules object): private paths from its documentation and from the .htaccess files "
    "site_install found, the entry points it names, its cached asset directories, a front controller for nice URLs. Every "
    "rule only narrows what is served, so apply what the application documents and nothing it does not. "
    "Protection of the host (docs/configuration.md 18) is split: the server owns its timeouts, protocol budgets and the "
    "connection ceiling; per-address limits on the web ports belong to the kernel's firewall and brute force on logins to "
    "fail2ban over the access logs. protection_show renders both for this host (an nftables table of its own that touches "
    "nothing else, fail2ban jails with the sites' login paths and, from the error log, their failed passwords) with root's commands: a firewall trial that undoes itself "
    "in ten minutes, then the keep step; and it reads back what is in place. health_check reports firewall_limits_missing and "
    "fail2ban_missing on a public host until they are; a panel's own limits count. When the user asks about rate limiting, "
    "brute force or bots, start there; for a site whose preset does not know its login path, ask the user and set "
    "login_paths with site_update before rendering the jail. "
    "Deleting a site: site_delete without files removes the configuration alone and leaves every file; with files: true it "
    "moves the site's directory, its account's state, its logs and its environment file into root's trash, where they stay "
    "for [control] trash_keep days (60 by default) and site_restore brings them back into an empty place; ask the user "
    "which they mean, and never use trash_delete unasked. A site whose application service runs must be stopped by root "
    "first (the answer carries the lines). "
    "Per-site limits (upload size, PHP memory, execution time, pool size) are changed with site_update's settings "
    "object; call site_settings_list first for the keys, units, current values and the ceilings root set. A request "
    "body above a site's max_body_size (1 MB unless set) is refused with 413 before the application sees it, and the "
    "error log names the site, the size and the limit: an upload that fails that way is fixed with settings "
    "{max_body_size}, and site_create's next_steps state the limit so the user knows it before the first upload. "
    "For any other key (workers, cache sizes, log level, timeouts, the control plane's own keys) call "
    "config_reference: it says what the key does, its running value, whether the change needs a reload or a "
    "restart, and which tool changes it. Only when via is file is there no tool: the main configuration file "
    "is root's and agensio never edits it, so answer with the exact line to set, the file, and the reload or "
    "restart command, exactly like the root commands protocol; never claim to have changed it. "
    "HTTP/2 is on for every TLS site (ALPN) with nothing to configure per site; [server] protocols = "
    "[\"h1\"] switches it off server-wide (root's file, via = file, then agensio reload), for instance "
    "while a client misbehaves; h2c in that list accepts prior-knowledge HTTP/2 on plain listeners for "
    "backends and load tools; h3 in that list adds HTTP/3 over QUIC on every TLS listener's port (UDP, a build "
    "with OpenSSL 3.5 on Linux; the firewall must pass UDP on that port). A host under a QUIC handshake flood "
    "sets [server] http3 = { retry = \"always\" } (root's file, then reload): every new HTTP/3 client then "
    "proves its address with a Retry round trip before it gets a connection; the default \"auto\" does that "
    "only once a worker has 512 handshakes in progress, and \"never\" is for benchmarks. Browsers find HTTP/3 "
    "through the alt-svc field every HTTP/1 and HTTP/2 answer of such a listener carries (http3 = { alt_svc = "
    "false } removes it; nothing else is needed). The startup line in the error log says when the kernel "
    "capped the QUIC sockets' buffers (net.core.rmem_max, 208 KB untuned): a root sysctl no tool changes; "
    "give the two commands of docs/configuration.md 17 when a site expects bursts of new HTTP/3 "
    "connections. Uploads are not "
    "slower over HTTP/2 here (windows follow the site's body limit), "
    "and the error log carries an info line for every GOAWAY or RST_STREAM the server sends, naming the "
    "client, the stream and the reason, which is where to look when a user reports HTTP/2 trouble. "
    "If an answer carries a NOTE that this bridge and the server are different versions (in its text, or as bridge.note in the structured answer), tell the user at once and how to fix it (reconnect the MCP server, or restart agensio): tools may be missing and descriptions out of date until then. "
    "Never invent settings: what a tool does not offer is not configurable here. Host names are "
    "strict: a site answers only the names in server_name, and a listener without a catch-all site "
    "(server_name [\"*\"] or default = true) answers 421 to any other Host, including the IP address; and on "
    "TLS a connection answers only the names its certificate covers, so a request that reaches one site's "
    "certificate with another site's Host is 421 too. When a user reports 421, one of those is the cause.";

const char* kGettingStarted =
    "Greet the administrator briefly. Remember rule one: what a tool can do is done here, through the tool; "
    "a terminal is for what no tool covers. Run health_check and server_status. Summarise: how many "
    "sites, which have certificates and their state, anything the health check flagged (with its "
    "fix), whether the server runs under a service user, and whether the host's firewall limits and fail2ban jail are in "
    "place (firewall_limits_missing, fail2ban_missing: protection_show has root's commands, trial first). Then offer the next jobs: add a site, "
    "check a site's logs for errors, renew a certificate, reload after a manual edit. Keep it "
    "short and ask what they want to do.";

const char* kNewSite =
    "Create a website step by step. Ask for the domain (and whether www. should be included as "
    "an alias). Call site_create with only the domain first: the server lists the open decisions "
    "with a suggestion each. Ask the user each question in turn: HTTPS (recommend auto, which "
    "needs port 80 reachable and the name pointing at this server), whether the site gets its own "
    "system user (recommend yes, suggest the proposed name), what runs there (presets_list: a PHP "
    "application's preset, rails, redmine, django, wagtail, proxy for any other application server, or static; a Django or Wagtail site also needs "
    "its project's package name) and where the files are. Call site_create again with every "
    "field and confirm: true only after the user agreed. If the server returns commands to run "
    "as root, show them verbatim and wait. After success, show next_steps and check with "
    "site_show that the certificate arrives. When the site's app has an official archive (presets_list, "
    "source) offer to install it now with site_install; for other applications ask whether the user has "
    "an https URL of the archive or wants to upload it with agensio ctl upload. An application presets_list does not name "
    "(TYPO3, Kanboard, phpBB) gets app = php, then its own documented server configuration as site_update rules, checked "
    "with path_check before and after (see the server instructions). The admin panel stays open to everyone unless "
    "the user wants it kept to their office or VPN: then rules.admin (WordPress, Drupal) or rules.restricted for a staging "
    "copy; ask for the addresses and check the user's own with access_check before applying.";

}  // namespace

std::string version_mismatch_note(std::string_view bridge, std::string_view server) {
    if (server.empty() || server == bridge) return "";
    return "NOTE: this MCP bridge is agensio " + std::string(bridge) + " and the server runs " + std::string(server) +
           ". The tools, their options and these texts are the bridge's own, so tools the other version has may be missing here and "
           "descriptions may be wrong. Tell the user now: either the bridge started before an upgrade (reconnect this MCP server "
           "in the agent host, so a new `agensio mcp` starts), or the server was not restarted after one (as root: systemctl restart "
           "agensio). Until then trust the server's answers over these descriptions.";
}

namespace {

class Mcp {
public:
    Mcp(std::string socket, std::istream& in, std::ostream& out) : socket_(std::move(socket)), in_(in), out_(out), tools_(tools()) {
        ControlReply reply;
        std::string error;
        if (control_request(socket_, "GET", "/v1/status", "", reply, error) && reply.status == 200) {
            json::Value v;
            if (json::parse(reply.body, v, error)) {
                server_version_ = std::string(v.get("version"));
                const std::string_view role = v["peer"].get("role");
                role_ = role == "admin" ? Role::admin : role == "operator" ? Role::operator_ : role == "viewer" ? Role::viewer : Role::none;
            }
        } else {
            unreachable_ = error.empty() ? "control socket answered HTTP " + std::to_string(reply.status) : error;
            role_ = Role::viewer;  // list the read tools so the agent can retry once the server is up
        }
    }

    void handle(const std::string& line) {
        json::Value msg;
        std::string err;
        if (!json::parse(line, msg, err) || !msg.is_object()) {
            send(json::Value::object().set("jsonrpc", "2.0").set("id", json::Value(nullptr))
                     .set("error", json::Value::object().set("code", -32700).set("message", "parse error: " + err)));
            return;
        }
        const std::string_view method = msg.get("method");
        const json::Value& id = msg["id"];
        const json::Value& params = msg["params"];
        if (id.is_null()) return;  // a notification (initialized, cancelled): nothing to answer
        if (method == "initialize") {
            // Whether the client can put a question to its user (MCP elicitation): pip_install asks
            // there, and without it hands the user a terminal command instead.
            can_elicit_ = params["capabilities"]["elicitation"].is_object();
            client_ = std::string(params["clientInfo"].get("name"));
            if (const std::string_view v = params["clientInfo"].get("version"); !v.empty()) client_ += " " + std::string(v);
            json::Value caps = json::Value::object();
            caps.set("tools", json::Value::object().set("listChanged", false));
            caps.set("prompts", json::Value::object().set("listChanged", false));
            std::string instructions = kInstructions;
            if (const std::string note = version_mismatch_note(AGENSIO_VERSION, server_version_); !note.empty()) instructions += " " + note;
            if (!unreachable_.empty())
                instructions += " NOTE: the control socket is not reachable right now (" + unreachable_ +
                                "); tell the user, and that the server must run with [control] enabled and this account must have a role.";
            result(id, json::Value::object().set("protocolVersion", kProtocol).set("capabilities", std::move(caps))
                           .set("serverInfo", json::Value::object().set("name", "agensio").set("version", AGENSIO_VERSION))
                           .set("instructions", instructions));
        } else if (method == "ping") {
            result(id, json::Value::object());
        } else if (method == "tools/list") {
            json::Value list = json::Value::array();
            for (const auto& t : tools_) {
                if (t.needs > role_) continue;  // a viewer never sees the mutating tools
                json::Value v = json::Value::object().set("name", t.name).set("title", t.title).set("description", t.description).set("inputSchema", t.schema);
                v.set("annotations", json::Value::object().set("title", t.title).set("readOnlyHint", t.read_only)
                                         .set("destructiveHint", t.destructive).set("idempotentHint", t.read_only).set("openWorldHint", false));
                list.push(std::move(v));
            }
            result(id, json::Value::object().set("tools", std::move(list)));
        } else if (method == "tools/call") {
            call(id, params);
        } else if (method == "prompts/list") {
            json::Value list = json::Value::array();
            list.push(json::Value::object().set("name", "getting_started").set("title", "Getting started").set("description", "Greet, check the server's health and offer the usual jobs."));
            list.push(json::Value::object().set("name", "new_site").set("title", "Create a website").set("description", "Guide the user through creating a site: HTTPS, its own user, what runs there."));
            result(id, json::Value::object().set("prompts", std::move(list)));
        } else if (method == "prompts/get") {
            const std::string_view name = params.get("name");
            const char* text = name == "getting_started" ? kGettingStarted : name == "new_site" ? kNewSite : nullptr;
            if (!text) {
                error(id, -32602, "unknown prompt");
                return;
            }
            json::Value msgs = json::Value::array();
            msgs.push(json::Value::object().set("role", "user").set("content", json::Value::object().set("type", "text").set("text", text)));
            result(id, json::Value::object().set("messages", std::move(msgs)));
        } else {
            error(id, -32601, "method not found: " + std::string(method));
        }
    }

private:
    void call(const json::Value& id, const json::Value& params) {
        const std::string_view name = params.get("name");
        const json::Value& args = params["arguments"];
        const Tool* tool = nullptr;
        for (const auto& t : tools_)
            if (name == t.name) tool = &t;
        if (!tool || tool->needs > role_) {
            error(id, -32602, "unknown tool: " + std::string(name));
            return;
        }
        std::string path = tool->path;
        std::string path_arg;  // the argument that fills the path: a site name or an upload name
        if (name == "site_settings_list" && !args.get("name").empty()) {
            const std::string site(args.get("name"));
            if (site.find('/') != std::string::npos) {
                tool_error(id, "the 'name' argument must be a site's host name");
                return;
            }
            path = "/v1/sites/" + site + "/settings";
        }
        for (const char* key : {"name", "file", "entry"}) {
            const std::string token = std::string("{") + key + "}";
            const std::size_t brace = path.find(token);
            if (brace == std::string::npos) continue;
            const std::string v(args.get(key));
            if (v.empty() || v.find('/') != std::string::npos) {
                tool_error(id, std::string("the '") + key + "' argument is required: " + (token == "{name}" ? "the site's host name" : "the upload's name"));
                return;
            }
            path.replace(brace, token.size(), v);
            path_arg = key;
        }
        std::string body;
        if (tool->method == std::string_view("POST")) {
            json::Value b = json::Value::object();
            // user_confirmed and client are the bridge's to set, after the user's own answer; an
            // argument of that name from the agent is dropped.
            for (const auto& m : args.members())
                if (m.first != path_arg && m.first != "user_confirmed" && m.first != "client" && !(name == "site_auth_user_set" && m.first == "hash"))
                    b.set(m.first, m.second);  // a hash comes from agensio ctl --prompt on the user's terminal, never through the agent
            if (name == "site_task" && tasks::needs_user_confirmation(args.get("task")) && !args["dry_run"].boolean()) {
                std::string refusal;
                if (!ask_user(args, refusal)) {
                    tool_error(id, refusal);
                    return;
                }
                b.set("user_confirmed", "mcp").set("client", client_);
            }
            body = b.dump();
        } else if (name == "logs_query" || name == "site_service_logs" || name == "site_task_output" || name == "access_check" || name == "path_check") {
            // Query arguments, each percent-encoded; the server checks their values.
            std::string q;
            const std::vector<const char*> keys = name == "logs_query"          ? std::vector<const char*>{"site", "since", "level", "status", "limit"}
                                                  : name == "site_service_logs" ? std::vector<const char*>{"lines", "since"}
                                                  : name == "access_check"      ? std::vector<const char*>{"path", "address"}
                                                  : name == "path_check"        ? std::vector<const char*>{"path"}
                                                                                : std::vector<const char*>{"offset", "length"};
            for (const char* k : keys) {
                const json::Value& v = args[k];
                if (v.is_null()) continue;
                std::string text = v.is_string() ? std::string(v.str()) : std::to_string(static_cast<long>(v.num()));
                std::string enc;
                for (char c : text) {
                    if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_' || c == ':') enc.push_back(c);
                    else { char h[4]; std::snprintf(h, sizeof h, "%%%02X", static_cast<unsigned char>(c)); enc += h; }
                }
                q += (q.empty() ? "?" : "&") + std::string(k) + "=" + enc;
            }
            path += q;
        } else if (name == "site_env" && args["reveal"].is_array()) {
            std::string names;
            for (const auto& n : args["reveal"].items()) {
                if (!n.is_string() || n.str().empty() || n.str().find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != std::string::npos) {
                    tool_error(id, "reveal takes variable names (letters, digits, _)");
                    return;
                }
                names += (names.empty() ? "" : ",") + std::string(n.str());
            }
            if (!names.empty()) path += "?reveal=" + names;
        }
        ControlReply reply;
        std::string err;
        if (!control_request(socket_, tool->method, path, body, reply, err)) {
            tool_error(id, "cannot reach the control socket: " + err);
            return;
        }
        json::Value parsed;
        const bool is_json = json::parse(reply.body, parsed, err);
        json::Value content = json::Value::array();
        // The server's version rides on every answer: a bridge left running across an
        // upgrade says so on the next call, first in the text and inside the structured
        // answer too, since a host that shows structuredContent never shows the text
        // (2026-09-27 report: Claude Code, a bridge left on alpha.26, the note never seen).
        const std::string note = version_mismatch_note(AGENSIO_VERSION, reply.version);
        if (!note.empty()) content.push(json::Value::object().set("type", "text").set("text", note));
        content.push(json::Value::object().set("type", "text").set("text", reply.body));
        json::Value r = json::Value::object().set("content", std::move(content)).set("isError", reply.status >= 400);
        if (is_json && parsed.is_object()) {
            if (!note.empty())
                parsed.set("bridge", json::Value::object().set("version", AGENSIO_VERSION).set("server", reply.version).set("note", note));
            r.set("structuredContent", parsed);
        }
        result(id, std::move(r));
    }

    // pip_install (2026-09-28, the owner's decision): the user confirms it in person, in the client's
    // own dialog (MCP elicitation), which the model can neither see nor answer. False with the
    // refusal (a bad value, a client that cannot ask, a no) and the terminal command for the user.
    bool ask_user(const json::Value& args, std::string& refusal) {
        const std::string site(args.get("name")), task(args.get("task"));
        const json::Value& params = args["params"];
        const std::string packages(params.get("packages"));
        for (const auto& r : tasks::rows())
            if (r.user_confirm && task == r.name)
                if (const std::string bad = tasks::check_params(r, params); !bad.empty()) {
                    refusal = bad;
                    return false;
                }
        std::string account, venv;
        {
            ControlReply reply;
            std::string err;
            json::Value v;
            if (site.find('/') == std::string::npos && control_request(socket_, "GET", "/v1/sites/" + site + "/tasks", "", reply, err) && reply.status == 200 &&
                json::parse(reply.body, v, err)) {
                account = std::string(v.get("runs_as"));
                venv = std::string(v.get("virtualenv"));
            }
        }
        const std::string warning = tasks::confirmation_warning(site, packages, account, venv);
        std::string given;
        for (const auto& m : params.members()) given += " --param '" + m.first + "=" + std::string(m.second.str()) + "'";
        const std::string terminal = "agensio ctl site-task " + site + " " + task + given + " --yes --reason \"...\"";
        const std::string fallback = " The user can run it in a terminal on the server instead, where agensio ctl shows the same warning and "
                                     "typing the command is the confirmation: " + terminal + ". Show the user that command and the warning: " + warning;
        if (!can_elicit_) {
            refusal = task + " runs only when the user confirms it in person, and this MCP client cannot ask them (it announced no elicitation "
                      "support; Claude Code's desktop app does not ask, its VS Code extension declines every question without showing it)." + fallback;
            return false;
        }
        const std::string rid = "agensio-confirm-" + std::to_string(++asked_);
        json::Value schema = json::Value::object().set("type", "object")
                                 .set("properties", json::Value::object().set("install", json::Value::object()
                                                                                          .set("type", "boolean").set("title", "Install these packages")
                                                                                          .set("description", "I checked the names on pypi.org").set("default", false)))
                                 .set("required", json::Value::array().push("install"));
        send(json::Value::object().set("jsonrpc", "2.0").set("id", rid).set("method", "elicitation/create")
                 .set("params", json::Value::object().set("message", warning).set("requestedSchema", std::move(schema))));
        // The answer, by its id; whatever else arrives meanwhile is handled after this call.
        std::string line;
        while (std::getline(in_, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            json::Value msg;
            std::string err;
            if (!json::parse(line, msg, err) || !msg.is_object() || !msg["method"].is_null() || !msg["id"].is_string() || msg["id"].str() != rid) {
                pending_.push_back(line);
                continue;
            }
            const std::string action(msg["result"].get("action"));
            if (action == "accept" && msg["result"]["content"]["install"].boolean()) return true;
            refusal = !msg["error"].is_null() ? "the client could not show the question (" + std::string(msg["error"].get("message")) + ")."
                      : action == "accept"    ? "the user left \"Install these packages\" unticked, so nothing was installed."
                      : action == "decline"   ? "the user declined, or the client declined without asking them (Claude Code's VS Code extension "
                                                "declines every question), so nothing was installed."
                                              : "the user dismissed the question, so nothing was installed.";
            refusal += fallback;
            return false;
        }
        refusal = "the client closed the connection before the user answered; nothing was installed.";
        return false;
    }

public:
    // The next line to handle: one that arrived while a question was open, else the input's.
    bool next_line(std::string& line) {
        if (!pending_.empty()) {
            line = std::move(pending_.front());
            pending_.pop_front();
            return true;
        }
        return static_cast<bool>(std::getline(in_, line));
    }

private:
    void tool_error(const json::Value& id, const std::string& text) {
        json::Value content = json::Value::array();
        content.push(json::Value::object().set("type", "text").set("text", text));
        result(id, json::Value::object().set("content", std::move(content)).set("isError", true));
    }
    void result(const json::Value& id, json::Value r) {
        send(json::Value::object().set("jsonrpc", "2.0").set("id", id).set("result", std::move(r)));
    }
    void error(const json::Value& id, int code, const std::string& message) {
        send(json::Value::object().set("jsonrpc", "2.0").set("id", id)
                 .set("error", json::Value::object().set("code", code).set("message", message)));
    }
    void send(const json::Value& v) { out_ << v.dump() << '\n' << std::flush; }

    std::string socket_;
    std::istream& in_;
    std::ostream& out_;
    std::deque<std::string> pending_;
    bool can_elicit_ = false;
    std::string client_;
    unsigned asked_ = 0;
    std::vector<Tool> tools_;
    Role role_ = Role::none;
    std::string unreachable_;
    std::string server_version_;
};

}  // namespace

int run_mcp(const std::string& socket_path, std::istream& in, std::ostream& out) {
    Mcp server(socket_path, in, out);
    std::string line;
    while (server.next_line(line)) {
        if (line.empty() || line == "\r") continue;
        if (line.back() == '\r') line.pop_back();
        server.handle(line);
    }
    return 0;
}

}  // namespace agensio
