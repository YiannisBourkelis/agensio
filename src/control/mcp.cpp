#include "control/mcp.hpp"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "config.hpp"
#include "control/client.hpp"
#include "control/roles.hpp"
#include "control/settings.hpp"
#include "services/json.hpp"

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
        if (d.pool) text += " Needs a site with its own user (a generated pool).";
        props.set(d.key, p.set("description", text));
    }
    return json::Value::object().set("type", "object").set("properties", props).set("additionalProperties", false)
        .set("description", "Per-site limits, each within the ceiling [control] site_limits sets; site_settings_list shows units, defaults, current values and ceilings. A value above the ceiling is refused naming it. No other PHP ini key can be set here: extra, open_basedir and the like stay in the configuration file, root's.");
}

json::Value name_arg() { return prop("string", "The site's host name (any of its server_name values)."); }
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
        {"user", json::Value::object().set("type", json::Value::array().push("string").push("null")).set("pattern", "^[a-z_][a-z0-9_-]{0,31}$").set("description", "A system account the site runs under (isolates it from other sites): lower-case letters, digits, _ and -. Ask the user; suggest a short name derived from the domain. For no account send no_user: true (JSON null works too; the string \"null\" is refused).")},
        {"no_user", prop("boolean", "Run the site without its own system account (the server's account serves it). Use this instead of user: null when null cannot be sent. Refused together with a user value.")},
        {"group", json::Value::object().set("type", "string").set("pattern", "^[a-z_][a-z0-9_-]{0,31}$").set("description", "The account's group (default: its primary group).")},
        {"app", app_enum()},
        {"root", prop("string", "Document root (Laravel: the project directory, its public/ is served; Drupal: the project directory, its web/ is served when present). Required unless app is proxy.")},
        {"upstream", prop("string", "app = proxy: where the application listens, e.g. http://127.0.0.1:3000.")},
        {"php_socket", prop("string", "PHP without a site user: the php-fpm socket to use (unix:/path or host:port).")},
        {"php_children", prop("integer", "PHP with a site user: pool size of the generated pool (default 8); the same as settings.children.")},
        {"settings", settings_schema()},
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
    t.push_back({"server_status", "Server status", "Version, pid, uptime, workers, open connections, listeners, sites and the caller's role. Each listener names its catch_all site (the one with server_name [\"*\"] or default = true) or null: a listener with none answers 421 Misdirected Request to any Host its sites do not list, including the IP address; on TLS a connection also answers 421 for a Host the certificate it presented does not cover (each site's own certificate bounds what its connections serve; a SAN or wildcard certificate covers every site it names).", "GET", "/v1/status", true, false, Role::viewer, schema({}, {})});
    t.push_back({"sites_list", "List sites", "Every configured site with its listeners, root, app, user, redirect, whether it is the catch_all of its listener, and certificate state (issuer, days left, whether it is still the placeholder). A site answers only the names it lists unless it is the catch-all.", "GET", "/v1/sites", true, false, Role::viewer, schema({}, {})});
    t.push_back({"site_show", "Show one site", "One site in full: effective locations after the preset expanded, PHP pool, upstreams, certificate.", "GET", "/v1/sites/{name}", true, false, Role::viewer, schema({{"name", name_arg()}}, {"name"})});
    t.push_back({"config_validate", "Validate configuration", "Loads the configuration file on disk again and runs the hosting rules; reports errors and the restart-only settings that differ from the running server.", "GET", "/v1/config/validate", true, false, Role::viewer, schema({}, {})});
    t.push_back({"logs_query", "Query logs", "Recent lines from the error log and the access logs. Use it for questions like 'any errors in the last 3 hours?'. Summarise for the user; do not paste hundreds of lines.", "GET", "/v1/logs", true, false, Role::viewer,
                 schema({{"site", prop("string", "A site's host name; omit for every site plus the error log.")},
                         {"since", prop("string", "How far back: 3h, 45m, 2d, 1w, seconds, or a local YYYY-MM-DDThh:mm:ss (default 1h).")},
                         {"level", json::Value::object().set("type", "string").set("enum", json::Value::array().push("error").push("warn").push("info")).set("description", "Error-log level filter (default warn = error and warn).")},
                         {"status", prop("string", "Access-log filter: 5xx (default), 4xx, all, or a number for that status and above.")},
                         {"limit", prop("integer", "Newest lines to return (default 200, max 5000).")}},
                        {})});
    t.push_back({"config_reference", "Configuration reference", "Every configuration key agensio reads, in one table: its table ([server], [cache], [log], [control], [[site]], php = {}, proxy = {}, [[site.location]]), type, default, meaning, whether a change applies on reload or needs a restart, who changes it (via: file = root in the main configuration file; site file; site-create = a field of site_create/site_update; settings = site_update's settings), the section of docs/configuration.md that explains it, and for server-level keys the running value and the file it comes from. Use it to answer 'how do I change X' and 'what is X set to'. Read via as which tool does it: settings and site-create mean site_update (or site_create), and you do it here; only via = file (root's main configuration) and via = site file (a hand-written site file) have no tool, and only then give the user the exact TOML line, the file, and `agensio reload` or `systemctl restart agensio` as applies says, stating that agensio does not edit that file itself. A key that is not listed does not exist.", "GET", "/v1/config/reference", true, false, Role::viewer, schema({}, {})});
    t.push_back({"site_settings_list", "Site settings", "The per-site limits site_create and site_update accept under settings, from the same table as the schema: for each key its type, unit and accepted spellings, meaning, default and where it comes from, minimum, the ceiling [control] site_limits sets (root raises it in the configuration file), what changing it costs (agensio reload, php-fpm reload) and what it derives (max_body_size drives the pool's upload_max_filesize and post_max_size). With name, also each key's current effective value and its source (site, server, default). Use it before changing a limit, and to answer 'what is this site's upload limit'.", "GET", "/v1/settings", true, false, Role::viewer,
                 schema({{"name", prop("string", "A site's host name: adds the current values. Omit for the table alone.")}}, {})});
    t.push_back({"presets_list", "Application presets", "What each `app` value does: which directory is served, whether every .php runs or only the front controller, what is refused, which directories never run PHP, which files are never served (and, the note says, refused in every backup spelling too: wp-config.php.bak, wp-config.php~, .wp-config.php.swp, wp-config.txt, so a user asking whether a backup of the credentials file is exposed can be answered without a terminal), and `source`: the official archive site_install takes when it has one (wordpress, drupal). Use it to answer 'which applications are supported', to pick app for site_create and to know whether site_install can fetch the application itself; the site_show tool shows the expanded locations of a real site.", "GET", "/v1/presets", true, false, Role::viewer, schema({}, {})});
    t.push_back({"health_check", "Health check", "What an administrator should look at: certificates, missing redirects, port 80 for ACME, recent errors, settings waiting for a restart, root, shared accounts, stale pools, php-fpm reloading without process_control_timeout (which cuts PHP requests on every site whenever a pool is written). Each finding has a severity and a fix. Run this first on a server you do not know.", "GET", "/v1/health", true, false, Role::viewer, schema({}, {})});
    t.push_back({"reload", "Reload configuration", "Validate the configuration on disk and switch to it without dropping a connection. Refused with the reason when it does not validate; nothing changes then.", "POST", "/v1/reload", false, false, Role::operator_, schema({{"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"confirm", "reason"})});
    t.push_back({"logs_reopen", "Reopen logs", "Reopen every log file after rotation.", "POST", "/v1/logs/reopen", false, false, Role::operator_, schema({{"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"confirm", "reason"})});
    t.push_back({"site_create", "Create a site", "Writes a new site file, validates and reloads. A new site is HTTPS-only with a redirect from http unless https is \"none\". Until https, root (or upstream), app and user are decided the server answers with the open questions and a suggestion each: ask the user each question, then call again with every field. When the server has its provisioning helper (started as root, the default), the account, the directories, the site's log and the php-fpm pool are created by this call and listed under done; only then is nothing left for a terminal. If it answers with commands to run as root instead (no helper, or the helper refused something), show them to the user, wait until they confirm they ran them, then call again with the same fields. The success answer may carry warnings: tell the user each one (for example that the site answers only its own names and a monitor checking the IP address needs the hostname, or a catch-all site with server_name [\"*\"]).", "POST", "/v1/sites", false, false, Role::admin, schema(site_fields(), {"domain", "confirm", "reason"})});
    {
        auto fields = site_fields();
        fields.insert(fields.begin(), {"name", name_arg()});
        t.push_back({"site_update", "Update a site", "Changes fields of a site that site_create wrote (aliases, https, user, app, root, upstream, PHP pool, and the per-site limits under settings: raising a WordPress site's upload limit is settings: {max_body_size: \"200MB\"}). The answer lists under done what was written and reloaded (the site file and agensio; the php-fpm pool and php-fpm, which briefly affects every PHP site unless process_control_timeout is set). Hand-written site files are refused; tell the user to edit those directly.", "POST", "/v1/sites/{name}", false, false, Role::admin, schema(fields, {"name", "confirm", "reason"})});
    }
    t.push_back({"site_disable", "Disable a site", "Stops serving the site (its file is renamed to .disabled) and reloads. Reversible with site_enable.", "POST", "/v1/sites/{name}/disable", false, false, Role::admin, schema({{"name", name_arg()}, {"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"name", "confirm", "reason"})});
    t.push_back({"site_enable", "Enable a site", "Brings a disabled site back and reloads.", "POST", "/v1/sites/{name}/enable", false, false, Role::admin, schema({{"name", name_arg()}, {"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"name", "confirm", "reason"})});
    t.push_back({"site_delete", "Delete a site", "Removes the site's configuration file (a .bak copy stays) and reloads. The site's files and account are never touched.", "POST", "/v1/sites/{name}/delete", false, true, Role::admin, schema({{"name", name_arg()}, {"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"name", "confirm", "reason"})});
    t.push_back({"cert_renew", "Renew certificate", "Orders the site's automatic certificate again now. Watch site_show and logs_query for the result.", "POST", "/v1/sites/{name}/renew", false, false, Role::operator_, schema({{"name", name_arg()}, {"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"name", "confirm", "reason"})});
    t.push_back({"uploads_list", "List uploads", "Archives stored on the server with `agensio ctl upload NAME < file` (run by the user on the server, or over ssh: `ssh admin@host agensio ctl upload NAME < file`), ready for site_install with file: NAME. This bridge cannot carry files itself: when the user has an archive on their own machine, give them that command.", "GET", "/v1/uploads", true, false, Role::viewer, schema({}, {})});
    t.push_back({"upload_delete", "Delete an upload", "Removes a stored upload once it is installed or not needed.", "POST", "/v1/uploads/{file}/delete", false, true, Role::operator_, schema({{"file", prop("string", "The upload's name as uploads_list shows it.")}, {"confirm", confirm_arg()}, {"reason", reason_arg()}}, {"file", "confirm", "reason"})});
    t.push_back({"site_install", "Install an application", "Puts an application's files into the site's directory, as the site's own account, from one of three sources: the preset's official archive (presets_list shows which presets have one, e.g. wordpress and drupal; version picks a release, default the newest), any https URL the user gives (url), or an archive the user uploaded (file, see uploads_list). The whole application goes into the site's directory, which must be empty; a plugin, theme or module goes into path (e.g. wp-content/plugins/NAME, web/modules/contrib/NAME) with create_path: true, which makes the missing directories as the site's account below the site's directory (never through a symlink, never in another account's directory); a single top directory in the archive (wordpress/, NAME/) is unwrapped. Rules the server enforces and reports: https only, no private, loopback or link-local address on any hop, size caps, no symlinks, hard links or devices inside an archive, optional sha256 check; on any refusal nothing is left behind. The preset's credential files (presets_list, secrets: wp-config.php, Drupal's settings.php) are made 0600 and listed under secured, and the configuration is validated after the install: an answer is never ok when agensio -t would refuse the result (a 409 with written: true and errors says what to fix). dry_run: true runs the same checks (target, account, what would be created) without installing. Tell the user the source and the sha256 from the answer, then the application's own setup remains (database, admin account), done in the browser. Laravel has no archive: it is created with composer.", "POST", "/v1/sites/{name}/install", false, false, Role::admin,
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
    "Start a session on a server you do not know with health_check and "
    "server_status, then explain the findings in plain words and offer the usual jobs: create a "
    "site (HTTPS by default, ask about the site user and what runs there; writing its php-fpm pool reloads "
    "php-fpm, which briefly affects every PHP site on the host unless process_control_timeout is set, see "
    "health_check), inspect a site, look "
    "at recent errors, install an application into a site. Every change needs the user's explicit agreement first (confirm: true) "
    "and a one-line reason. When the server answers with commands to run as root, show them "
    "exactly, say that the server waits for them, and continue only when the user says they ran "
    "them. On a server whose helper is present, site_create does that root work itself and reports it under done. "
    "After a site exists, site_install fills it: the preset's official archive (wordpress, drupal), an https URL "
    "the user names, or an archive the user uploaded with `agensio ctl upload NAME < file` (this bridge carries no files; "
    "give the user that command when the archive is on their machine, and also when the server refuses a download by its "
    "rules). The install runs as the site's account into an empty directory and refuses symlinks, private addresses and "
    "oversize archives, leaving nothing behind on a refusal; report the source and sha256 it answers with. "
    "site_install and site_copy make the preset's credential files 0600 and validate the configuration "
    "before answering; a 409 with written: true means the files are there but health lists what to fix. "
    "A plugin or theme goes into its own directory with site_install's path and create_path; a drop-in file an "
    "application ships as a template (WordPress's wp-content/db.php from the SQLite plugin's db.copy, Drupal's "
    "settings.php) is put in place with site_copy, which copies one file within the same site and nothing else. "
    "Per-site limits (upload size, PHP memory, execution time, pool size) are changed with site_update's settings "
    "object; call site_settings_list first for the keys, units, current values and the ceilings root set. "
    "For any other key (workers, cache sizes, log level, timeouts, the control plane's own keys) call "
    "config_reference: it says what the key does, its running value, whether the change needs a reload or a "
    "restart, and which tool changes it. Only when via is file is there no tool: the main configuration file "
    "is root's and agensio never edits it, so answer with the exact line to set, the file, and the reload or "
    "restart command, exactly like the root commands protocol; never claim to have changed it. "
    "Never invent settings: what a tool does not offer is not configurable here. Host names are "
    "strict: a site answers only the names in server_name, and a listener without a catch-all site "
    "(server_name [\"*\"] or default = true) answers 421 to any other Host, including the IP address; and on "
    "TLS a connection answers only the names its certificate covers, so a request that reaches one site's "
    "certificate with another site's Host is 421 too. When a user reports 421, one of those is the cause.";

const char* kGettingStarted =
    "Greet the administrator briefly. Remember rule one: what a tool can do is done here, through the tool; "
    "a terminal is for what no tool covers. Run health_check and server_status. Summarise: how many "
    "sites, which have certificates and their state, anything the health check flagged (with its "
    "fix), whether the server runs under a service user. Then offer the next jobs: add a site, "
    "check a site's logs for errors, renew a certificate, reload after a manual edit. Keep it "
    "short and ask what they want to do.";

const char* kNewSite =
    "Create a website step by step. Ask for the domain (and whether www. should be included as "
    "an alias). Call site_create with only the domain first: the server lists the open decisions "
    "with a suggestion each. Ask the user each question in turn: HTTPS (recommend auto, which "
    "needs port 80 reachable and the name pointing at this server), whether the site gets its own "
    "system user (recommend yes, suggest the proposed name), what runs there (static, php, "
    "laravel, wordpress or proxy) and where the files are. Call site_create again with every "
    "field and confirm: true only after the user agreed. If the server returns commands to run "
    "as root, show them verbatim and wait. After success, show next_steps and check with "
    "site_show that the certificate arrives. When the site's app has an official archive (presets_list, "
    "source) offer to install it now with site_install; for other applications ask whether the user has "
    "an https URL of the archive or wants to upload it with agensio ctl upload.";

class Mcp {
public:
    Mcp(std::string socket, std::ostream& out) : socket_(std::move(socket)), out_(out), tools_(tools()) {
        ControlReply reply;
        std::string error;
        if (control_request(socket_, "GET", "/v1/status", "", reply, error) && reply.status == 200) {
            json::Value v;
            if (json::parse(reply.body, v, error)) {
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
            json::Value caps = json::Value::object();
            caps.set("tools", json::Value::object().set("listChanged", false));
            caps.set("prompts", json::Value::object().set("listChanged", false));
            std::string instructions = kInstructions;
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
        for (const char* key : {"name", "file"}) {
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
            for (const auto& m : args.members())
                if (m.first != path_arg) b.set(m.first, m.second);
            body = b.dump();
        } else if (name == "logs_query") {
            std::string q;
            for (const char* k : {"site", "since", "level", "status", "limit"}) {
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
        content.push(json::Value::object().set("type", "text").set("text", reply.body));
        json::Value r = json::Value::object().set("content", std::move(content)).set("isError", reply.status >= 400);
        if (is_json && parsed.is_object()) r.set("structuredContent", parsed);
        result(id, std::move(r));
    }

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
    std::ostream& out_;
    std::vector<Tool> tools_;
    Role role_ = Role::none;
    std::string unreachable_;
};

}  // namespace

int run_mcp(const std::string& socket_path, std::istream& in, std::ostream& out) {
    Mcp server(socket_path, out);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line == "\r") continue;
        if (line.back() == '\r') line.pop_back();
        server.handle(line);
    }
    return 0;
}

}  // namespace agensio
