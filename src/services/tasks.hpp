// Site tasks (F13, docs/design-site-operations.md section 4): the framework commands an
// application needs (rails new, bundle install, db:prepare, assets:precompile), each a row
// of a table with a fixed argv and typed parameters, run as the site's account in the
// site's directory. No command string exists anywhere: the caller names a task and gives
// parameters, each parameter is checked against its row's pattern, and the argv the row
// builds is what runs (execve, no shell), started by an interpreter from [control]
// runtimes that only root can have written. The table, the checks, the plan, the output
// capture and the text cleaning are pure and unit tested; `run`, `sweep` and `execute`
// are the process and the filesystem, run as real accounts by tests/tasks.sh.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "services/json.hpp"

namespace agensio::tasks {

// A parameter the caller may give: its name, what it means, the pattern its value must
// match (shown to callers as text, checked by `valid`), and whether it is required.
struct Param {
    const char* name;
    const char* description;
    const char* pattern;
    bool (*valid)(std::string_view) noexcept;
    bool required;
};

// One argument of a row's command: literal text, or text holding {placeholders} ({home},
// {gem_home}, {venv}, {root}, {project}, or a parameter's name). `only_if` drops the argument when that parameter was
// not given; `unless` drops it when it was (a default spelled for a caller who gave none).
struct Arg {
    const char* text;
    const char* only_if = nullptr;
    const char* unless = nullptr;
    bool split = false;  // the expanded text is several arguments, one per space (pip_install's packages)
};

// A file a task needs before it runs, or must leave behind when it exits 0: a path relative
// to the site's directory ("Gemfile") or one starting with {gem_home} or {home}, and what
// the caller should do when it is missing (2026-09-27 report: gem_install_rails answered ok
// without writing the rails command, and rails_new then failed with a bare LoadError).
struct Need {
    const char* path;
    const char* hint;
};

struct Row {
    const char* app;      // the preset whose sites offer the task
    const char* name;     // what the caller names
    const char* summary;
    const char* runtime;  // the [control] runtimes key
    const char* program;  // a file in that directory
    std::vector<Arg> args;
    std::vector<Param> params;
    std::vector<std::pair<const char*, const char*>> env;  // the row's own variables, after the preset's
    bool network;         // downloads; refused with [control] task_network = false
    bool needs_empty;     // the site's directory must be empty
    unsigned timeout;     // seconds; [control] task_limits.timeout caps it
    std::vector<Need> needs = {};     // checked before it runs, dry run included
    std::vector<Need> produces = {};  // checked after it exited 0
    // A row that writes one file from a fixed template instead of running a program (no
    // interpreter, no argv; 2026-09-27 Redmine report: an archive-installed application
    // ships config/database.yml.example and nothing can make config/database.yml): the path
    // below the site's directory, its whole content (never the caller's), its mode. Written
    // as the site's account, never through a symlink, only when the file does not exist.
    const char* writes = nullptr;
    const char* content = nullptr;
    unsigned mode = 0640;
    // Variables the site's environment must hold first (database_config: DATABASE_URL),
    // with what to do when one is missing.
    std::vector<Need> needs_env = {};
    // Only for making a new application (gem_install_rails, rails_new): not offered to a
    // preset built on this row's app for an application installed from an archive (redmine).
    bool new_app_only = false;
    // The name the interpreter runs under (argv[0]), when not its own path: "{venv}/bin/python"
    // makes root's python3 the site's virtualenv (Python finds pyvenv.cfg from argv[0]), so
    // the program executed stays root's file while the packages are the site's
    // (2026-09-28, the Wagtail report).
    const char* argv0 = nullptr;
    // The interpreter must be able to make a virtualenv (Debian ships ensurepip apart, in
    // python3-venv): checked before the run and in the listing, with the package command.
    bool needs_venv_support = false;
    // The caller names what gets installed (pip_install, 2026-09-28, the owner's decision): any
    // package the site's account may install, so the user confirms every run themselves, in
    // the MCP client's own dialog or in a terminal; the agent's confirm is not enough.
    bool user_confirm = false;
    // A template row may replace a file that is still agensio's own earlier version (it starts
    // with the template's first line): django_settings, so a site gets the new template's fixes
    // (2026-09-28: secure cookies); the previous file is kept beside it as NAME.bak.
    bool replace_own = false;
};

// Whether a task of this name needs the user's own confirmation (the MCP bridge and
// `agensio ctl` ask before they send it; the control API refuses it without one).
bool needs_user_confirmation(std::string_view task) noexcept;
// The warning the user reads before confirming: what is installed, where, as whom, and why a
// name must be checked first. `account` and `venv` may be empty when not known.
std::string confirmation_warning(std::string_view site, std::string_view packages, std::string_view account, std::string_view venv);

// What every row of a preset shares: its environment (values may hold {home} and
// {gem_home}) and the files the sweep makes private after each run on top of the hosting
// rule's own list (`secret_paths`); a '*' in the last component matches any run of
// characters there, and only there.
struct Family {
    const char* app;
    std::vector<std::pair<const char*, const char*>> env;
    std::vector<const char*> secret_patterns;
};

const std::vector<Row>& rows();
// Whether `app` offers the row: its own rows, and for a preset built on another (redmine on
// rails) that one's rows too, but not the ones that make a new application.
bool offered(const Row& row, std::string_view app) noexcept;
const Row* find(std::string_view app, std::string_view task) noexcept;
const Family* family(std::string_view app) noexcept;
bool has_tasks(std::string_view app) noexcept;
std::vector<std::string> names(std::string_view app);
// Every task name, and every parameter some row takes (one per name), for the MCP schema.
std::vector<std::string> all_names();
std::vector<const Param*> all_params();

// A site's tasks for GET /v1/sites/NAME/tasks: task, summary, runtime, params (name,
// description, pattern, required), network, needs_empty, timeout. With a context, the
// timeout is the effective one (the row's, capped by [control] task_limits.timeout) and
// each task carries `interpreter`: the program it would run, whether the interpreter rule
// accepts it, and when not the reason and the package command (`run_as_root`), so a
// missing runtime is known before the first task, not on the third.
struct CatalogContext {
    unsigned timeout_cap = 0;
    std::function<std::string(std::string_view runtime)> runtime_dir;
    std::string sites_root;
};
json::Value catalog(std::string_view app, const CatalogContext* ctx = nullptr);

// The caller's params against the row: an object (or null) of strings, no name the row
// does not list, every required one given, each value matching its pattern. "" when
// acceptable, else the refusal naming the parameter.
std::string check_params(const Row& row, const json::Value& params);

struct Context {
    std::string runtime_dir;  // [control] runtimes.<row.runtime>
    std::string root;         // the site's directory: the working directory
    std::string home;         // the account's home (<state_dir>/<account>); TMPDIR is its tmp/
    std::string app;          // the site's preset: its family's environment and credential patterns
    std::string site;         // the site's first host name: {venv} is <home>/venvs/<site>
    std::string project;      // app = django | wagtail: the project's package ({project})
    std::string hosts, origins, base_url;  // what a Django site's settings are told (config app_context)
    bool https_redirect = false, hsts = false;  // what agensio does at the edge for the site
    unsigned timeout = 1200;  // effective seconds
    unsigned processes = 512;
    // The site's application environment (services/appenv.*: SECRET_KEY_BASE and the like),
    // added after every variable agensio sets and never replacing one; the answer shows the
    // names, never the values.
    std::vector<std::pair<std::string, std::string>> app_env;
};

struct Plan {
    std::string exec;               // the file executed (root's interpreter, as trusted_program resolved it)
    std::vector<std::string> argv;  // argv[0]: the program's path, or the name the row runs it under (argv0)
    std::vector<std::string> env;   // NAME=value, the whole environment
    std::string cwd;
    unsigned timeout = 1200;
    unsigned processes = 512;
    unsigned open_files = 4096;
    unsigned term_grace = 10;  // seconds between SIGTERM and SIGKILL
    unsigned drain = 2;        // seconds of output still read after the program exited
};

// The plan for a row whose params passed check_params; `program` is the interpreter's path
// as trusted_program resolved it.
Plan build(const Row& row, const json::Value& params, const Context& ctx, const std::string& program);

// What a failed run's output means when it is a known cause with a fix agensio can name
// (Rails without SECRET_KEY_BASE, a Gemfile pinning another Ruby than [control] runtimes
// gives): the hint, or "".
std::string failure_hint(const Row& row, std::string_view output, const Context& ctx);
// What an exit 0 does not show: output that says the result cannot work (Redmine's Gemfile
// without config/database.yml leaves the bundle with no database driver). "" when none; else
// the task answers 409 with it.
std::string output_problem(const Row& row, std::string_view output);
// One line that says what a successful run did, from its output or the files it left
// ("240 migrations applied", Bundler's closing line, "public/assets holds 39 files"); "" when
// there is nothing to add. `root_fd` the site's directory, or -1.
std::string summarize(const Row& row, std::string_view output, int root_fd);

// The row's `needs` (or, with `after`, its `produces`) against the filesystem, relative
// paths below `root_fd`: "" when every one exists, else the refusal naming the first
// missing path and what to do. As the executing account; never follows a symlink at the
// last component of a relative path.
std::string check_needs(const Row& row, const json::Value& params, const Context& ctx, int root_fd, bool after = false);

// The rule for an interpreter: every component of the configured path and of the path it
// resolves to belongs to root, every directory on them is writable by root alone, the file
// is regular and executable and does not lie below `sites_root`. "" with `canonical` set,
// or what is wrong; `missing` says the file does not exist.
std::string trusted_program(const std::string& path, const std::string& sites_root, std::string& canonical, bool& missing);

// The command root runs to install a runtime ("apt-get install -y ruby ..."), "" when there
// is no known one for this system.
std::string install_hint(std::string_view runtime);
// Whether the Python at `canonical` (/usr/bin/python3.13) can make a virtualenv: its
// ensurepip (<prefix>/lib/python3.13/ensurepip) is there. "" when it can or when the path
// says nothing about a layout; else why, with `run_as_root` the package command.
std::string venv_support(const std::string& canonical, std::string& run_as_root);
// The virtualenv of a site: <home>/venvs/<site>.
std::string venv_path(const Context& ctx);

// The head and the tail of a program's output, bounded: the first `head` bytes and the
// last `tail`, the total counted, a marker naming what was cut.
class Capture {
public:
    explicit Capture(std::size_t head = 16 * 1024, std::size_t tail = 48 * 1024) noexcept : head_cap_(head), tail_cap_(tail) {}
    void add(const char* p, std::size_t n);
    std::string text() const;
    std::uint64_t total() const noexcept { return total_; }
    bool truncated() const noexcept { return total_ > head_cap_ + tail_cap_; }

private:
    std::size_t head_cap_, tail_cap_;
    std::string head_, tail_;
    std::uint64_t total_ = 0;
};

// Output made fit for JSON and a reader: invalid UTF-8 becomes U+FFFD, terminal escape
// sequences are dropped.
std::string clean_text(std::string_view bytes);

// Runs the plan as the calling account (the caller has become the site's account already):
// a child in its own process group, default signal dispositions, umask 027, the limits,
// the working directory by descriptor, the plan's environment and nothing else, stdin
// /dev/null, stdout and stderr into one pipe. The timeout sends SIGTERM to the group and
// SIGKILL `term_grace` later; once the program exits, output is read for `drain` seconds
// more and the group is killed, so nothing it started stays behind.
// {"exit"? | "signal"?, "timed_out", "duration_ms", "output", "output_bytes", "truncated"},
// or {"error"} when it could not be started.
json::Value run(const Plan& plan, int cwd_fd);

// The credential sweep after a run: the hosting rule's secrets (relative paths) and the
// preset's patterns below the site's directory (a descriptor), files 0600 and directories
// secret_dir_mode(), never through a symlink, only what this account owns.
// {"secured": [absolute paths changed], "exposed": [what could not be made private]}.
json::Value sweep(int root_fd, const std::string& root, const std::vector<std::string>& secrets, const std::vector<const char*>& patterns);

// The whole task in the calling account's identity: the site's directory (reached without
// a symlink, this account's, empty when the row needs it), the home and its tmp/, the
// runtime rule, the plan; then, unless `dry_run`, the run and the sweep.
struct Request {
    const Row* row = nullptr;
    json::Value params;
    Context ctx;
    std::string sites_root;
    std::vector<std::string> secrets;  // the hosting rule's list, relative to ctx.root
    bool network_allowed = true;       // [control] task_network
    bool dry_run = false;
};
// {"ok", "task", "as", "cwd", "argv", "env" (the site's own variables as NAME=<site
// environment>), "network", "limits", then for a run "ran", "exit" | "signal", "timed_out",
// "duration_ms", "output", "output_bytes", "truncated", "secured", "exposed", "hint" when
// failure_hint knows the cause; "error" (and "run_as_root" for a missing runtime) when refused}.
json::Value execute(const Request& req);

}  // namespace agensio::tasks
