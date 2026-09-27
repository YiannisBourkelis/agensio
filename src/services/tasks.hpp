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
// {gem_home}, or a parameter's name). `only_if` drops the argument when that parameter was
// not given; `unless` drops it when it was (a default spelled for a caller who gave none).
struct Arg {
    const char* text;
    const char* only_if = nullptr;
    const char* unless = nullptr;
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
};

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
    unsigned timeout = 1200;  // effective seconds
    unsigned processes = 512;
};

struct Plan {
    std::vector<std::string> argv;  // argv[0]: the program exactly as it is executed
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
// {"ok", "task", "as", "cwd", "argv", "env", "network", "limits", then for a run "ran",
// "exit" | "signal", "timed_out", "duration_ms", "output", "output_bytes", "truncated",
// "secured", "exposed"; "error" (and "run_as_root" for a missing runtime) when refused}.
json::Value execute(const Request& req);

}  // namespace agensio::tasks
