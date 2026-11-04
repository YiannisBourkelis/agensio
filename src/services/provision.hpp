// The provisioning helper (F8): a root process forked before the privilege drop, connected
// to the server by a socketpair, that does a fixed set of things on the server's behalf so
// that a site with its own account can be created, filled and prepared through the control
// plane: create the account, lay out the site's directories, hand a per-site log to the
// site's group, write the php-fpm pools and reload php-fpm, restart the service, install an
// application's files as the site's account (F9, `app_install`), copy one of a site's files
// (F9b, `file_copy`), and run a named task of the site's preset as the site's account (F13,
// `task_run`: a row of services/tasks, never a command line). It is not a listener: only
// the server process holds the other end. Every argument is validated again in the helper
// with the same rules the control API uses; programs run by absolute path with a fixed
// argument list and an environment built for them, never through a shell. What a fully
// compromised server process could obtain through it is bounded to exactly those
// operations, within the directories named below; docs/security-control-plane.md spells
// that out.
//
// The reads and the approval codes have a helper of their own, the reader (2026-11-04, the
// alpha.126 report, problem 3): forked beside the main one, the same loop with a fixed list of
// requests (provision::reader_op) and nothing else, so a task that holds the main helper for
// minutes no longer makes health, the service's state or an approval code wait or answer busy.
// Each request is served by one of the two only: the main helper refuses the reader's.
#pragma once

#include <mutex>
#include <string>
#include <string_view>

#include "config.hpp"
#include "services/json.hpp"
#include "services/log.hpp"

namespace agensio {

class Provisioner {
public:
    ~Provisioner();
    // Forks the reader, then the helper (needs euid 0). False, with the reason logged, when the
    // helper cannot start; a reader that cannot leaves the helper serving everything, as before.
    bool start(const Config& cfg, ErrorLog& log);
    bool available() const noexcept { return main_.fd >= 0; }
    // One request, one reply: {"op": ..., ...} -> {"ok": bool, "error"?: text, "output"?: text}.
    // Synchronous and serialised per helper: a reader's request waits for the reads before it, at
    // most kReadWait ({"ok": false, "busy": true} past it); any other waits its turn, behind a task.
    json::Value request(const json::Value& req);
    // The same without waiting: {"ok": false, "busy": true} when another request (a task
    // that runs for minutes, or for a read another read) holds the helper that serves it.
    // For the reads a caller must never wait on (worker 0).
    json::Value try_request(const json::Value& req);
    // A read off the workers: with the reader, request; without one, try_request, so that nothing
    // waits behind a task where it did not before.
    json::Value read(const json::Value& req);
    void stop() noexcept;
    static constexpr int kReadWait = 30;  // seconds

private:
    struct Channel {
        int fd = -1;
        int pid = -1;
        std::timed_mutex mutex;
    };
    Channel& channel_for(const json::Value& req) noexcept;
    static json::Value exchange(Channel& c, const json::Value& req);  // one request and its reply; the caller holds c.mutex
    Channel main_, reader_;
};

namespace provision {
// The helper's own validation of a request against the configuration it was started
// with: "" when acceptable, else what is wrong. Pure, unit tested; the helper calls it
// before acting, whatever the server said.
std::string validate(const json::Value& req, const Config& cfg);
// The requests the reader serves, and the only ones it serves besides ping: the reads that change
// nothing a request of the main helper depends on (env_check, app_check, app_status, app_logs,
// host_protection, php_runtimes, trash_list, approvers_list) and approval_check, whose count of wrong
// codes and last used steps one process alone may keep. With a reader the main helper refuses them.
bool reader_op(std::string_view op) noexcept;
enum class Role { main, reader };
// The loop of a helper process: one JSON line in, one out, until the other end closes, then
// _exit(0). `reader_apart`: for the main helper, that a reader serves the reader's requests.
// Unit tested over a socketpair; the server forks it in Provisioner::start.
[[noreturn]] void serve(int fd, const Config& cfg, Role role, bool reader_apart);
// The directory every site directory must live under.
std::string sites_root(const Config& cfg);
// The directory every per-site log must live under.
std::string logs_root(const Config& cfg);
// Where `agensio ctl upload` puts archives: <state_dir>/uploads, the server's own, 0700.
std::string uploads_dir(const Config& cfg);
// `path` is `root` or lies below it, textually (both normalised).
bool under_root(const std::string& path, const std::string& root);
// <sites_root>/.trash: where a site deleted with its files goes (F12b), root's alone.
std::string trash_dir(const Config& cfg);
// A trash entry's name: <domain>-<YYYYMMDD>-<HHMMSS>, nothing else (no '/', no '.', no '..').
bool valid_trash_entry(std::string_view name) noexcept;
// The directory a files-delete moves for a site: the first directory below sites_root on
// the root's path (/var/www/example.com for /var/www/example.com/app), unless another
// site's root lies under it, then the root alone; "" with `why` when the root is not below
// sites_root.
std::string site_tree(const Config& cfg, const SiteConfig& site, std::string& why);
}  // namespace provision

}  // namespace agensio
