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
#pragma once

#include <mutex>
#include <string>

#include "config.hpp"
#include "services/json.hpp"
#include "services/log.hpp"

namespace agensio {

class Provisioner {
public:
    ~Provisioner();
    // Forks the helper (needs euid 0). False, with the reason logged, when it cannot.
    bool start(const Config& cfg, ErrorLog& log);
    bool available() const noexcept { return fd_ >= 0; }
    // One request, one reply: {"op": ..., ...} -> {"ok": bool, "error"?: text, "output"?: text}.
    // Synchronous and serialised; the operations take milliseconds.
    json::Value request(const json::Value& req);
    // The same without waiting: {"ok": false, "busy": true} when another request (a task
    // that runs for minutes) holds the helper. For the reads a caller must never wait on.
    json::Value try_request(const json::Value& req);
    void stop() noexcept;

private:
    json::Value exchange(const json::Value& req);  // one request and its reply; the caller holds mutex_
    int fd_ = -1;
    int pid_ = -1;
    std::mutex mutex_;
};

namespace provision {
// The helper's own validation of a request against the configuration it was started
// with: "" when acceptable, else what is wrong. Pure, unit tested; the helper calls it
// before acting, whatever the server said.
std::string validate(const json::Value& req, const Config& cfg);
// The directory every site directory must live under.
std::string sites_root(const Config& cfg);
// The directory every per-site log must live under.
std::string logs_root(const Config& cfg);
// Where `agensio ctl upload` puts archives: <state_dir>/uploads, the server's own, 0700.
std::string uploads_dir(const Config& cfg);
// `path` is `root` or lies below it, textually (both normalised).
bool under_root(const std::string& path, const std::string& root);
}  // namespace provision

}  // namespace agensio
