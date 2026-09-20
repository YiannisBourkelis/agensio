// The provisioning helper (F8): a root process forked before the privilege drop, connected
// to the server by a socketpair, that does five things on the server's behalf so that a
// site with its own account can be created in one control call: create the account, lay
// out the site's directories, hand a per-site log to the site's group, write the php-fpm
// pools and reload php-fpm, restart the service. It is not a listener: only the server
// process holds the other end. Every argument is validated again in the helper with the
// same rules the control API uses; programs run by absolute path with a fixed argument
// list and an empty environment, never through a shell. What a fully compromised server
// process could obtain through it is bounded to exactly those five operations, within
// the directories named below; docs/security-control-plane.md spells that out.
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
    void stop() noexcept;

private:
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
}  // namespace provision

}  // namespace agensio
