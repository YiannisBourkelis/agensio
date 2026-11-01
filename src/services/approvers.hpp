// The people who approve changes (docs/design-site-operations.md 27.5): one file per approver,
// <directory of the main configuration>/approvers/NAME.totp, holding the TOTP secret, and NAME.step
// beside it with the last time step accepted (a code is accepted once). Root's, 0600, in a 0700
// directory of root's, read only by the provisioning helper; a server without the helper keeps them
// under its own account, as the suites run it, and health says what that is worth. Written only by
// `agensio approver-add` on the server, never through the control plane, so no agent can enroll
// itself.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace agensio {
struct Config;
}

namespace agensio::approvers {

// <directory of the main configuration>/approvers.
std::filesystem::path dir_of(const Config& cfg);
// ^[a-z0-9][a-z0-9_-]{0,31}$: "" or why.
std::string check_name(std::string_view name);

struct Approver {
    std::string name;
    std::string created;
    std::int64_t last_step = -1;  // the last time step a code of this approver was accepted at
    std::string problem;          // why the file is not used (owner, mode, content); "" when usable
};
// The approvers of `dir`, each file checked: owned by `owner`, a regular file, nothing for group or
// others, never followed through a symlink; the directory the same. `dir_problem` says what is wrong
// with the directory itself ("" when fine, "missing" when there is none).
std::vector<Approver> list(const std::filesystem::path& dir, uid_t owner, std::string& dir_problem);

// A new approver with `secret`: the directory made 0700 when missing, NAME.totp created 0600 with
// O_EXCL (an existing one is refused unless `replace`); false with why.
bool add(const std::filesystem::path& dir, std::string_view name, std::string_view secret, bool replace, std::string& why);
bool remove(const std::filesystem::path& dir, std::string_view name, std::string& why);

// What checks a code: one per process that checks (the helper, or the server without it), keeping
// the wrong codes of the last ten minutes. Five of them stop approvals for ten minutes.
class Checker {
public:
    struct Result {
        bool ok = false;
        std::string approver;
        std::string error;
        std::int64_t locked_until = 0;  // set while approvals are stopped
        int failures = 0;               // wrong codes in the last ten minutes, this one included
    };
    static constexpr int kMaxFailures = 5;
    static constexpr std::int64_t kWindow = 600;

    Result check(const std::filesystem::path& dir, uid_t owner, std::string_view code, std::int64_t now);

private:
    std::vector<std::int64_t> failures_;
    std::int64_t locked_until_ = 0;
};

}  // namespace agensio::approvers
