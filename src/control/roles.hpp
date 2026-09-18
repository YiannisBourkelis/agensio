// Control plane roles (phase F0): what a peer may do, decided from its uid and groups.
// root and the server's own user are always admin; the three configured groups map to
// the three roles; anyone else has no role and is refused at accept. Pure, unit tested.
#pragma once

#include <algorithm>
#include <cstdint>
#include <string_view>
#include <vector>

namespace agensio {

enum class Role : std::uint8_t { none = 0, viewer = 1, operator_ = 2, admin = 3 };

struct RoleGroups {
    long admins = -1;  // gids, -1 when the group is not configured or does not exist
    long operators = -1;
    long viewers = -1;
};

inline Role role_of(long uid, long gid, const std::vector<long>& groups, long server_uid, const RoleGroups& g) noexcept {
    if (uid == 0 || uid == server_uid) return Role::admin;
    auto member = [&](long target) {
        return target >= 0 && (gid == target || std::find(groups.begin(), groups.end(), target) != groups.end());
    };
    if (member(g.admins)) return Role::admin;
    if (member(g.operators)) return Role::operator_;
    if (member(g.viewers)) return Role::viewer;
    return Role::none;
}

inline std::string_view role_name(Role r) noexcept {
    switch (r) {
        case Role::admin: return "admin";
        case Role::operator_: return "operator";
        case Role::viewer: return "viewer";
        default: return "none";
    }
}

}  // namespace agensio
