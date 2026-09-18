// Peer credentials of a unix-socket connection (F0): the kernel tells us the uid and gid
// of the process at the other end, whatever the socket's file mode says. Supplementary
// groups come from the account database. POSIX only.
#pragma once

#include <vector>

#ifndef _WIN32
#include <grp.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace agensio {

inline bool peer_credentials(int fd, long& uid, long& gid) noexcept {
#if defined(__linux__)
    struct ucred cred{};
    socklen_t len = sizeof cred;
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) return false;
    uid = cred.uid;
    gid = cred.gid;
    return true;
#elif !defined(_WIN32)
    uid_t u = 0;
    gid_t g = 0;
    if (::getpeereid(fd, &u, &g) != 0) return false;
    uid = u;
    gid = g;
    return true;
#else
    (void)fd;
    (void)uid;
    (void)gid;
    return false;
#endif
}

// The supplementary groups of `uid` (empty when the account is unknown).
inline std::vector<long> groups_of(long uid) {
    std::vector<long> out;
#ifndef _WIN32
    const struct passwd* pw = ::getpwuid(static_cast<uid_t>(uid));
    if (!pw) return out;
    int n = 64;
#ifdef __APPLE__
    std::vector<int> groups(static_cast<std::size_t>(n));
    if (::getgrouplist(pw->pw_name, static_cast<int>(pw->pw_gid), groups.data(), &n) < 0) {
        groups.resize(static_cast<std::size_t>(n));
        ::getgrouplist(pw->pw_name, static_cast<int>(pw->pw_gid), groups.data(), &n);
    }
#else
    std::vector<gid_t> groups(static_cast<std::size_t>(n));
    if (::getgrouplist(pw->pw_name, pw->pw_gid, groups.data(), &n) < 0) {
        groups.resize(static_cast<std::size_t>(n));
        ::getgrouplist(pw->pw_name, pw->pw_gid, groups.data(), &n);
    }
#endif
    for (int i = 0; i < n && i < static_cast<int>(groups.size()); ++i) out.push_back(static_cast<long>(groups[static_cast<std::size_t>(i)]));
#else
    (void)uid;
#endif
    return out;
}

}  // namespace agensio
