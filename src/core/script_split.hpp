// The script a request runs, split from its path info the way agensio's own handlers run it
// (2026-10-09, the alpha.58 report, finding 1). One place, used by the handlers that run the
// script (handlers/fastcgi.cpp, handlers/cgi.cpp) and by the rules that judge it (core/access.hpp
// script_of), so the two can never disagree: Caddy's CVE-2026-27590 and CVE-2026-45135 came from a
// second split that did (research_notes/Exact rules and path info/servers.md).
#pragma once

#include <algorithm>
#include <string>
#include <string_view>

#include "config.hpp"

namespace agensio::script_split {

// FastCGI with path_info: the script ends at the first ".php" followed by '/', nginx's
// fastcgi_split_path_info ^(.+?\.php)(/.*)$ ("/index.php/extra": "/index.php" and "/extra"),
// which the router's suffix match agrees with (Router::suffix_hit). The script's length within
// `path`, or npos when it has no path info.
inline std::size_t php_end(std::string_view path) noexcept {
    const std::size_t p = path.find(".php/");
    return p == std::string_view::npos ? std::string_view::npos : p + 4;
}

// The file a location maps a path to: its root followed by the path, or its alias in place of the
// location's prefix (the static handler's fs_path_of).
inline void file_of(const LocationConfig& loc, std::string_view path, std::string& out) {
    if (loc.alias.empty()) out.assign(loc.root).append(path);
    else out.assign(loc.alias).append(path.substr(std::min(path.size(), loc.path.size() - 1)));  // keeps the '/'
}

// CGI: the longest leading part of `path`, cut at a '/', whose file under the location is a regular
// file (Apache's rule); the rest is PATH_INFO. Its length within `path`, or 0 when no leading part
// is one. `is_file` stats a file system path; `fs` is scratch for it.
template <class IsFile>
std::size_t cgi_end(const LocationConfig& loc, std::string_view path, std::string& fs, IsFile&& is_file) {
    for (std::size_t cut = path.size(); cut > 0;) {
        file_of(loc, path.substr(0, cut), fs);
        if (is_file(fs)) return cut;
        const std::size_t slash = path.rfind('/', cut - 1);
        if (slash == std::string_view::npos || slash == 0) return 0;
        cut = slash;
    }
    return 0;
}

}  // namespace agensio::script_split
