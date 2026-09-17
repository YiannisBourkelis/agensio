// Routing: which site serves a Host header on a listening address, and which of the
// site's locations serves a normalised path. Both lookups are read-only over structures
// built at startup; per request they cost one hash lookup (host) and one scan over the
// site's locations, which are sorted so that the first match is the winner: exact
// matches, then suffixes (".php"), then prefixes, longest first within a kind, the
// implicit "/" last.
// Handlers are chosen per location (only "static" until phase C).
#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>

#include "config.hpp"

namespace agensio {

struct StringViewHash {
    using is_transparent = void;
    std::size_t operator()(std::string_view s) const noexcept { return std::hash<std::string_view>{}(s); }
};

class Router {
public:
    // Registers a site's server names. The first "*" name or `default = true` becomes
    // the default site; failing both, the first site added is.
    void add_site(const SiteConfig& site);

    // The site for a raw Host header value (may include a port); never null once a site
    // has been added.
    const SiteConfig* site(std::string_view host) const noexcept;

    // The location serving `path` (normalised, starting with '/'). A site always has at
    // least the implicit "/" prefix location, so this never fails.
    static const LocationConfig& location(const SiteConfig& site, std::string_view path) noexcept {
        for (const LocationConfig& loc : site.locations) {
            const bool hit = loc.exact    ? path == loc.path
                             : loc.suffix ? suffix_hit(path, loc.path)
                                          : path.starts_with(loc.path);
            if (hit) return loc;
        }
        return site.locations.back();
    }

    // A suffix matches at the end of the path or before a '/' ("/index.php/extra": PATH_INFO).
    static bool suffix_hit(std::string_view path, std::string_view suffix) noexcept {
        for (std::size_t p = path.find(suffix); p != std::string_view::npos; p = path.find(suffix, p + 1)) {
            const std::size_t end = p + suffix.size();
            if (end == path.size() || path[end] == '/') return true;
        }
        return false;
    }

    const SiteConfig* default_site() const noexcept { return default_site_; }

private:
    std::unordered_map<std::string, const SiteConfig*, StringViewHash, std::equal_to<>> by_name_;
    const SiteConfig* default_site_ = nullptr;
};

}  // namespace agensio
