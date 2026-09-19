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

    // The site for a raw Host header value (may include a port), or the catch-all, or
    // null when the host matches nothing and the listener has no catch-all.
    const SiteConfig* site(std::string_view host) const noexcept;

    // The location serving `path` (normalised, starting with '/'). A site always has at
    // least the implicit "/" prefix location, so this never fails.
    static const LocationConfig& location(const SiteConfig& site, std::string_view path) noexcept {
        // One pass over the sorted list: an exact hit wins at once; the first suffix and
        // the first (= longest) prefix hits are remembered. A `final` prefix (nginx ^~)
        // shields its subtree from suffix locations: /wp-content/uploads/x.php stays static.
        const LocationConfig* suffix = nullptr;
        for (const LocationConfig& loc : site.locations) {
            if (loc.exact) {
                if (path == loc.path) return loc;
            } else if (loc.suffix) {
                if (!suffix && suffix_hit(path, loc.path)) suffix = &loc;
            } else if (path.starts_with(loc.path)) {
                if (loc.final || !suffix) return loc;
                return *suffix;
            }
        }
        return suffix ? *suffix : site.locations.back();
    }

    // A suffix matches at the end of the path or before a '/' ("/index.php/extra": PATH_INFO).
    static bool suffix_hit(std::string_view path, std::string_view suffix) noexcept {
        for (std::size_t p = path.find(suffix); p != std::string_view::npos; p = path.find(suffix, p + 1)) {
            const std::size_t end = p + suffix.size();
            if (end == path.size() || path[end] == '/') return true;
        }
        return false;
    }

    // The listener's catch-all (`server_name = ["*"]` or `default = true`), or null: then a
    // Host no site lists is answered 421 Misdirected Request.
    const SiteConfig* default_site() const noexcept { return default_site_; }

private:
    std::unordered_map<std::string, const SiteConfig*, StringViewHash, std::equal_to<>> by_name_;
    const SiteConfig* default_site_ = nullptr;
};

}  // namespace agensio
