#include "core/router.hpp"

#include "core/strings.hpp"

namespace agensio {

namespace {
inline char lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
}
}  // namespace

// A site answers the names it lists. The catch-all for a listener is the site that says so
// (`server_name = ["*"]` or `default = true`), never the first site that happened to be
// added: until 2026-09-19 a listener with one named site served every Host, so forged
// Host headers reached the application (the class Drupal's trusted_host_patterns and
// Laravel's TrustedHosts exist for). Unmatched hosts get 421 from the dispatcher.
void Router::add_site(const SiteConfig& site) {
    for (const auto& name : site.server_names) {
        if (name == "*") {
            if (!default_site_) default_site_ = &site;
        } else {
            by_name_.emplace(name, &site);
        }
    }
    if (site.is_default && !default_site_) default_site_ = &site;
}

const SiteConfig* Router::site(std::string_view host) const noexcept {
    if (host.empty()) return default_site_;
    // Strip the port: "example.com:8080", "[::1]:8080".
    if (host.front() == '[') {
        auto close = host.find(']');
        if (close != std::string_view::npos) host = slice(host, 1, close - 1);
    } else {
        auto colon = host.rfind(':');
        if (colon != std::string_view::npos) host = slice(host, 0, colon);
    }
    if (!host.empty() && host.back() == '.') host.remove_suffix(1);
    if (host.size() > 253) return default_site_;
    char buf[256];
    for (std::size_t i = 0; i < host.size(); ++i)
        buf[i] = lower(host[i]);
    auto it = by_name_.find(std::string_view(buf, host.size()));
    return it == by_name_.end() ? default_site_ : it->second;
}

}  // namespace agensio
