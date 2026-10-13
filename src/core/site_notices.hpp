// What a request saw that only health can name (docs/redirects.md 2.4 and 4.1): a trusted proxy
// that sends no X-Forwarded-Proto to a site whose plain HTTP redirects (proxy_scheme_missing), an
// application's HSTS stronger than the site's, which replaced it (hsts_narrows_application). The
// worker that sees one writes it here under the mutex, behind a gate of its own (once a minute per
// site, once per generation of a site), and health reads a copy from worker 0. A request that
// meets neither never comes here.
#pragma once

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace agensio {

struct SiteNotice {
    std::string code;     // proxy_scheme_missing | hsts_narrows_application
    std::string site;     // the site's first name
    std::string subject;  // the proxy's address, or the application's HSTS value
    std::time_t first = 0, last = 0;
    std::time_t logged = 0;   // the error log's last line for it
    std::uint64_t count = 0;  // sightings written (each behind its worker's gate)
};

class SiteNotices {
public:
    // One sighting; true when the error log should say it: no line for this code, site and subject
    // in the last minute, whichever worker wrote it.
    bool note(std::string_view code, std::string_view site, std::string_view subject, std::time_t now) {
        subject = subject.substr(0, kSubject);
        std::lock_guard lock(m_);
        SiteNotice* n = nullptr;
        for (auto& e : list_)
            if (e.code == code && e.site == site && e.subject == subject) {
                n = &e;
                break;
            }
        if (!n) {  // a new one; when full, the one seen longest ago gives way
            n = list_.size() < kMax ? &list_.emplace_back()
                                    : &*std::min_element(list_.begin(), list_.end(), [](const SiteNotice& a, const SiteNotice& b) { return a.last < b.last; });
            *n = SiteNotice{std::string(code), std::string(site), std::string(subject), now, now, 0, 0};
        }
        n->last = now;
        ++n->count;
        if (n->logged != 0 && now - n->logged < 60) return false;
        n->logged = now;
        return true;
    }
    std::vector<SiteNotice> snapshot() const {
        std::lock_guard lock(m_);
        return list_;
    }

private:
    static constexpr std::size_t kMax = 64;
    static constexpr std::size_t kSubject = 256;
    mutable std::mutex m_;
    std::vector<SiteNotice> list_;
};

// The process's one store: workers note, health reads (Server::health_with).
inline SiteNotices& site_notices() {
    static SiteNotices notices;
    return notices;
}

}  // namespace agensio
