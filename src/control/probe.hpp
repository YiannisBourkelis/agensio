// What only a request to a site itself shows (docs/redirects.md 3.4, alpha.84): health asks each
// site with `canonical` once, over loopback, for its canonical home page. An application whose
// configured address is another of the site's names redirects there, and agensio sends that name
// back to the canonical one, so browsers loop: app_redirects_elsewhere, with the application's
// setting to change. The requests block, with a short timeout, so they run on a thread of their
// own (Server::health_async), never on a worker, which may be the one that has to answer them.
#pragma once

#include <ctime>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "control/commands.hpp"

namespace agensio::control {

struct CanonicalProbe {
    std::string site;       // the site's first name, for the finding
    std::string canonical;  // the name asked for
    std::string app;        // which setting the fix names
    std::vector<std::string> names;  // every name the site lists
    std::string host, port;          // the site's listener, a wildcard address asked over loopback
    bool tls = false;
};

// One probe per site whose other names redirect to its canonical one, copied out of the
// configuration so the thread never reads it.
std::vector<CanonicalProbe> canonical_probes(const Config& cfg);
// The finding an answer gives, or none: a redirect whose Location names another of the site's names.
std::optional<Finding> judge_canonical_answer(const CanonicalProbe& p, int status, std::string_view location);
// Every probe, one request each (GET /, Connection: close), at most `timeout_ms` per step, all at once;
// a site that does not answer gives no finding here (health has its own findings for that).
std::vector<Finding> run_canonical_probes(const std::vector<CanonicalProbe>& probes, int timeout_ms = 3000);

// hsts_from_application before any visitor (docs/redirects.md 4.2, the alpha.87/88 report): the
// request path notes an application's own HSTS only once an HTTPS answer has carried it, so after a
// start health would suggest the site's over it until the first visitor came. Health asks each site
// where the suggestion could show (no hsts line, an application behind it, a real certificate for a
// week, nothing noted yet) once for its home page; the server's own request path notes the field.
std::vector<CanonicalProbe> hsts_probes(const Config& cfg, const TlsFacts& tls, std::time_t now);
void run_hsts_probes(const std::vector<CanonicalProbe>& probes, int timeout_ms = 3000);

}  // namespace agensio::control
