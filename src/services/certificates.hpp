// Certificate and key pairs loaded as the server loads them (design section 26, C3): the start, a
// reload, the certificate refresh, agensio -t and the control plane's view of the next reload
// (validate, health) share this code, so each says what the others do.
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#ifdef AGENSIO_HAS_TLS
#include <asio/ssl/context.hpp>
#endif

#include "config.hpp"

namespace agensio {

#ifdef AGENSIO_HAS_TLS
using CertificateSet = std::map<std::string, std::shared_ptr<asio::ssl::context>>;  // by "cert\nkey"
// One certificate and key pair from its files, as the start, a reload, the refresh and agensio -t
// load it: nullptr and why when it does not load (a file missing or unreadable, not PEM, a key that
// is not the certificate's), with what cfg.user lacks to read the files after the drop (step T1).
std::shared_ptr<asio::ssl::context> load_certificate_pair(const Config& cfg, const TlsConfig& t, std::string& error);
// The certificate step of the start, a reload and agensio -t (design section 26, C3): every TLS
// site's pair loaded once with `load` into `out`; a site whose pair does not load is set aside with
// its file (HeldBack::certificate), a carried one keeps `previous`'s material (said in `kept`).
// Throws for the main file's sites and when no site is left.
void isolate_certificates(Config& cfg, const Config* running, CertificateSet& out, const CertificateSet* previous,
                          const std::function<std::shared_ptr<asio::ssl::context>(const TlsConfig&, std::string&)>& load,
                          std::vector<std::string>& kept);
#endif
// The certificate step without a server: each pair loaded as the start loads it (the alpha.64 report,
// finding 1), or with `running` as the next reload would (a served site whose pair no longer loads
// keeps its running version, validate and health). Not an automatic certificate still to be issued
// (the start or the reload writes a placeholder), and not a file this process may not read while the
// start reads it as root (-t not root, server.user another account): the notes returned name those.
// Throws as the start does.
std::vector<std::string> check_certificates(Config& cfg, const Config* running = nullptr);

}  // namespace agensio
