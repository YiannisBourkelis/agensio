#include "services/certificates.hpp"

#include "services/pools.hpp"

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cerrno>
#include <filesystem>
#include <optional>
#include <stdexcept>

#ifdef AGENSIO_HAS_TLS
#include <openssl/err.h>
#endif

namespace agensio {

#ifdef AGENSIO_HAS_TLS
// One certificate and key pair from its files: nullptr and why when it does not load, with what
// the server's account lacks after the privilege drop and root's commands (step T1).
std::shared_ptr<asio::ssl::context> load_certificate_pair(const Config& cfg, const TlsConfig& t, std::string& error) {
    auto ctx = std::make_shared<asio::ssl::context>(asio::ssl::context::tls_server);
    asio::error_code ec;
    ctx->use_certificate_chain_file(t.cert.string(), ec);
    if (ec) error = "certificate " + t.cert.string() + ": " + ec.message();
    else {
        ctx->use_private_key_file(t.key.string(), asio::ssl::context::pem, ec);  // also checks it is the certificate's key
        if (ec) error = "key " + t.key.string() + ": " + ec.message();
    }
    if (!ec) return ctx;
    ERR_clear_error();
    const HostFacts facts = system_facts();
    for (const auto& file : {t.cert.string(), t.key.string()}) {
        std::string fix;
        if (const std::string why = server_read_problem(cfg, facts, file, fix); !why.empty())
            error += " (" + cfg.user + ", the account the server runs as, cannot read " + file + ": " + why + "; fix: " + fix + ")";
    }
    return nullptr;
}

void isolate_certificates(Config& cfg, const Config* running, CertificateSet& out, const CertificateSet* previous,
                          const std::function<std::shared_ptr<asio::ssl::context>(const TlsConfig&, std::string&)>& load,
                          std::vector<std::string>& kept) {
    std::map<std::string, std::string> before;
    for (const auto& h : cfg.held_back) before[h.file] = h.error;
    set_aside_until_clean(cfg, running, [&](const Config& c) -> std::optional<SiteConflict> {
        for (std::size_t i = 0; i < c.sites.size(); ++i) {
            const SiteConfig& site = c.sites[i];
            if (!site.tls) continue;
            const std::string pair = site.tls->cert.string() + '\n' + site.tls->key.string();
            if (out.contains(pair)) continue;
            std::string error;
            if (auto ctx = load(*site.tls, error)) {
                out.emplace(pair, std::move(ctx));
                continue;
            }
            // A carried version (its file set aside, or set aside right here) keeps what the
            // running generation loaded from the same files.
            if (site.carried && previous)
                if (auto p = previous->find(pair); p != previous->end()) {
                    out.emplace(pair, p->second);
                    kept.push_back("site " + site.server_names.front() + ": " + error + "; the certificate loaded before keeps serving");
                    continue;
                }
            return SiteConflict{i, SiteConflict::npos, "site " + site.server_names.front() + ": the certificate could not be loaded: " + error};
        }
        return std::nullopt;
    });
    for (auto& h : cfg.held_back)  // what this step set aside, so validate and health can say it was the certificate
        if (auto b = before.find(h.file); b == before.end() || b->second != h.error) h.certificate = true;
    if (cfg.sites.empty()) {
        std::string why;
        for (const auto& h : cfg.held_back) why += "\n  " + h.file + ": " + h.error;
        throw std::runtime_error(cfg.config_path.string() + ": no site could be loaded; every site file was set aside:" + why);
    }
}
#endif

std::vector<std::string> check_certificates(Config& cfg, const Config* running) {
    std::vector<std::string> notes;
#ifdef AGENSIO_HAS_TLS
    // The start reads the files as root when server.user names another account; a -t that is not
    // root cannot tell a key it may not read from one the start may not read.
    bool judge_unreadable = true;
#ifndef _WIN32
    if (::geteuid() != 0 && !cfg.user.empty()) {
        unsigned uid = 0, gid = 0;
        judge_unreadable = system_facts().user(cfg.user, uid, gid) && uid == ::geteuid();
    }
#endif
    // The running generation holds a pair for every pair its sites name, so those are what a carried
    // site keeps (the material itself is not needed to tell).
    CertificateSet loaded, previous;
    if (running)
        for (const auto& s : running->sites)
            if (s.tls) previous.emplace(s.tls->cert.string() + '\n' + s.tls->key.string(), nullptr);
    std::vector<std::string> kept;
    isolate_certificates(cfg, running, loaded, running ? &previous : nullptr,
                         [&](const TlsConfig& t, std::string& error) -> std::shared_ptr<asio::ssl::context> {
                             std::error_code ec;
                             if (t.automatic && (!std::filesystem::is_regular_file(t.cert, ec) || !std::filesystem::is_regular_file(t.key, ec)))
                                 return std::make_shared<asio::ssl::context>(asio::ssl::context::tls_server);  // the start or reload writes a placeholder
#ifndef _WIN32
                             if (!judge_unreadable)
                                 for (const auto& f : {t.cert, t.key}) {
                                     const int fd = ::open(f.c_str(), O_RDONLY | O_CLOEXEC);
                                     if (fd >= 0) ::close(fd);
                                     else if (errno == EACCES) {
                                         notes.push_back(f.string() + ": not checked, this account cannot read it and the start reads it as root before it runs as " +
                                                         cfg.user + "; agensio -t as root loads the pair as the start does");
                                         return std::make_shared<asio::ssl::context>(asio::ssl::context::tls_server);
                                     }
                                 }
#endif
                             return load_certificate_pair(cfg, t, error);
                         },
                         kept);
#else
    (void)cfg;
    (void)running;
#endif
    return notes;
}

}  // namespace agensio
