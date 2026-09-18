// Automatic certificates (H3): an ACME v2 client (RFC 8555) with the HTTP-01 challenge.
// The manager runs on worker 0's loop and does the network work on its own thread with
// blocking calls: it is management traffic a few times a year, never on the request path.
// The dispatcher answers /.well-known/acme-challenge/<token> from `AcmeChallenges`; a new
// certificate is picked up through the reload path (H1), so no request is interrupted.
#pragma once

#include <chrono>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <asio.hpp>

#include "config.hpp"
#include "services/log.hpp"

namespace agensio {

// Tokens of the orders in flight. Read by any worker, written by the manager thread.
class AcmeChallenges {
public:
    void add(std::string token, std::string key_authorization) {
        std::lock_guard lock(mutex_);
        tokens_[std::move(token)] = std::move(key_authorization);
    }
    void remove(const std::string& token) {
        std::lock_guard lock(mutex_);
        tokens_.erase(token);
    }
    // Copies the key authorization for `token` into `out`; false when unknown. Only reached
    // for targets under the challenge prefix, so the lock never touches ordinary requests.
    bool lookup(std::string_view token, std::string& out) const {
        std::lock_guard lock(mutex_);
        auto it = tokens_.find(token);
        if (it == tokens_.end()) return false;
        out = it->second;
        return true;
    }

private:
    mutable std::mutex mutex_;
    std::map<std::string, std::string, std::less<>> tokens_;
};

// One certificate we manage: the names it covers and where its files live.
struct AcmeSite {
    std::vector<std::string> names;  // the site's server_names
    std::filesystem::path dir;       // <storage>/<first name>
    std::filesystem::path key;       // dir/key.pem
    std::filesystem::path cert;      // dir/fullchain.pem
};

namespace acme {

// The sites with `tls = "auto"`, one entry per certificate directory.
std::vector<AcmeSite> sites_of(const Config& cfg);

// Creates the storage tree and a self-signed placeholder for every site without a
// certificate yet, so the TLS listeners can start before the first order completes. With
// `uid`/`gid` set (started as root with server.user) the tree is handed to that account so
// renewals still work after the privilege drop. Throws on failure.
void prepare_storage(const Config& cfg, const std::vector<AcmeSite>& sites, int uid, int gid);

// What a certificate file says: issuer, names, validity, whether it is our placeholder.
struct CertInfo {
    std::string issuer;
    std::vector<std::string> names;
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
    bool placeholder = false;
};
bool certificate_info(const std::filesystem::path& cert, CertInfo& out, std::string& error);

// True when the certificate at `cert` should be (re)issued for `names`: missing, unreadable,
// our placeholder, not covering every name, or less than a third of its lifetime left.
// `why` says which.
bool needs_renewal(const std::filesystem::path& cert, const std::vector<std::string>& names,
                   std::chrono::system_clock::time_point now, std::string& why);
// The renewal rule alone, unit tested: renew once a third of the lifetime is left.
bool renewal_due(std::chrono::system_clock::time_point not_before, std::chrono::system_clock::time_point not_after,
                 std::chrono::system_clock::time_point now) noexcept;

// Runs one order end to end (account, order, HTTP-01 for every name, finalize, download)
// and writes the site's key and chain. Blocking; meant for the manager's thread.
bool issue(const AcmeConfig& cfg, const AcmeSite& site, AcmeChallenges& challenges, ErrorLog& log,
           std::string& error);

// Pure helpers, unit tested.
std::string base64url(std::string_view bytes);
// JWS with ES256 over `protected_header` and `payload` (both already JSON text; the payload
// may be empty for POST-as-GET). `pem_key` is an EC P-256 private key in PEM.
std::string jws_sign(const std::string& pem_key, std::string_view protected_header, std::string_view payload,
                     std::string& error);
// The JWK of a PEM key and its RFC 7638 thumbprint (base64url of SHA-256 of the canonical JWK).
bool jwk_of(const std::string& pem_key, std::string& jwk_json, std::string& thumbprint, std::string& error);
bool jws_verify(const std::string& pem_key, std::string_view jws_json, std::string& error);  // tests only

}  // namespace acme

// Owns the schedule: an immediate check at start, then one an hour; every check orders
// the certificates that are due (one thread, sites one after the other), and when at
// least one was written `on_renewed` runs on the loop that started the manager.
class AcmeManager {
public:
    explicit AcmeManager(ErrorLog& log) : log_(log) {}
    ~AcmeManager();

    AcmeChallenges& challenges() noexcept { return challenges_; }

    // On `ctx`'s thread. `update` replaces the configuration and the sites (reload) and
    // checks at once when no order is running.
    void start(asio::io_context& ctx, const AcmeConfig& cfg, std::vector<AcmeSite> sites,
               std::function<void()> on_renewed);
    void update(const AcmeConfig& cfg, std::vector<AcmeSite> sites);
    // Orders `cert` again now, whatever its state; false when no managed site has it.
    bool renew_now(const std::filesystem::path& cert);
    void stop();

private:
    void check();
    void arm(std::chrono::seconds delay);

    ErrorLog& log_;
    asio::io_context* ctx_ = nullptr;
    std::unique_ptr<asio::steady_timer> timer_;
    AcmeConfig cfg_;
    std::vector<AcmeSite> sites_;
    std::map<std::string, std::chrono::steady_clock::time_point> failed_at_;  // by cert path; retried after an hour
    std::vector<std::string> forced_;  // cert paths to order at the next check regardless
    std::function<void()> on_renewed_;
    AcmeChallenges challenges_;
    std::thread worker_;  // not jthread: libc++ (macOS) ships it only as experimental
    bool busy_ = false;
    bool stopped_ = false;
};

}  // namespace agensio
