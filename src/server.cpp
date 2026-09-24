#include "server.hpp"

#include "core/cpus.hpp"
#include "control/commands.hpp"
#include "control/peer.hpp"
#include "services/install.hpp"
#include "services/pools.hpp"
#include "services/provision.hpp"

#ifndef _WIN32
#include <fcntl.h>
#include <grp.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <chrono>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <csignal>
#include <iostream>
#include <stdexcept>
#include <thread>

#include "file.hpp"
#include "http1/connection.hpp"
#include "response.hpp"

#ifdef AGENSIO_HAS_TLS
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

namespace agensio {

namespace {

#if defined(SO_REUSEPORT)
using reuse_port_option = asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT>;
constexpr bool kHasReusePort = true;
#else
using reuse_port_option = asio::socket_base::reuse_address;  // placeholder, never used
constexpr bool kHasReusePort = false;
#endif

asio::ip::tcp::endpoint parse_endpoint(const std::string& address) {
    auto colon = address.rfind(':');
    std::string host = address.substr(0, colon);
    unsigned short port = static_cast<unsigned short>(std::stoi(address.substr(colon + 1)));
    asio::error_code ec;
    auto ip = asio::ip::make_address(host, ec);
    if (ec) throw std::runtime_error("invalid listen address '" + address + "'");
    return asio::ip::tcp::endpoint(ip, port);
}

}  // namespace

Server::Server(Config cfg)
    : cfg_(cfg),
      cache_(cfg_.cache_max_file_size, cfg_.cache_max_size, cfg_.cache_evict_fraction, cfg_.cache_max_open_files),
      handler_(cfg_, cache_),
      fcgi_handler_(cfg_, error_log_),
      proxy_handler_(cfg_, error_log_),
      cgi_handler_(cfg_, error_log_),
      control_handler_(error_log_),
      dispatcher_(handler_, fcgi_handler_, proxy_handler_, cgi_handler_, control_handler_, httparena_handler_) {
    auto gen = std::make_shared<Generation>();
    gen->cfg = std::move(cfg);
    open_logs();
    if (cfg_.control.enabled) audit_sink_ = logs_.add(cfg_.control.audit);
    control_handler_.attach(this, &logs_, audit_sink_);
    assign_log_sinks(gen->cfg);
    std::string err;
    if (!logs_.open_all(err)) throw std::runtime_error(err);
    own_site_logs(gen->cfg);
    warm_response_tables();
    prepare_acme(gen->cfg);
    build_listeners(*gen);
    gen_ = std::move(gen);
    build_workers();
    dispatcher_.set_acme(&acme_.challenges());
    dispatcher_.set_error_log(&error_log_);
}

// The ACME storage tree, owned by server.user when we start as root so the manager can
// still write renewals after the privilege drop, and a self-signed placeholder for every
// certificate that does not exist yet so the listener can come up before the first order.
void Server::prepare_acme(const Config& cfg) {
#ifdef AGENSIO_HAS_TLS
    const auto sites = acme::sites_of(cfg);
    if (sites.empty()) return;
    int uid = -1, gid = -1;
#ifndef _WIN32
    if (!cfg_.user.empty() && ::geteuid() == 0) {
        unsigned u = 0, g = 0;
        const HostFacts facts = system_facts();
        if (facts.user(cfg_.user, u, g)) {
            if (!cfg_.group.empty()) facts.group(cfg_.group, g);
            uid = static_cast<int>(u);
            gid = static_cast<int>(g);
        }
    }
#endif
    acme::prepare_storage(cfg, sites, uid, gid);
#else
    (void)cfg;
#endif
}

Server::~Server() {
    stop();
    remove_pid_file();
}

// The error log first so startup messages have somewhere to go.
void Server::open_logs() {
    const int error_sink = logs_.add(cfg_.log.error);
    LogLevel level = LogLevel::warn;
    parse_log_level(cfg_.log.level, level);
    error_log_.configure(&logs_, error_sink, level);
}

// One sink per distinct path, shared across generations (the registry keeps a path's
// descriptor as long as the process runs).
void Server::assign_log_sinks(Config& cfg) {
    for (auto& site : cfg.sites) {
        site.access_log_sink = logs_.add(site.access_log);
        if (site.access_log_sink >= 0) access_logging_ = true;
    }
}

// A site with `user` gets its access log as agensio:<site group> 0640: agensio writes it
// as the owner (also after a SIGUSR1 reopen once privileges are dropped), the customer
// reads it through the group, nobody else. Needs root (or CAP_CHOWN); otherwise one
// warning per site and the file stays ours.
void Server::own_site_logs(const Config& cfg) {
#ifndef _WIN32
    const HostFacts facts = system_facts();
    unsigned agensio_uid = ::geteuid();
    unsigned agensio_gid = ::getegid();
    if (!cfg_.user.empty()) {
        unsigned primary = 0;
        if (facts.user(cfg_.user, agensio_uid, primary)) agensio_gid = primary;
    }
    if (!cfg_.group.empty()) facts.group(cfg_.group, agensio_gid);
    // The server's own files (error, default access, audit) were opened as root: hand them
    // to the service user so SIGUSR1 can reopen them after the privilege drop.
    if (::geteuid() == 0 && !cfg_.user.empty()) {
        for (const std::string& path : {cfg.log.error, cfg.log.access, cfg.control.audit}) {
            if (path.empty() || path == "stderr" || path == "off") continue;
            if (::chown(path.c_str(), agensio_uid, agensio_gid) == 0) ::chmod(path.c_str(), 0640);
        }
    }
    for (const auto& site : cfg.sites) {
        if (site.user.empty() || site.access_log.empty()) continue;
        unsigned uid = 0, gid = 0;
        if (!facts.user(site.user, uid, gid)) continue;  // check_hosting already refused this
        if (!site.group.empty()) facts.group(site.group, gid);
        // Already the site's group: nothing to do (a non-root chown to the same owner still
        // fails with EPERM, which warned on every reload before 2026-09-20). Otherwise the
        // helper hands it over at creation; only without one is there something to warn about.
        struct stat st {};
        if (::stat(site.access_log.c_str(), &st) == 0 && st.st_gid == gid && (st.st_mode & 0040)) continue;
        if (::chown(site.access_log.c_str(), agensio_uid, gid) != 0) {
            if (provisioner_.available()) continue;  // site-create's log_own does it and verifies it
            error_log_.warn("cannot chown " + site.access_log + " to " + std::to_string(agensio_uid) + ":" +
                            (site.group.empty() ? site.user : site.group) + " (not root); " + site.user +
                            " cannot read its log");
            continue;
        }
        ::chmod(site.access_log.c_str(), 0640);
    }
#endif
}

// Root only for what needs it: binding privileged ports and opening files other users
// must not write. Everything after this runs as server.user. Sockets and log descriptors
// stay open across the switch. Refuses to keep running as root when no user is given.
void Server::drop_privileges() {
#ifndef _WIN32
    if (cfg_.user.empty()) {
        if (::geteuid() == 0) error_log_.warn("running as root; set server.user to drop privileges after binding");
        return;
    }
    unsigned uid = 0, gid = 0;
    const HostFacts facts = system_facts();
    if (!facts.user(cfg_.user, uid, gid)) throw std::runtime_error("server.user: user '" + cfg_.user + "' does not exist");
    if (!cfg_.group.empty() && !facts.group(cfg_.group, gid))
        throw std::runtime_error("server.group: group '" + cfg_.group + "' does not exist");
    if (::geteuid() == uid && ::getegid() == gid) return;  // already that user (started by systemd as it)
    if (::geteuid() != 0)
        throw std::runtime_error("server.user is set to '" + cfg_.user + "' but agensio is not root and cannot switch");
    if (::initgroups(cfg_.user.c_str(), static_cast<gid_t>(gid)) != 0 || ::setgid(static_cast<gid_t>(gid)) != 0 ||
        ::setuid(static_cast<uid_t>(uid)) != 0)
        throw std::runtime_error("cannot switch to user " + cfg_.user + ": " + std::strerror(errno));
    if (::setuid(0) == 0) throw std::runtime_error("privilege drop did not stick");
    error_log_.info("running as " + cfg_.user + " (uid " + std::to_string(uid) + ", gid " + std::to_string(gid) + ")");
#endif
}

#if defined(__GLIBC__)
#include <malloc.h>
#endif
static void trim_heap() noexcept {
#if defined(__GLIBC__)
    malloc_trim(0);
#endif
}

void Server::arm_flush(Worker& w) {
    w.flush_timer.expires_after(std::chrono::seconds(1));
    w.flush_timer.async_wait([this, &w](const asio::error_code& ec) {
        if (ec) return;
        w.state.logs.flush();
        // Buffers shed by idle connections and those of closed connections are freed, but
        // glibc keeps freed chunks of that size mapped: a trim once a second, only when
        // something was freed, gives the pages back (measured: 3,000 idle connections held
        // 75 MB of RSS until this ran, and a burst of closes left the peak mapped for good).
        if (w.sheds) {
            w.sheds = 0;
            trim_heap();
        }
        arm_flush(w);
    });
}

#ifdef AGENSIO_HAS_TLS
// The names a context's certificate covers: the subject CN and every DNS and IP entry of
// the subjectAltName, parsed once at load; what a connection is authoritative for.
static CertNames certificate_names(SSL_CTX* ctx) {
    CertNames names;
    X509* x = SSL_CTX_get0_certificate(ctx);
    if (!x) return names;
    char cn[256] = {};
    if (X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, cn, sizeof cn) > 0) names.add(cn);
    if (auto* sans = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr))) {
        for (int i = 0; i < sk_GENERAL_NAME_num(sans); ++i) {
            const GENERAL_NAME* g = sk_GENERAL_NAME_value(sans, i);
            if (g->type == GEN_DNS) {
                names.add(std::string_view(reinterpret_cast<const char*>(ASN1_STRING_get0_data(g->d.dNSName)),
                                           static_cast<std::size_t>(ASN1_STRING_length(g->d.dNSName))));
            } else if (g->type == GEN_IPADD) {
                const unsigned char* b = ASN1_STRING_get0_data(g->d.iPAddress);
                const int len = ASN1_STRING_length(g->d.iPAddress);
                if (len == 4) names.add(asio::ip::address_v4(std::array<unsigned char, 4>{b[0], b[1], b[2], b[3]}).to_string());
                else if (len == 16) {
                    std::array<unsigned char, 16> v6{};
                    std::copy(b, b + 16, v6.begin());
                    names.add(asio::ip::address_v6(v6).to_string());
                }
            }
        }
        GENERAL_NAMES_free(sans);
    }
    return names;
}

// SNI: the certificate of the site that lists the requested name, or the listener's
// catch-all's when the client sent no name; a name no site lists ends the handshake with
// unrecognized_name, so no other site's certificate is ever shown (which would disclose
// what else is hosted here) and no site serves a host it did not claim.
static int select_certificate(SSL* ssl, int* alert, void* arg) {
    const auto* listener = static_cast<const Listener*>(arg);
    const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    const SiteConfig* site = listener->router.site(name ? std::string_view(name) : std::string_view());
    if (!site || !site->tls) {
        *alert = SSL_AD_UNRECOGNIZED_NAME;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    auto it = listener->tls_contexts.find(site->tls->cert.string());
    if (it == listener->tls_contexts.end()) {
        *alert = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    if (SSL_get_SSL_CTX(ssl) != it->second->native_handle()) SSL_set_SSL_CTX(ssl, it->second->native_handle());
    return SSL_TLSEXT_ERR_OK;
}
#endif

#ifdef AGENSIO_HAS_TLS
// ALPN (HTTP/2, phase G): the first protocol of our list the client offers wins, in our
// order; a client without ALPN, or without any of ours, gets no selection and speaks
// HTTP/1.1 as before. Set on every context, since the SNI callback switches contexts.
static int select_protocol(SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in,
                           unsigned inlen, void* arg) {
    const auto* l = static_cast<const Listener*>(arg);
    if (l->alpn.empty()) return SSL_TLSEXT_ERR_NOACK;
    unsigned char* selected = nullptr;
    unsigned char selected_len = 0;
    const int r = SSL_select_next_proto(&selected, &selected_len, reinterpret_cast<const unsigned char*>(l->alpn.data()),
                                        static_cast<unsigned>(l->alpn.size()), in, inlen);
    if (r != OPENSSL_NPN_NEGOTIATED) return SSL_TLSEXT_ERR_NOACK;
    *out = selected;
    *outlen = selected_len;
    return SSL_TLSEXT_ERR_OK;
}
#endif

void Server::build_listeners(Generation& gen) {
    auto& listeners = gen.listeners;
    for (const auto& site : gen.cfg.sites) {
        for (const auto& address : site.listen) {
            Listener* l = nullptr;
            for (auto& existing : listeners)
                if (existing.address == address) {
                    l = &existing;
                    break;
                }
            if (!l) {
                listeners.emplace_back();
                l = &listeners.back();
                l->address = address;
                l->endpoint = parse_endpoint(address);
                l->address_text = l->endpoint.address().to_string();
                l->port = l->endpoint.port();
                l->tls = site.tls.has_value();
                l->h2 = site.h2;
                l->h2c = site.h2c;
#ifdef AGENSIO_HAS_TLS
                l->alpn = site.alpn_wire;
#else
                if (l->tls)
                    throw std::runtime_error("site on " + address +
                                             " requires TLS but agensio was built without OpenSSL");
#endif
            }
#ifdef AGENSIO_HAS_TLS
            // One context per certificate on the listener; the first one starts every
            // handshake and the SNI callback switches to the site's own.
            if (site.tls && !l->tls_contexts.contains(site.tls->cert.string())) {
                auto ctx = std::make_shared<asio::ssl::context>(asio::ssl::context::tls_server);
                ctx->set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                                 asio::ssl::context::no_sslv3 | asio::ssl::context::no_tlsv1 |
                                 asio::ssl::context::no_tlsv1_1 | asio::ssl::context::single_dh_use);
                ctx->use_certificate_chain_file(site.tls->cert.string());
                ctx->use_private_key_file(site.tls->key.string(), asio::ssl::context::pem);
                SSL_CTX_set_min_proto_version(ctx->native_handle(), TLS1_2_VERSION);
                // SSL_MODE_RELEASE_BUFFERS deliberately not set: it costs a malloc/free per record.
                SSL_CTX_set_options(ctx->native_handle(), SSL_OP_NO_COMPRESSION);
                if (!l->ssl) l->ssl = ctx;
                l->cert_names.emplace(ctx->native_handle(), std::make_shared<const CertNames>(certificate_names(ctx->native_handle())));
                l->tls_contexts.emplace(site.tls->cert.string(), std::move(ctx));
            }
#endif
            l->router.add_site(site);
            l->site_names.push_back(site.server_names.front());
        }
    }
#ifdef AGENSIO_HAS_TLS
    // The vector is complete: each listener's address is stable for the callback argument.
    for (auto& l : listeners) {
        for (auto& [path, ctx] : l.tls_contexts) {
            SSL_CTX_set_tlsext_servername_callback(ctx->native_handle(), select_certificate);
            SSL_CTX_set_tlsext_servername_arg(ctx->native_handle(), &l);
            SSL_CTX_set_alpn_select_cb(ctx->native_handle(), select_protocol, &l);
        }
    }
#endif
    if (gen.cfg.control.enabled) {
        gen.control_site = control_site();
        gen.control = std::make_unique<Listener>();
        gen.control->address = "unix:" + gen.cfg.control.socket;
        gen.control->address_text = "unix";
        gen.control->router.add_site(gen.control_site);
    }
}

// ---- control socket (F0/F1) ----

void Server::open_control() {
    if (!cfg_.control.enabled) return;
#ifdef ASIO_HAS_LOCAL_SOCKETS
    const HostFacts facts = system_facts();
    unsigned uid = 0, gid = 0;
    const bool have_user = !cfg_.user.empty() && facts.user(cfg_.user, uid, gid);
    if (!cfg_.group.empty()) facts.group(cfg_.group, gid);
    server_uid_ = have_user ? static_cast<long>(uid) : static_cast<long>(::geteuid());
    auto group_id = [&](const std::string& name, const char* key) -> long {
        if (name.empty()) return -1;
        unsigned g = 0;
        if (facts.group(name, g)) return static_cast<long>(g);
        error_log_.warn(std::string("control.") + key + ": group '" + name + "' does not exist; nobody gets that role");
        return -1;
    };
    control_groups_.admins = group_id(cfg_.control.admins, "admins");
    control_groups_.operators = group_id(cfg_.control.operators, "operators");
    control_groups_.viewers = group_id(cfg_.control.viewers, "viewers");

    // The directory is part of the boundary: owned by the server, never world-writable, so
    // no site user can replace the socket path. The socket itself is 0660 for the admin
    // group when that is the only group, otherwise 0666: every connection is gated by its
    // peer credentials regardless, the file mode is the second line.
    const std::filesystem::path path = cfg_.control.socket;
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) throw std::runtime_error("control: cannot create " + path.parent_path().string() + ": " + ec.message());
    ::chmod(path.parent_path().c_str(), 0755);
    if (have_user && ::geteuid() == 0 && ::chown(path.parent_path().c_str(), uid, gid) != 0)
        error_log_.warn("control: cannot chown " + path.parent_path().string());
    ::unlink(path.c_str());
    control_acceptor_ = std::make_unique<asio::local::stream_protocol::acceptor>(workers_[0]->ctx);
    control_acceptor_->open();
    control_acceptor_->bind(asio::local::stream_protocol::endpoint(path.string()));
    control_acceptor_->listen(64);
    const bool one_group = control_groups_.admins >= 0 && control_groups_.operators < 0 && control_groups_.viewers < 0;
    if (::geteuid() == 0) {
        if (::chown(path.c_str(), have_user ? uid : 0, one_group ? static_cast<gid_t>(control_groups_.admins) : gid) != 0)
            error_log_.warn("control: cannot chown " + path.string());
    }
    ::chmod(path.c_str(), one_group ? 0660 : 0666);
    error_log_.info("control socket " + path.string() + (one_group ? " (0660, group " + cfg_.control.admins + ")" : " (0666, roles by peer credentials)"));
    std::cout << "  control socket " << path.string() << "\n";
#else
    error_log_.warn("control socket: unix domain sockets are not available on this platform; [control] ignored");
#endif
}

void Server::start_accept_control() {
#ifdef ASIO_HAS_LOCAL_SOCKETS
    if (!control_acceptor_) return;
    Worker& w = *workers_[0];
    control_acceptor_->async_accept(w.ctx, [this, &w](const asio::error_code& ec, asio::local::stream_protocol::socket sock) {
        if (ec == asio::error::operation_aborted || stopping_) return;
        if (!ec) {
            long uid = -1, gid = -1;
            Role role = Role::none;
            if (peer_credentials(sock.native_handle(), uid, gid))
                role = role_of(uid, gid, groups_of(uid), server_uid_, control_groups_);
            std::shared_ptr<const Generation> gen = w.gen;
            if (role == Role::none || !gen || !gen->control) {
                control_handler_.audit(uid, gid, role, "connect", "refused");
                asio::error_code ignored;
                sock.close(ignored);
            } else {
                auto c = std::make_shared<Http1Connection<asio::local::stream_protocol::socket>>(
                    std::move(sock), w, gen, gen->control.get(), cfg_, dispatcher_);
                c->set_peer(uid, gid, static_cast<std::uint8_t>(role));
                c->start();
            }
        }
        start_accept_control();
    });
#endif
}

json::Value Server::sites() { return control::sites(gen_->cfg, std::time(nullptr)); }

json::Value Server::site(std::string_view name, bool& found) {
    const SiteConfig* s = control::find_site(gen_->cfg, name);
    found = s != nullptr;
    return s ? control::site(gen_->cfg, *s, std::time(nullptr)) : json::Value();
}

json::Value Server::validate() { return control::validate(cfg_.config_path, cfg_); }

json::Value Server::logs(std::string_view target) {
    control::LogQuery q;
    const std::time_t now = std::time(nullptr);
    q.site = control::query_value(target, "site");
    const std::string since = control::query_value(target, "since");
    if (since.empty() || !control::parse_since(since, now, q.since)) q.since = now - 3600;
    const std::string level = control::query_value(target, "level");
    if (level == "error" || level == "warn" || level == "info") q.level = level;
    const std::string status = control::query_value(target, "status");
    if (status == "all") q.status_min = 0;
    else if (status == "4xx") q.status_min = 400;
    else if (!status.empty() && std::isdigit(static_cast<unsigned char>(status[0]))) q.status_min = std::atoi(status.c_str());
    const std::string limit = control::query_value(target, "limit");
    if (!limit.empty()) q.limit = static_cast<std::size_t>(std::clamp(std::atol(limit.c_str()), 1L, 5000L));
    return control::logs(gen_->cfg, q);
}

json::Value Server::health() {
#ifdef _WIN32
    const bool as_root = false;
#else
    const bool as_root = ::geteuid() == 0;
#endif
    return control::health(gen_->cfg, cfg_, as_root, std::time(nullptr));
}

json::Value Server::status() {
    json::Value v = json::Value::object();
    v.set("version", AGENSIO_VERSION);
    v.set("pid", static_cast<double>(::getpid()));
    v.set("uptime_s", static_cast<double>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - started_).count()));
    v.set("config", gen_->cfg.config_path.string());
    v.set("workers", static_cast<double>(workers_.size()));
    std::uint64_t conns = 0;
    for (const auto& w : workers_) conns += w->connections.load(std::memory_order_relaxed);
    v.set("connections", static_cast<double>(conns));
    v.set("user", cfg_.user);
    json::Value listeners = json::Value::array();
    for (const auto& l : gen_->listeners) {
        json::Value entry = json::Value::object().set("address", l.address).set("tls", l.tls).set("sites", static_cast<double>(l.site_names.size()));
        json::Value protocols = json::Value::array();
        if (l.tls) {
            if (l.h2) protocols.push("h2");
            protocols.push("h1");
        } else {
            if (l.h2c) protocols.push("h2c");
            protocols.push("h1");
        }
        entry.set("protocols", std::move(protocols));
        const SiteConfig* all = l.router.default_site();
        entry.set("catch_all", all ? json::Value(all->server_names.front()) : json::Value(nullptr));
        listeners.push(std::move(entry));
    }
    v.set("listeners", std::move(listeners));
    json::Value sites = json::Value::array();
    for (const auto& s : gen_->cfg.sites) {
        json::Value names = json::Value::array();
        for (const auto& n : s.server_names) names.push(n);
        json::Value listen = json::Value::array();
        for (const auto& a : s.listen) listen.push(a);
        json::Value site = json::Value::object().set("server_name", std::move(names)).set("listen", std::move(listen));
        site.set("root", s.root).set("app", s.app).set("user", s.user);
        site.set("tls", !s.tls ? "none" : s.tls->automatic ? "auto" : "manual");
        if (!s.redirect.empty()) site.set("redirect", s.redirect);
        sites.push(std::move(site));
    }
    v.set("sites", std::move(sites));
    v.set("acme", gen_->cfg.acme.enabled);
    return v;
}

void Server::build_workers() {
    unsigned n = cfg_.workers ? cfg_.workers : available_cpus();  // the affinity mask: a container's cpuset counts
    if (n == 0) n = 1;
    for (unsigned i = 0; i < n; ++i)
        workers_.push_back(std::make_unique<Worker>(i));
    for (auto& w : workers_)
        if (!cfg_.server_header.empty()) w->state.server_line = "Server: " + cfg_.server_header + "\r\n";

    reuse_port_ = false;
    if (cfg_.reuse_port == "on") reuse_port_ = kHasReusePort;
#ifdef __linux__
    if (cfg_.reuse_port == "auto") reuse_port_ = kHasReusePort;
#endif
    if (cfg_.reuse_port == "on" && !kHasReusePort)
        error_log_.warn("SO_REUSEPORT is not available on this platform; using a shared acceptor");
}

std::size_t Server::open_acceptor(const Listener& listener, Worker& worker, bool reuse_port) {
    // A closed slot of the same worker is reused so the indexes captured by accept
    // handlers stay valid.
    auto acc = std::make_unique<Acceptor>(worker.ctx, listener.address, &worker);
    open_acceptor_socket(*acc, listener, reuse_port);  // throws before the table changes
    for (std::size_t i = 0; i < acceptors_.size(); ++i)
        if (!acceptors_[i]->open && acceptors_[i]->closed.load(std::memory_order_acquire) &&
            acceptors_[i]->owner == &worker) {
            acceptors_[i] = std::move(acc);
            return i;
        }
    acceptors_.push_back(std::move(acc));
    return acceptors_.size() - 1;
}

void Server::open_acceptor_socket(Acceptor& acc, const Listener& listener, bool reuse_port) {
    auto& s = acc.socket;
    s.open(listener.endpoint.protocol());
    s.set_option(asio::socket_base::reuse_address(true));
    if (reuse_port) s.set_option(reuse_port_option(true));
    if (listener.endpoint.address().is_v6()) {
        asio::error_code ec;
        s.set_option(asio::ip::v6_only(false), ec);
    }
    asio::error_code ec;
    s.bind(listener.endpoint, ec);
    if (ec) throw std::runtime_error("cannot bind " + listener.address + ": " + ec.message());
    s.listen(4096, ec);
    if (ec) throw std::runtime_error("cannot listen on " + listener.address + ": " + ec.message());
}

void Server::start_accept(std::size_t index) {
    Acceptor& acc = *acceptors_[index];
    if (!acc.open) return;
    Worker& target =
        reuse_port_ ? *acc.owner : *workers_[next_worker_.fetch_add(1, std::memory_order_relaxed) % workers_.size()];
    acc.socket.async_accept(
        target.ctx, [this, index, &acc, &target](const asio::error_code& ec, asio::ip::tcp::socket sock) {
            if (ec == asio::error::operation_aborted || stopping_.load(std::memory_order_relaxed) || !acc.open) return;
            if (ec == asio::error::no_descriptors || ec == asio::error::no_buffer_space ||
                ec == std::errc::too_many_files_open_in_system) {
                // Out of descriptors: retrying immediately would spin at 100 % CPU while the
                // clients holding them idle. Pause, let timeouts free some, then resume.
                error_log_.error("accept: " + ec.message() + "; pausing accepts for 100 ms");
                acc.backoff.expires_after(std::chrono::milliseconds(100));
                acc.backoff.async_wait([this, index](const asio::error_code& tec) {
                    if (!tec) start_accept(index);
                });
                return;
            }
            if (!ec) {
                if (cfg_.tcp_nodelay) {
                    asio::error_code ignored;
                    sock.set_option(asio::ip::tcp::no_delay(true), ignored);
                }
                // This handler runs on `target`'s loop, so its generation is safe to read.
                std::shared_ptr<const Generation> gen = target.gen;
                const Listener* l = gen ? gen->find(acc.address) : nullptr;
                if (!l) {  // the address left the configuration a moment ago: nothing to serve
                    asio::error_code ignored;
                    sock.close(ignored);
                } else if (l->tls) {
#ifdef AGENSIO_HAS_TLS
                    auto c = std::make_shared<Http1Connection<TlsStream>>(TlsStream(std::move(sock), *l->ssl), target,
                                                                     std::move(gen), l, cfg_, dispatcher_);
                    if (&target == acc.owner) c->start();
                    else asio::post(target.ctx, [c] { c->start(); });
#endif
                } else {
                    auto c = std::make_shared<Http1Connection<asio::ip::tcp::socket>>(std::move(sock), target,
                                                                                       std::move(gen), l, cfg_, dispatcher_);
                    if (&target == acc.owner) c->start();
                    else asio::post(target.ctx, [c] { c->start(); });
                }
            }
            start_accept(index);
        });
}

void Server::run() {
    raise_open_file_limit();
#ifndef _WIN32
    // A peer that closes mid-response must surface as EPIPE from send()/sendfile(), not kill
    // the process. Asio passes MSG_NOSIGNAL (Linux) or sets SO_NOSIGPIPE (BSD/macOS) on its
    // own sockets, but OpenSSL's socket BIO (TlsStream) and our sendfile() calls write to the
    // descriptor directly; on Linux those raised SIGPIPE under load.
    std::signal(SIGPIPE, SIG_IGN);
#endif
    if (reuse_port_) {
        for (const auto& l : gen_->listeners)
            for (auto& w : workers_)
                open_acceptor(l, *w, true);
    } else {
        for (const auto& l : gen_->listeners)
            open_acceptor(l, *workers_[0], false);
    }
    open_control();
    prepare_uploads();
    write_pid_file();
    // The provisioning helper keeps root for the five operations site creation needs;
    // forked before the drop so that nothing else in this process is ever root again.
    if (cfg_.control.enabled && cfg_.control.provision) provisioner_.start(gen_->cfg, error_log_);
    drop_privileges();  // ports are bound and logs open: nothing else needs root
    for (auto& w : workers_) w->gen = gen_;
#ifdef AGENSIO_HAS_TLS
    // Automatic certificates: orders run on the manager's thread, the result comes back
    // through reload() so the new certificate is picked up without touching a request.
    acme_.start(workers_[0]->ctx, gen_->cfg.acme, acme::sites_of(gen_->cfg), [this] {
        error_log_.info("acme: new certificate(s) on disk, reloading");
        reload();
    });
#endif
    for (auto& w : workers_) {
        guards_.push_back(
            std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(w->ctx.get_executor()));
        w->state.logs.attach(&logs_,
                             cfg_.log.json ? AccessLogFormat::json : AccessLogFormat::combined);
        arm_flush(*w);  // always: a reload may add the first access log later
    }
    for (std::size_t i = 0; i < acceptors_.size(); ++i)
        start_accept(i);
    start_accept_control();

    asio::signal_set signals(workers_[0]->ctx, SIGINT, SIGTERM);
    signals.async_wait([this](const asio::error_code& ec, int) {
        if (!ec) stop();
    });
#ifndef _WIN32
    // Reload: SIGHUP (also what `agensio reload` sends) loads the file again and switches.
    // The handlers re-arm themselves and, like the signal sets, live in this frame for
    // as long as the loop runs (a self-owning std::function was a reference cycle the
    // sanitizer reported at exit).
    asio::signal_set hup(workers_[0]->ctx, SIGHUP);
    std::function<void(const asio::error_code&, int)> on_hup;
    on_hup = [this, &hup, &on_hup](const asio::error_code& ec, int) {
        if (ec) return;
        reload();
        hup.async_wait(on_hup);
    };
    hup.async_wait(on_hup);
    // Log rotation: SIGUSR1 reopens every log file (logrotate's postrotate hook).
    asio::signal_set reopen(workers_[0]->ctx, SIGUSR1);
    std::function<void(const asio::error_code&, int)> on_reopen;
    on_reopen = [this, &reopen, &on_reopen](const asio::error_code& ec, int) {
        if (ec) return;
        logs_.reopen_all();
        error_log_.info("log files reopened (SIGUSR1)");
        reopen.async_wait(on_reopen);
    };
    reopen.async_wait(on_reopen);
#endif

    for (std::size_t i = 1; i < workers_.size(); ++i) {
        Worker* w = workers_[i].get();
        threads_.emplace_back([w] { w->ctx.run(); });
    }
    workers_[0]->ctx.run();
    for (auto& t : threads_)
        t.join();
    threads_.clear();
    for (auto& w : workers_)
        w->state.logs.flush();
}

// The uploads directory: created by the server for itself (0700), so an archive put there
// by `agensio ctl upload` is readable by nobody else until the install reads it.
void Server::prepare_uploads() {
    if (!cfg_.control.enabled) return;
#ifndef _WIN32
    const std::string dir = provision::uploads_dir(cfg_);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        error_log_.warn("control: cannot create " + dir + " (" + ec.message() + "); uploads and installs from uploads are off");
        return;
    }
    if (::geteuid() == 0 && !cfg_.user.empty()) {
        unsigned uid = 0, gid = 0;
        if (system_facts().user(cfg_.user, uid, gid) && ::chown(dir.c_str(), uid, gid) != 0)
            error_log_.warn("control: cannot chown " + dir + ": " + std::strerror(errno));
    }
    ::chmod(dir.c_str(), 0700);
    if (::access(dir.c_str(), W_OK) != 0 && ::geteuid() != 0) {
        error_log_.warn("control: " + dir + " is not writable; uploads are off");
        return;
    }
    uploads_dir_ = dir;
#endif
}

void Server::install_async(const json::Value& req, std::function<void(json::Value)> done) {
    // Off the worker: the helper's request blocks for the download's duration, and so does
    // the in-process install. The result is posted back to worker 0, where the control
    // connection lives.
    std::thread([this, req, done = std::move(done)] {
        json::Value r;
        const bool copy = req.get("op") == "file_copy";
        if (provisioner_.available()) {
            json::Value h = req;
            if (!copy) h.set("op", "app_install");
            r = provisioner_.request(h);
        } else if (copy) {
#ifndef _WIN32
            install::CopyRequest cr;
            cr.site_root = std::string(req.get("site_root"));
            cr.from = std::string(req.get("from"));
            cr.to = std::string(req.get("to"));
            cr.overwrite = req["overwrite"].boolean();
            cr.dry_run = req["dry_run"].boolean();
            cr.max_bytes = cfg_.control.upload_max;
            for (const auto& sec : req["secrets"].items()) cr.secrets.push_back(sec.str());
            r = install::copy_file(cr);
#else
            r = json::Value::object().set("ok", false).set("error", "not available on this platform");
#endif
        } else {
#ifndef _WIN32
            install::Request ir;
            ir.site_root = std::string(req.get("site_root"));
            ir.target = std::string(req.get("target"));
            ir.create_path = req["create_path"].boolean();
            ir.dry_run = req["dry_run"].boolean();
            ir.url = std::string(req.get("url"));
            ir.upload_name = std::string(req.get("upload"));
            ir.sha256 = std::string(req.get("sha256"));
            ir.strip = req["strip"].is_null() ? -1 : static_cast<int>(req["strip"].num());
            ir.allow_private = cfg_.control.install_private;
            ir.ca_file = cfg_.control.install_ca;
            for (const auto& sec : req["secrets"].items()) ir.secrets.push_back(sec.str());
            if (!ir.url.empty() && !cfg_.control.install) {
                r = json::Value::object().set("ok", false).set("error", "downloads are off ([control] install = false); upload the archive instead");
            } else {
                if (!ir.upload_name.empty()) {
                    const std::string path = uploads_dir_ + "/" + ir.upload_name;
                    ir.upload_fd = uploads_dir_.empty() ? -1 : ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                    if (ir.upload_fd < 0) r = json::Value::object().set("ok", false).set("error", "upload " + ir.upload_name + ": " + std::strerror(errno));
                }
                if (r.is_null()) r = install::execute(ir);
                if (ir.upload_fd >= 0) ::close(ir.upload_fd);
            }
#else
            r = json::Value::object().set("ok", false).set("error", "not available on this platform");
#endif
        }
        asio::post(workers_[0]->ctx, [done, r] { done(r); });
    }).detach();
}

void Server::restart_later() {
    restart_timer_ = std::make_unique<asio::steady_timer>(workers_[0]->ctx);
    restart_timer_->expires_after(std::chrono::milliseconds(800));  // the reply is on the wire by then
    restart_timer_->async_wait([this](const asio::error_code& ec) {
        if (ec) return;
        const json::Value r = provisioner_.request(json::Value::object().set("op", "service_restart"));
        if (!r["ok"].boolean()) error_log_.error("restart through the helper failed: " + std::string(r.get("error")));
    });
}

void Server::stop() {
    if (stopping_.exchange(true)) return;
    provisioner_.stop();
    acme_.stop();
#ifdef ASIO_HAS_LOCAL_SOCKETS
    if (control_acceptor_) {
        asio::error_code ignored;
        control_acceptor_->close(ignored);
        ::unlink(cfg_.control.socket.c_str());
    }
#endif
    for (auto& w : workers_)
        w->ctx.stop();
}

// ---- reload ----

bool Server::reload(std::string& error) {
    auto refuse = [&](const std::string& why) {
        error = why;
        error_log_.error("reload refused: " + why);
        return false;
    };
    Config fresh;
    try {
        fresh = load_config(cfg_.config_path);
    } catch (const std::exception& e) {
        return refuse(e.what());
    }
    const auto hosting = check_hosting(fresh, system_facts());
    if (!hosting.empty()) {
        std::string all;
        for (const auto& e : hosting) all += (all.empty() ? "" : "; ") + e;
        return refuse(all);
    }
    // Restart-only settings stay what they were; say so when the file changed them.
    if (fresh.workers != cfg_.workers || fresh.reuse_port != cfg_.reuse_port || fresh.user != cfg_.user ||
        fresh.group != cfg_.group || fresh.sendfile != cfg_.sendfile || fresh.cache_max_size != cfg_.cache_max_size ||
        fresh.cache_max_file_size != cfg_.cache_max_file_size)
        error_log_.warn("reload: workers, reuse_port, user, group, sendfile and cache sizes need a restart; kept");
    auto gen = std::make_shared<Generation>();
    gen->cfg = std::move(fresh);
    try {
        prepare_acme(gen->cfg);
        build_listeners(*gen);
    } catch (const std::exception& e) {
        return refuse(e.what());
    }
    assign_log_sinks(gen->cfg);
    std::string err;
    if (!logs_.open_all(err)) return refuse(err);
    own_site_logs(gen->cfg);

    // New addresses are bound before anything switches, so a port that cannot be bound
    // refuses the whole reload and nothing changed.
    std::vector<std::size_t> opened;
    try {
        for (const auto& l : gen->listeners) {
            bool bound = false;
            for (const auto& a : acceptors_) bound = bound || (a->open && a->address == l.address);
            if (bound) continue;
            if (reuse_port_)
                for (auto& w : workers_) opened.push_back(open_acceptor(l, *w, true));
            else
                opened.push_back(open_acceptor(l, *workers_[0], false));
        }
    } catch (const std::exception& e) {
        for (std::size_t i : opened) {  // never accepted: nothing runs on them yet
            asio::error_code ignored;
            acceptors_[i]->socket.close(ignored);
            acceptors_[i]->open = false;
            acceptors_[i]->closed.store(true, std::memory_order_release);
        }
        return refuse(e.what());
    }
    // Switch: every worker takes the generation on its own loop; connections pick it up at
    // their next request, exchanges in flight keep the old one alive until they finish.
    gen_ = gen;
    for (auto& w : workers_) asio::post(w->ctx, [w = w.get(), gen] { w->gen = gen; });
    for (std::size_t i : opened) asio::post(acceptors_[i]->owner->ctx, [this, i] { start_accept(i); });
    // Addresses that left the configuration stop accepting; their open connections finish
    // their current request and are told to close (Connection: close) on the next one.
    std::size_t removed = 0;
    for (auto& a : acceptors_) {
        if (!a->open || gen->find(a->address)) continue;
        a->open = false;
        ++removed;
        Acceptor* acc = a.get();  // stays alive: its slot is reused only after `closed` is set here
        asio::post(acc->owner->ctx, [acc] {
            asio::error_code ignored;
            acc->socket.close(ignored);
            acc->closed.store(true, std::memory_order_release);
        });
    }
#ifdef AGENSIO_HAS_TLS
    acme_.update(gen->cfg.acme, acme::sites_of(gen->cfg));
#endif
    error_log_.warn("reloaded " + cfg_.config_path.string() + ": " + std::to_string(gen->cfg.sites.size()) +
                    " site(s), " + std::to_string(gen->listeners.size()) + " listener(s), " +
                    std::to_string(opened.size()) + " bound, " + std::to_string(removed) + " closed");
    return true;
}

bool Server::renew_certificate(std::string_view site, std::string& error) {
#ifdef AGENSIO_HAS_TLS
    const SiteConfig* s = control::find_site(gen_->cfg, site);
    if (!s) {
        error = "no such site";
        return false;
    }
    if (!s->tls || !s->tls->automatic) {
        error = "the site has no automatic certificate (tls = \"auto\")";
        return false;
    }
    if (!acme_.renew_now(s->tls->cert)) {
        error = "certificate not managed";
        return false;
    }
    return true;
#else
    (void)site;
    error = "built without TLS";
    return false;
#endif
}

void Server::write_pid_file() {
    if (cfg_.pid_file.empty()) return;
    std::ofstream f(cfg_.pid_file, std::ios::trunc);
    f << ::getpid() << "\n";
    if (!f)  // a development run as a user cannot write /run: `agensio reload` will say so
        error_log_.warn("cannot write pid file " + cfg_.pid_file + " (set server.pid_file to a writable path for `agensio reload`)");
}

void Server::remove_pid_file() noexcept {
    if (cfg_.pid_file.empty()) return;
    std::error_code ec;
    std::filesystem::remove(cfg_.pid_file, ec);
}

}  // namespace agensio
