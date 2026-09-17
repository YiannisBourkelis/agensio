#include "server.hpp"
#include "services/pools.hpp"

#ifndef _WIN32
#include <grp.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <chrono>
#include <functional>
#include <csignal>
#include <iostream>
#include <stdexcept>

#include "file.hpp"
#include "http1/connection.hpp"
#include "response.hpp"

#ifdef AGENSIO_HAS_TLS
#include <openssl/ssl.h>
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
    : cfg_(std::move(cfg)),
      cache_(cfg_.cache_max_file_size, cfg_.cache_max_size, cfg_.cache_evict_fraction, cfg_.cache_max_open_files),
      handler_(cfg_, cache_),
      fcgi_handler_(cfg_, error_log_),
      proxy_handler_(cfg_, error_log_),
      cgi_handler_(cfg_, error_log_),
      dispatcher_(handler_, fcgi_handler_, proxy_handler_, cgi_handler_) {
    open_logs();
    warm_response_tables();
    build_listeners();
    build_workers();
}

Server::~Server() {
    stop();
}

// One sink per distinct path; the error log first so startup messages have somewhere to go.
void Server::open_logs() {
    const int error_sink = logs_.add(cfg_.log.error);
    for (auto& site : cfg_.sites) {
        site.access_log_sink = logs_.add(site.access_log);
        if (site.access_log_sink >= 0) access_logging_ = true;
    }
    std::string err;
    if (!logs_.open_all(err)) throw std::runtime_error(err);
    LogLevel level = LogLevel::warn;
    parse_log_level(cfg_.log.level, level);
    error_log_.configure(&logs_, error_sink, level);
    own_site_logs();
}

// A site with `user` gets its access log as agensio:<site group> 0640: agensio writes it
// as the owner (also after a SIGUSR1 reopen once privileges are dropped), the customer
// reads it through the group, nobody else. Needs root (or CAP_CHOWN); otherwise one
// warning per site and the file stays ours.
void Server::own_site_logs() {
#ifndef _WIN32
    const HostFacts facts = system_facts();
    unsigned agensio_uid = ::geteuid();
    unsigned agensio_gid = ::getegid();
    if (!cfg_.user.empty()) {
        unsigned primary = 0;
        if (facts.user(cfg_.user, agensio_uid, primary)) agensio_gid = primary;
    }
    if (!cfg_.group.empty()) facts.group(cfg_.group, agensio_gid);
    for (const auto& site : cfg_.sites) {
        if (site.user.empty() || site.access_log.empty()) continue;
        unsigned uid = 0, gid = 0;
        if (!facts.user(site.user, uid, gid)) continue;  // check_hosting already refused this
        if (!site.group.empty()) facts.group(site.group, gid);
        if (::chown(site.access_log.c_str(), agensio_uid, gid) != 0) {
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

void Server::arm_flush(Worker& w) {
    w.flush_timer.expires_after(std::chrono::seconds(1));
    w.flush_timer.async_wait([this, &w](const asio::error_code& ec) {
        if (ec) return;
        w.state.logs.flush();
        arm_flush(w);
    });
}

void Server::build_listeners() {
    for (const auto& site : cfg_.sites) {
        for (const auto& address : site.listen) {
            Listener* l = nullptr;
            for (auto& existing : listeners_)
                if (existing.address == address) {
                    l = &existing;
                    break;
                }
            if (!l) {
                listeners_.emplace_back();
                l = &listeners_.back();
                l->address = address;
                l->endpoint = parse_endpoint(address);
                l->address_text = l->endpoint.address().to_string();
                l->port = l->endpoint.port();
                l->tls = site.tls.has_value();
                if (l->tls) {
#ifdef AGENSIO_HAS_TLS
                    l->ssl = std::make_shared<asio::ssl::context>(asio::ssl::context::tls_server);
                    l->ssl->set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                                        asio::ssl::context::no_sslv3 | asio::ssl::context::no_tlsv1 |
                                        asio::ssl::context::no_tlsv1_1 | asio::ssl::context::single_dh_use);
                    l->ssl->use_certificate_chain_file(site.tls->cert.string());
                    l->ssl->use_private_key_file(site.tls->key.string(), asio::ssl::context::pem);
                    SSL_CTX_set_min_proto_version(l->ssl->native_handle(), TLS1_2_VERSION);
                    // SSL_MODE_RELEASE_BUFFERS deliberately not set: it costs a malloc/free per record.
                    SSL_CTX_set_options(l->ssl->native_handle(), SSL_OP_NO_COMPRESSION);
#else
                    throw std::runtime_error("site on " + address +
                                             " requires TLS but agensio was built without OpenSSL");
#endif
                }
            }
            l->router.add_site(site);
            l->site_names.push_back(site.server_names.front());
        }
    }
}

void Server::build_workers() {
    unsigned n = cfg_.workers ? cfg_.workers : std::thread::hardware_concurrency();
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

void Server::open_acceptor(Listener& listener, Worker& worker, bool reuse_port) {
    auto acc = std::make_unique<Acceptor>(worker.ctx, &listener, &worker);
    auto& s = acc->socket;
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
    acceptors_.push_back(std::move(acc));
}

void Server::start_accept(std::size_t index) {
    Acceptor& acc = *acceptors_[index];
    Worker& target =
        reuse_port_ ? *acc.owner : *workers_[next_worker_.fetch_add(1, std::memory_order_relaxed) % workers_.size()];
    acc.socket.async_accept(
        target.ctx, [this, index, &acc, &target](const asio::error_code& ec, asio::ip::tcp::socket sock) {
            if (ec == asio::error::operation_aborted || stopping_.load(std::memory_order_relaxed)) return;
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
                const Listener& l = *acc.listener;
                if (l.tls) {
#ifdef AGENSIO_HAS_TLS
                    auto c = std::make_shared<Http1Connection<TlsStream>>(TlsStream(std::move(sock), *l.ssl), target, l,
                                                                     cfg_, dispatcher_);
                    if (&target == acc.owner) c->start();
                    else asio::post(target.ctx, [c] { c->start(); });
#endif
                } else {
                    auto c = std::make_shared<Http1Connection<asio::ip::tcp::socket>>(std::move(sock), target, l,
                                                                                       cfg_, dispatcher_);
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
        for (auto& l : listeners_)
            for (auto& w : workers_)
                open_acceptor(l, *w, true);
    } else {
        for (auto& l : listeners_)
            open_acceptor(l, *workers_[0], false);
    }
    drop_privileges();  // ports are bound and logs open: nothing else needs root
    for (auto& w : workers_) {
        guards_.push_back(
            std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(w->ctx.get_executor()));
        w->state.logs.attach(&logs_,
                             cfg_.log.json ? AccessLogFormat::json : AccessLogFormat::combined);
        if (access_logging_) arm_flush(*w);
    }
    for (std::size_t i = 0; i < acceptors_.size(); ++i)
        start_accept(i);

    asio::signal_set signals(workers_[0]->ctx, SIGINT, SIGTERM);
    signals.async_wait([this](const asio::error_code& ec, int) {
        if (!ec) stop();
    });
#ifndef _WIN32
    // Log rotation: SIGUSR1 reopens every log file (logrotate's postrotate hook).
    asio::signal_set reopen(workers_[0]->ctx, SIGUSR1);
    auto on_reopen = std::make_shared<std::function<void(const asio::error_code&, int)>>();
    *on_reopen = [this, &reopen, on_reopen](const asio::error_code& ec, int) {
        if (ec) return;
        logs_.reopen_all();
        error_log_.info("log files reopened (SIGUSR1)");
        reopen.async_wait(*on_reopen);
    };
    reopen.async_wait(*on_reopen);
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

void Server::stop() {
    if (stopping_.exchange(true)) return;
    for (auto& w : workers_)
        w->ctx.stop();
}

}  // namespace agensio
