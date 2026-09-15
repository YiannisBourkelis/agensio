#include "server.hpp"

#include <iostream>
#include <stdexcept>

#include "connection.hpp"

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
      cache_(cfg_.cache_max_file_size, cfg_.cache_max_size, cfg_.cache_evict_fraction),
      handler_(cfg_, cache_) {
    build_listeners();
    build_workers();
}

Server::~Server() { stop(); }

void Server::build_listeners() {
    for (const auto& site : cfg_.sites) {
        for (const auto& address : site.listen) {
            Listener* l = nullptr;
            for (auto& existing : listeners_)
                if (existing.address == address) { l = &existing; break; }
            if (!l) {
                listeners_.emplace_back();
                l = &listeners_.back();
                l->address = address;
                l->endpoint = parse_endpoint(address);
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
                    throw std::runtime_error("site on " + address + " requires TLS but agensio was built without OpenSSL");
#endif
                }
            }
            for (const auto& name : site.server_names) {
                if (name == "*") {
                    if (!l->route.default_site) l->route.default_site = &site;
                } else {
                    l->route.by_name.emplace(name, &site);
                }
            }
            if (site.is_default) l->route.default_site = &site;
            if (!l->route.default_site) l->route.default_site = &site;
            l->site_names.push_back(site.server_names.front());
        }
    }
}

void Server::build_workers() {
    unsigned n = cfg_.workers ? cfg_.workers : std::thread::hardware_concurrency();
    if (n == 0) n = 1;
    for (unsigned i = 0; i < n; ++i) workers_.push_back(std::make_unique<Worker>(i));

    reuse_port_ = false;
    if (cfg_.reuse_port == "on") reuse_port_ = kHasReusePort;
#ifdef __linux__
    if (cfg_.reuse_port == "auto") reuse_port_ = kHasReusePort;
#endif
    if (cfg_.reuse_port == "on" && !kHasReusePort)
        std::cerr << "warning: SO_REUSEPORT is not available on this platform; using a shared acceptor\n";
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
    Worker& target = reuse_port_ ? *acc.owner : *workers_[next_worker_.fetch_add(1, std::memory_order_relaxed) % workers_.size()];
    acc.socket.async_accept(target.ctx, [this, index, &acc, &target](const asio::error_code& ec, asio::ip::tcp::socket sock) {
        if (ec == asio::error::operation_aborted || stopping_.load(std::memory_order_relaxed)) return;
        if (!ec) {
            if (cfg_.tcp_nodelay) {
                asio::error_code ignored;
                sock.set_option(asio::ip::tcp::no_delay(true), ignored);
            }
            const Listener& l = *acc.listener;
            if (l.tls) {
#ifdef AGENSIO_HAS_TLS
                using TlsStream = asio::ssl::stream<asio::ip::tcp::socket>;
                auto c = std::make_shared<Connection<TlsStream>>(TlsStream(std::move(sock), *l.ssl), target, l, cfg_, handler_);
                if (&target == acc.owner) c->start();
                else asio::post(target.ctx, [c] { c->start(); });
#endif
            } else {
                auto c = std::make_shared<Connection<asio::ip::tcp::socket>>(std::move(sock), target, l, cfg_, handler_);
                if (&target == acc.owner) c->start();
                else asio::post(target.ctx, [c] { c->start(); });
            }
        }
        start_accept(index);
    });
}

void Server::run() {
    if (reuse_port_) {
        for (auto& l : listeners_)
            for (auto& w : workers_) open_acceptor(l, *w, true);
    } else {
        for (auto& l : listeners_) open_acceptor(l, *workers_[0], false);
    }
    for (auto& w : workers_) guards_.push_back(std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(w->ctx.get_executor()));
    for (std::size_t i = 0; i < acceptors_.size(); ++i) start_accept(i);

    asio::signal_set signals(workers_[0]->ctx, SIGINT, SIGTERM);
    signals.async_wait([this](const asio::error_code& ec, int) { if (!ec) stop(); });

    for (std::size_t i = 1; i < workers_.size(); ++i) {
        Worker* w = workers_[i].get();
        threads_.emplace_back([w] { w->ctx.run(); });
    }
    workers_[0]->ctx.run();
    for (auto& t : threads_) t.join();
    threads_.clear();
}

void Server::stop() {
    if (stopping_.exchange(true)) return;
    for (auto& w : workers_) w->ctx.stop();
}

}  // namespace agensio
