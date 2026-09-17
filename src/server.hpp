// Workers, listeners and the accept loop.
#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>
#ifdef AGENSIO_HAS_TLS
#include <asio/ssl.hpp>
#endif

#include "cache.hpp"
#include "config.hpp"
#include "core/router.hpp"
#include "core/worker_state.hpp"
#include "handlers/dispatch.hpp"
#include "handlers/fastcgi.hpp"
#include "handlers/static.hpp"
#include "services/log.hpp"
#include "upstream/fcgi_client.hpp"

namespace agensio {

struct Worker {
    explicit Worker(unsigned id_) : id(id_) {}
    unsigned id;
    asio::io_context ctx{1};  // concurrency hint 1: single thread, no internal locking
    WorkerState state;
    asio::steady_timer flush_timer{ctx};  // access log buffers, once per second
    FcgiPool fcgi_pool{ctx};              // idle FastCGI connections of this worker
    std::atomic<std::uint64_t> connections{0};
};

struct Listener {
    std::string address;  // "host:port" as configured
    asio::ip::tcp::endpoint endpoint;
    std::string address_text;  // the bound IP as text (SERVER_ADDR)
    std::uint16_t port = 0;
    Router router;  // site by Host, location by path
    bool tls = false;
#ifdef AGENSIO_HAS_TLS
    std::shared_ptr<asio::ssl::context> ssl;
#endif
    std::vector<std::string> site_names;  // for the startup log
};

class Server {
public:
    explicit Server(Config cfg);
    ~Server();

    // Binds all listeners and runs until stop() or SIGINT/SIGTERM. Throws on bind errors.
    void run();
    void stop();

    const std::vector<Listener>& listeners() const noexcept { return listeners_; }
    unsigned worker_count() const noexcept { return static_cast<unsigned>(workers_.size()); }
    bool reuse_port_enabled() const noexcept { return reuse_port_; }

private:
    void build_listeners();
    void build_workers();
    void open_acceptor(Listener& listener, Worker& worker, bool reuse_port);
    void start_accept(std::size_t acceptor_index);
    void open_logs();
    void arm_flush(Worker& w);

    struct Acceptor {
        asio::ip::tcp::acceptor socket;
        asio::steady_timer backoff;  // pauses accepting when descriptors run out
        Listener* listener;
        Worker* owner;  // the worker whose io_context runs this acceptor
        Acceptor(asio::io_context& ctx, Listener* l, Worker* w) : socket(ctx), backoff(ctx), listener(l), owner(w) {}
    };

    Config cfg_;
    LogRegistry logs_;
    ErrorLog error_log_;
    bool access_logging_ = false;
    FileCache cache_;
    StaticHandler handler_;
    FcgiHandler fcgi_handler_;
    Dispatcher dispatcher_;
    std::vector<std::unique_ptr<Worker>> workers_;
    std::vector<Listener> listeners_;
    std::vector<std::unique_ptr<Acceptor>> acceptors_;
    std::vector<std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>>> guards_;
    std::vector<std::jthread> threads_;
    std::atomic<unsigned> next_worker_{0};
    bool reuse_port_ = false;
    std::atomic<bool> stopping_{false};
};

}  // namespace agensio
