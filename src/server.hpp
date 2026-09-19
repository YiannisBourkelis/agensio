// Workers, listeners and the accept loop.
#pragma once

#include <atomic>
#include <map>
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
#include "handlers/cgi.hpp"
#include "handlers/proxy.hpp"
#include "handlers/static.hpp"
#include "control/handler.hpp"
#include "control/roles.hpp"
#include "services/acme.hpp"
#include "services/log.hpp"
#include "upstream/fcgi_client.hpp"

namespace agensio {

struct Generation;

struct Worker {
    explicit Worker(unsigned id_) : id(id_) {}
    unsigned id;
    asio::io_context ctx{1};  // concurrency hint 1: single thread, no internal locking
    WorkerState state;
    asio::steady_timer flush_timer{ctx};  // access log buffers, once per second
    UpstreamPool upstream_pool{ctx};      // this worker's FastCGI and origin connections
    std::atomic<std::uint64_t> connections{0};
    // The configuration this worker hands to new connections and to connections at their
    // next request. Written only by a handler posted to this worker's loop (reload).
    std::shared_ptr<const Generation> gen;
};

struct Listener {
    std::string address;  // "host:port" as configured
    asio::ip::tcp::endpoint endpoint;
    std::string address_text;  // the bound IP as text (SERVER_ADDR)
    std::uint16_t port = 0;
    Router router;  // site by Host, location by path
    bool tls = false;
#ifdef AGENSIO_HAS_TLS
    std::shared_ptr<asio::ssl::context> ssl;  // the handshake starts here; SNI switches to the site's context
    std::map<std::string, std::shared_ptr<asio::ssl::context>> tls_contexts;  // by certificate path
#endif
    std::vector<std::string> site_names;  // for the startup log
};

// One loaded configuration with everything derived from it: the routers (which point into
// its sites), the TLS contexts, the log sink indexes. A reload builds a new one and
// switches the workers to it; a connection keeps the generation it is serving a request
// from alive through its shared_ptr, so nothing in flight ever sees a dangling pointer.
struct Generation {
    Config cfg;
    std::vector<Listener> listeners;
    SiteConfig control_site;             // the control listener's synthetic site (stable address for its router)
    std::unique_ptr<Listener> control;   // present when [control] is enabled
    const Listener* find(std::string_view address) const noexcept {
        for (const auto& l : listeners)
            if (l.address == address) return &l;
        return nullptr;
    }
};

class Server : public ControlBackend {
public:
    explicit Server(Config cfg);
    ~Server();

    // Binds all listeners and runs until stop() or SIGINT/SIGTERM. Throws on bind errors.
    void run();
    void stop();
    // SIGHUP / `agensio reload`: loads the configuration file again and, when it is valid
    // and its new listeners bind, switches every worker to it between requests. Requests,
    // upstream exchanges and tunnels in flight finish on the configuration they started
    // with; keep-alive connections pick the new one up at their next request. A bad file
    // or a port that cannot be bound is logged and the current configuration keeps serving.
    void reload() {
        std::string ignored;
        reload(ignored);
    }
    bool reload(std::string& error);

    const std::vector<Listener>& listeners() const noexcept { return gen_->listeners; }
    unsigned worker_count() const noexcept { return static_cast<unsigned>(workers_.size()); }
    bool reuse_port_enabled() const noexcept { return reuse_port_; }

private:
    struct Acceptor {
        asio::ip::tcp::acceptor socket;
        asio::steady_timer backoff;  // pauses accepting when descriptors run out
        std::string address;         // the listener it serves, looked up in the worker's generation at accept
        Worker* owner;               // the worker whose io_context runs this acceptor
        bool open = true;            // accepting (written by the reload thread)
        std::atomic<bool> closed{false};  // the posted close ran on the owner's loop: the slot may be reused
        Acceptor(asio::io_context& ctx, std::string a, Worker* w)
            : socket(ctx), backoff(ctx), address(std::move(a)), owner(w) {}
    };

    void build_listeners(Generation& gen);
    void build_workers();
    std::size_t open_acceptor(const Listener& listener, Worker& worker, bool reuse_port);
    void open_acceptor_socket(Acceptor& acc, const Listener& listener, bool reuse_port);
    void start_accept(std::size_t acceptor_index);
    void open_logs();
    void assign_log_sinks(Config& cfg);  // site access logs into the registry (opened by open_all)
    void own_site_logs(const Config& cfg);  // per-site logs: agensio:<site group> 0640, when we can chown
    void drop_privileges();   // server.user: after binding and opening logs
    void arm_flush(Worker& w);
    void write_pid_file();
    void remove_pid_file() noexcept;
    void prepare_acme(const Config& cfg);  // storage tree and placeholder certificates for tls = "auto" sites
    void open_control();                   // the control socket (F0/F1), before the privilege drop
    void start_accept_control();
    json::Value status() override;
    json::Value sites() override;
    json::Value site(std::string_view name, bool& found) override;
    json::Value validate() override;
    json::Value logs(std::string_view target) override;
    json::Value health() override;
    bool reload_now(std::string& error) override { return reload(error); }
    bool renew_certificate(std::string_view site, std::string& error) override;
    void reopen_logs() override { logs_.reopen_all(); }
    const Config& running() override { return gen_->cfg; }
    bool privileged() override {
#ifdef _WIN32
        return true;
#else
        return ::geteuid() == 0;
#endif
    }


    Config cfg_;                            // the boot configuration: workers, cache, sendfile, user; restart-only
    std::shared_ptr<const Generation> gen_;  // the live one; the workers hold their own pointer
    LogRegistry logs_;
    ErrorLog error_log_;
    bool access_logging_ = false;
    FileCache cache_;
    StaticHandler handler_;
    FcgiHandler fcgi_handler_;
    ProxyHandler proxy_handler_;
    CgiHandler cgi_handler_;
    ControlHandler control_handler_;
    Dispatcher dispatcher_;
    AcmeManager acme_{error_log_};
    std::vector<std::unique_ptr<Worker>> workers_;
    std::vector<std::unique_ptr<Acceptor>> acceptors_;
    std::vector<std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>>> guards_;
    std::vector<std::thread> threads_;  // joined in run(); not jthread: libc++ has it only as experimental
    std::atomic<unsigned> next_worker_{0};
    bool reuse_port_ = false;
    std::atomic<bool> stopping_{false};
#ifdef ASIO_HAS_LOCAL_SOCKETS
    std::unique_ptr<asio::local::stream_protocol::acceptor> control_acceptor_;
#endif
    RoleGroups control_groups_;
    long server_uid_ = -1;
    int audit_sink_ = -1;
    std::chrono::system_clock::time_point started_ = std::chrono::system_clock::now();
};

}  // namespace agensio
