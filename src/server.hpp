// Workers, listeners and the accept loop.
#pragma once

#include "control/commands.hpp"

#include <array>
#include <atomic>
#include <functional>
#include <mutex>
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
#include "core/host.hpp"
#include "services/provision.hpp"
#include "services/log.hpp"
#include "upstream/fcgi_client.hpp"

namespace agensio {

struct Generation;

// What the refusals at a worker's ceiling looked like (hardening item 5; the 2026-10-02
// question: an agent must tell an attack from a low ceiling from stuck clients without a
// shell): the addresses refused most, the listeners, when. Written on refusals by the
// worker's own thread and read by status and health from worker 0, under a mutex: the
// refusal path is the overload path, not the request path. Addresses are kept as values,
// so a refusal allocates nothing.
struct RefusalSample {
    struct Address {
        asio::ip::address addr;
        std::uint64_t count = 0;
        std::chrono::steady_clock::time_point last{};
    };
    std::array<Address, 8> addresses{};  // when every slot is taken the least recently refused address gives way
    std::uint64_t unsampled = 0;         // refusals an evicted address had: the sample is partial then
    std::vector<std::pair<std::string, std::uint64_t>> listeners;  // refusals per listener address
    std::chrono::steady_clock::time_point first{}, last{};
    std::uint64_t window = 0;  // refusals since the last log line
    std::chrono::steady_clock::time_point window_start{};
};

struct Worker {
    explicit Worker(unsigned id_) : id(id_) {}
    unsigned id;
    asio::io_context ctx{1};  // concurrency hint 1: single thread, no internal locking
    WorkerState state;
    asio::steady_timer flush_timer{ctx};  // access log buffers, once per second
    UpstreamPool upstream_pool{ctx};      // this worker's FastCGI and origin connections
    std::atomic<std::uint64_t> connections{0};
    std::atomic<std::uint64_t> refused{0};  // connections refused at the ceiling since start (status, health)
    std::atomic<std::uint32_t> idle{0};     // HTTP/1 and HTTP/2 connections idle 2 s or more (buffers shed); this thread writes
    mutable std::mutex refusal_mutex;
    RefusalSample refusals;
    unsigned sheds = 0;  // connections that dropped their idle buffers or closed since the last trim (this thread only)
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
    bool h2 = true;   // TLS: h2 offered through ALPN (the sites' `protocols`)
    bool h2c = false; // plain: the HTTP/2 preface accepted
    bool h3 = false;  // TLS: HTTP/3 over QUIC on the same port number (UDP), phase I
    bool hq = false;  // TLS: the interop runner's hq-interop over QUIC too (AGENSIO_INTEROP builds)
    std::string alt_svc;       // TLS with h3: the alt-svc value (h3=":port"; ma=86400) every h1 and h2 answer carries
    std::string alt_svc_line;  // the same as the HTTP/1 head line, prebuilt
#ifdef AGENSIO_HAS_TLS
    std::shared_ptr<asio::ssl::context> ssl;  // the handshake starts here; SNI switches to the site's context
    std::map<std::string, std::shared_ptr<asio::ssl::context>> tls_contexts;  // by certificate path
    // The names each certificate covers, by the context that presents it: a connection takes
    // the entry of the context its handshake ended with and keeps it (shared) for its life,
    // so a renewal or reload never changes what an established connection is authoritative for.
    std::map<const SSL_CTX*, std::shared_ptr<const CertNames>> cert_names;
    std::string alpn;  // the protocols offered, OpenSSL wire form ("\x02h2\x08http/1.1"), from [server] protocols
    std::shared_ptr<const CertNames> names_for(const SSL_CTX* ctx) const {
        const auto it = cert_names.find(ctx);
        return it == cert_names.end() ? nullptr : it->second;
    }
#endif
    std::vector<std::string> site_names;  // for the startup log
};

#ifdef AGENSIO_HAS_TLS
using CertificateSet = std::map<std::string, std::shared_ptr<asio::ssl::context>>;  // by "cert\nkey"
// One certificate and key pair from its files, as the start, a reload, the refresh and agensio -t
// load it: nullptr and why when it does not load (a file missing or unreadable, not PEM, a key that
// is not the certificate's), with what cfg.user lacks to read the files after the drop (step T1).
std::shared_ptr<asio::ssl::context> load_certificate_pair(const Config& cfg, const TlsConfig& t, std::string& error);
// The certificate step of the start, a reload and agensio -t (design section 26, C3): every TLS
// site's pair loaded once with `load` into `out`; a site whose pair does not load is set aside with
// its file, a carried one keeps `previous`'s material (said in `kept`). Throws for the main file's
// sites and when no site is left.
void isolate_certificates(Config& cfg, const Config* running, CertificateSet& out, const CertificateSet* previous,
                          const std::function<std::shared_ptr<asio::ssl::context>(const TlsConfig&, std::string&)>& load,
                          std::vector<std::string>& kept);
#endif
// agensio -t's certificate step (the alpha.64 report, finding 1): each pair loaded as the start
// loads it, so a site the start would set aside for its certificate is set aside here too. Not an
// automatic certificate still to be issued (the start writes a placeholder), and not a file this
// process may not read while the start reads it as root (-t not root, server.user another
// account): the notes returned name those. Throws as the start does.
std::vector<std::string> check_certificates(Config& cfg);

// One loaded configuration with everything derived from it: the routers (which point into
// its sites), the TLS contexts, the log sink indexes. A reload builds a new one and
// switches the workers to it; a connection keeps the generation it is serving a request
// from alive through its shared_ptr, so nothing in flight ever sees a dangling pointer.
struct Generation {
    Config cfg;
    std::vector<Listener> listeners;
#ifdef AGENSIO_HAS_TLS
    // Each certificate and key pair the configuration names, loaded once (load_certificates): the
    // listeners' contexts take their material from here, and a carried site whose files no longer
    // load takes it from the previous generation's (design section 26, C3). Never used for a
    // handshake, so sharing one between generations is safe.
    CertificateSet certificates;
#endif
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
    // `must_load`: a site file that must load (the control plane's own change): its being set
    // aside refuses the reload; any other file set aside keeps its last good version.
    bool reload(std::string& error, std::string_view must_load = {});

    const std::vector<Listener>& listeners() const noexcept { return gen_->listeners; }
    unsigned worker_count() const noexcept { return static_cast<unsigned>(workers_.size()); }
    bool reuse_port_enabled() const noexcept { return reuse_port_; }

private:
    struct Acceptor {
        asio::ip::tcp::acceptor socket;
        asio::steady_timer backoff;  // pauses accepting when descriptors run out
        std::string address;         // the listener it serves, looked up in the worker's generation at accept
        Worker* owner;               // the worker whose io_context runs this acceptor
        // The client of the connection accept(2) returned, written by that call itself (its
        // sockaddr argument): no getpeername later, and an address even after the client reset.
        asio::ip::tcp::endpoint peer;
        bool open = true;            // accepting (written by the reload thread)
        std::atomic<bool> closed{false};  // the posted close ran on the owner's loop: the slot may be reused
        Acceptor(asio::io_context& ctx, std::string a, Worker* w)
            : socket(ctx), backoff(ctx), address(std::move(a)), owner(w) {}
    };

    void build_listeners(Generation& gen);
    // Loads every certificate of `gen` before the listeners are built; a site whose pair does not
    // load is set aside with its file, a carried one keeps `previous`'s material. Throws for the
    // main file's sites. Returns the lines to log for material kept.
    std::vector<std::string> load_certificates(Generation& gen, const Generation* previous);
    control::TlsFacts tls_facts();  // the certificates as served and the ACME failures, for health (T2)
    bool switch_to(const std::shared_ptr<Generation>& gen, std::string& error, std::size_t& bound, std::size_t& closed, bool logs);
    void prepare_served_record();  // <state_dir>/server, the server's account's (alpha.63 report, finding 1)
    void record_served();          // after a start and a reload
    bool record_warned_ = false;
    // The certificate refresh and its hourly watch (step T3).
    bool refresh_certificates(std::string& error, const std::vector<std::string>& only, std::vector<std::string>& report);
    void arm_certificate_watch();
#ifdef AGENSIO_HAS_TLS
    static std::string pair_stamp(const TlsConfig& t);
#endif
    std::map<std::string, std::string> cert_stamps_;       // by pair: the files as last loaded (or tried)
    std::map<std::string, std::string> cert_load_errors_;  // by pair: why its files did not load, last time
    std::unique_ptr<asio::steady_timer> cert_watch_timer_;
    std::chrono::seconds cert_watch_interval_{3600};
    void build_workers();
    std::size_t open_acceptor(const Listener& listener, Worker& worker, bool reuse_port);
    void open_acceptor_socket(Acceptor& acc, const Listener& listener, bool reuse_port);
    void start_accept(std::size_t acceptor_index);
    // A connection accepted while its worker is at the ceiling: counted, a plain client told
    // 503 with Retry-After, a TLS one closed before any handshake work, one log line per
    // worker per ten seconds. Runs on the worker's own loop.
    void refuse_connection(asio::ip::tcp::socket& sock, const asio::ip::tcp::endpoint& peer, const Listener& l, Worker& w);
    // The error log line for a worker at its ceiling, from its sample (under refusal_mutex).
    std::string ceiling_line(const Worker& w, const RefusalSample& s, std::chrono::steady_clock::time_point now) const;
    // Every worker's refusals merged, for status and health.
    control::RefusalReport refusal_report() const;
    void open_logs();
    void assign_log_sinks(Config& cfg);  // site access logs into the registry (opened by open_all)
    void own_site_logs(const Config& cfg);  // per-site logs: agensio:<site group> 0640, when we can chown
    void drop_privileges();   // server.user: after binding and opening logs
    void arm_flush(Worker& w);
    void write_pid_file();
    void remove_pid_file() noexcept;
    void prepare_acme(const Config& cfg);  // storage tree and placeholder certificates for tls = "auto" sites
    void open_control();                   // the control socket (F0/F1), before the privilege drop
    RoleGroups resolve_control_groups(const Config& cfg);  // the role groups' ids by name
    void apply_control_groups(const Config& cfg);          // a reload's new role groups, on worker 0
    void start_accept_control();
    // HTTP/3 (phase I, docs/design-http3.md): a UDP endpoint per TLS listener that lists
    // h3, on worker 0 in this slice; bound before the privilege drop like the acceptors.
    void open_h3();
    void start_h3();
    void reload_h3(const Config& cfg);
    void open_h3_listener(const Listener& l, const Config& cfg, bool start);
    void sync_h3(const std::shared_ptr<const Generation>& gen);
    void stop_h3();
    struct H3Endpoints;
    json::Value status() override;
    json::Value sites() override;
    json::Value site(std::string_view name, bool& found) override;
    json::Value validate() override;
    json::Value logs(std::string_view target) override;
    json::Value health() override;
    bool reload_now(std::string& error, std::string_view must_load = {}) override { return reload(error, must_load); }
    std::vector<std::string> restart_pending() override { return control::restart_needed(gen_->cfg, cfg_); }
    bool renew_certificate(std::string_view site, std::string& error, std::string& message) override;
    void reopen_logs() override { logs_.reopen_all(); }
    const Config& running() override { return gen_->cfg; }
    bool provision_available() override { return provisioner_.available(); }
    json::Value provision(const json::Value& req) override { return provisioner_.request(req); }
    void restart_later() override;
    void install_async(const json::Value& req, std::function<void(json::Value)> done) override;
    void task_async(const json::Value& req, std::function<void(json::Value)> done) override;
    void env_async(const json::Value& req, std::function<void(json::Value)> done) override;
    void auth_users_async(const json::Value& req, std::function<void(json::Value)> done) override;
    int env_file_state(std::string_view site, std::vector<std::string>& exposed) override;
    void helper_async(const json::Value& req, std::function<void(json::Value)> done) override;
    void provision_async(const json::Value& req, std::function<void(json::Value)> done) override;
    std::string uploads_dir() override { return uploads_dir_; }
    void prepare_uploads();  // <state_dir>/uploads, the server's own, before the privilege drop
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
    HttparenaHandler httparena_handler_;
    Dispatcher dispatcher_;
    AcmeManager acme_{error_log_};
    Provisioner provisioner_;
    std::string uploads_dir_;
    void arm_trash_expiry();
    std::vector<std::unique_ptr<Worker>> workers_;
    // Timers on worker 0's context. Declared after workers_, so they are destroyed first: a timer
    // destroyed after its context's timer service reads freed memory (2026-10-09, the sanitizer
    // build at every exit with the helper running, which arms the trash timer).
    std::unique_ptr<asio::steady_timer> restart_timer_;
    std::unique_ptr<asio::steady_timer> trash_timer_;  // hourly: expired trash entries removed through the helper
    // [[site.auth]]'s verification pool. Declared after workers_, so it is destroyed first: its
    // threads post results into the workers' contexts and must stop before those go.
    std::unique_ptr<auth::Verifier> auth_verifier_;
    std::vector<std::unique_ptr<Acceptor>> acceptors_;
    std::unique_ptr<H3Endpoints> h3_;
    std::vector<std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>>> guards_;
    std::vector<std::thread> threads_;  // joined in run(); not jthread: libc++ has it only as experimental
    std::atomic<unsigned> next_worker_{0};
    std::uint64_t fd_limit_ = 0;                        // the open-file limit after run() raised it
    std::atomic<std::uint64_t> max_connections_{0};     // the per-worker ceiling in force (connection_ceiling)
    bool reuse_port_ = false;
    std::atomic<bool> stopping_{false};
#ifdef ASIO_HAS_LOCAL_SOCKETS
    std::unique_ptr<asio::local::stream_protocol::acceptor> control_acceptor_;
#endif
    RoleGroups control_groups_;
    long server_uid_ = -1;
    int audit_sink_ = -1;
    int error_sink_ = -1;
    std::chrono::system_clock::time_point started_ = std::chrono::system_clock::now();
};

}  // namespace agensio
