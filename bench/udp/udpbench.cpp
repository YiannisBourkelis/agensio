// UDP I/O strategies with Asio on Linux, measured before the QUIC transport is written
// (docs/design-http3.md 6.1). A server echoes every datagram it receives back to its
// sender, with one of four strategies for the socket, and reports the CPU it spent per
// datagram and the number of system calls; a client keeps a window of datagrams in
// flight per flow from several threads. Built and run by bench/udp/run.sh.
//
//   udpbench server MODE PORT [--seconds N] [--batch N] [--gro] [--gso]
//     MODE  asio   async_receive_from per datagram, send_to per reply (the textbook Asio loop)
//           spec   async_receive_from for the first datagram (Asio's speculative read),
//                  then recvmmsg until EAGAIN, replies in one sendmmsg per batch
//           wait   async_wait(wait_read), then recvmmsg until EAGAIN, sendmmsg per batch
//           (--gro: UDP_GRO on the socket; --gso: replies to one peer in one UDP_SEGMENT message)
//   udpbench client HOST PORT [--threads T] [--flows F] [--window W] [--size S] [--seconds N] [--gso] [--cpus LIST]
//     T threads, F flows (sockets) each, W datagrams of S bytes in flight per flow; a burst is
//     resent when its replies do not arrive within 200 ms (counted as lost).
#include <asio.hpp>

#include <arpa/inet.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif

namespace {

using clock_type = std::chrono::steady_clock;

int arg_int(int argc, char** argv, const char* name, int def) {
    for (int i = 1; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], name) == 0) return std::atoi(argv[i + 1]);
    return def;
}
const char* arg_str(int argc, char** argv, const char* name, const char* def) {
    for (int i = 1; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], name) == 0) return argv[i + 1];
    return def;
}
bool arg_flag(int argc, char** argv, const char* name) {
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], name) == 0) return true;
    return false;
}

double cpu_seconds() {
    rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    return static_cast<double>(ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) +
           static_cast<double>(ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e6;
}

void set_buffers(int fd) {
    int n = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, sizeof n);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, sizeof n);
}

// ---- server ----

enum class Mode { asio, spec, wait };

class Server {
public:
    Server(Mode mode, unsigned short port, int batch, bool gro, bool gso)
        : mode_(mode), batch_(batch), gro_(gro), gso_(gso), sock_(ctx_), timer_(ctx_) {
        sock_.open(asio::ip::udp::v4());
        set_buffers(sock_.native_handle());
        if (gro_) {
            int on = 1;
            if (setsockopt(sock_.native_handle(), SOL_UDP, UDP_GRO, &on, sizeof on) != 0) { std::perror("UDP_GRO"); std::exit(2); }
        }
        sock_.bind(asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), port));
        sock_.non_blocking(true);
        slot_ = gro_ ? 65536 : 2048;
        buf_.resize(static_cast<std::size_t>(batch_) * slot_);
        msgs_.resize(static_cast<std::size_t>(batch_));
        iov_.resize(static_cast<std::size_t>(batch_));
        addrs_.resize(static_cast<std::size_t>(batch_));
        ctl_.resize(static_cast<std::size_t>(batch_) * 64);
        out_.reserve(static_cast<std::size_t>(batch_) * 64);
        oiov_.reserve(static_cast<std::size_t>(batch_) * 64);
        octl_.resize(static_cast<std::size_t>(batch_) * 64 * CMSG_SPACE(sizeof(std::uint16_t)));
    }

    void run(int seconds) {
        timer_.expires_after(std::chrono::seconds(seconds));
        timer_.async_wait([this](const asio::error_code&) { ctx_.stop(); });
        cpu0_ = cpu_seconds();
        t0_ = clock_type::now();
        switch (mode_) {
            case Mode::asio: arm_asio(); break;
            case Mode::spec: arm_spec(); break;
            case Mode::wait: arm_wait(); break;
        }
        ctx_.run();
        const double cpu = cpu_seconds() - cpu0_;
        const double secs = std::chrono::duration<double>(clock_type::now() - t0_).count();
        std::printf("server mode=%s gro=%d gso=%d batch=%d received=%llu sent=%llu per_sec=%.0f cpu_us_per_datagram=%.3f "
                    "wakeups=%llu recv_calls=%llu send_calls=%llu datagrams_per_recv_call=%.1f datagrams_per_send_call=%.1f "
                    "gro_messages=%llu\n",
                    mode_ == Mode::asio ? "asio" : mode_ == Mode::spec ? "spec" : "wait", gro_ ? 1 : 0, gso_ ? 1 : 0, batch_,
                    received_, sent_, static_cast<double>(received_) / secs,
                    received_ ? cpu * 1e6 / static_cast<double>(received_) : 0.0, wakeups_, recv_calls_, send_calls_,
                    recv_calls_ ? static_cast<double>(received_) / static_cast<double>(recv_calls_) : 0.0,
                    send_calls_ ? static_cast<double>(sent_) / static_cast<double>(send_calls_) : 0.0, gro_messages_);
    }

private:
    template <class H>
    auto immediate(H&& h) { return asio::bind_immediate_executor(ctx_.get_executor(), std::forward<H>(h)); }

    // The textbook loop: one datagram per completion, one send per reply.
    void arm_asio() {
        sock_.async_receive_from(asio::buffer(buf_.data(), slot_), peer_, immediate([this](const asio::error_code& ec, std::size_t n) {
            if (ec) { if (ec != asio::error::operation_aborted) std::fprintf(stderr, "recv: %s\n", ec.message().c_str()); return; }
            ++wakeups_; ++recv_calls_; ++received_;
            asio::error_code sec;
            sock_.send_to(asio::buffer(buf_.data(), n), peer_, 0, sec);
            ++send_calls_;
            if (!sec) ++sent_;
            rearm([this] { arm_asio(); });
        }));
    }

    // A speculative read that finds a datagram completes inline (the immediate executor),
    // and a client that never lets the queue empty would recurse for ever: the yield budget
    // of Connection::finish_response, here every 64 inline completions.
    template <class F>
    void rearm(F f) {
        if (++inline_ < 64) { f(); return; }
        inline_ = 0;
        asio::post(ctx_, std::move(f));
    }

    // Asio's speculative read gets the first datagram (or queues without an epoll_ctl);
    // the rest of the burst is drained with recvmmsg.
    void arm_spec() {
        sock_.async_receive_from(asio::buffer(buf_.data(), slot_), peer_, immediate([this](const asio::error_code& ec, std::size_t n) {
            if (ec) { if (ec != asio::error::operation_aborted) std::fprintf(stderr, "recv: %s\n", ec.message().c_str()); return; }
            ++wakeups_; ++recv_calls_; ++received_;
            // The first datagram is answered on its own (it came through Asio's buffer).
            asio::error_code sec;
            sock_.send_to(asio::buffer(buf_.data(), n), peer_, 0, sec);
            ++send_calls_;
            if (!sec) ++sent_;
            drain();
            rearm([this] { arm_spec(); });
        }));
    }

    // Readiness only; every datagram through recvmmsg.
    void arm_wait() {
        sock_.async_wait(asio::socket_base::wait_read, immediate([this](const asio::error_code& ec) {
            if (ec) { if (ec != asio::error::operation_aborted) std::fprintf(stderr, "wait: %s\n", ec.message().c_str()); return; }
            ++wakeups_;
            drain();
            arm_wait();
        }));
    }

    void drain() {
        const int fd = sock_.native_handle();
        for (int rounds = 0; rounds < 64; ++rounds) {  // a bound per wake-up: other work gets the loop back
            for (int i = 0; i < batch_; ++i) {
                iov_[static_cast<std::size_t>(i)] = {buf_.data() + static_cast<std::size_t>(i) * slot_, slot_};
                msghdr& h = msgs_[static_cast<std::size_t>(i)].msg_hdr;
                h = {};
                h.msg_name = &addrs_[static_cast<std::size_t>(i)];
                h.msg_namelen = sizeof(sockaddr_storage);
                h.msg_iov = &iov_[static_cast<std::size_t>(i)];
                h.msg_iovlen = 1;
                h.msg_control = ctl_.data() + static_cast<std::size_t>(i) * 64;
                h.msg_controllen = 64;
            }
            const int r = recvmmsg(fd, msgs_.data(), static_cast<unsigned>(batch_), MSG_DONTWAIT, nullptr);
            ++recv_calls_;
            if (r < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) std::perror("recvmmsg");
                return;
            }
            if (r == 0) return;
            out_.clear();
            oiov_.clear();
            for (int i = 0; i < r; ++i) reply(i);
            flush();
            if (r < batch_) return;  // the queue is empty (or nearly): back to the loop
        }
    }

    // Queues the replies for received message i: one datagram per segment, or one GSO
    // message for the whole coalesced buffer.
    void reply(int i) {
        const mmsghdr& m = msgs_[static_cast<std::size_t>(i)];
        const std::size_t len = m.msg_len;
        received_ += 0;  // counted per segment below
        int gso_size = 0;
        for (cmsghdr* c = CMSG_FIRSTHDR(&m.msg_hdr); c; c = CMSG_NXTHDR(const_cast<msghdr*>(&m.msg_hdr), c))
            if (c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_GRO) std::memcpy(&gso_size, CMSG_DATA(c), sizeof gso_size);
        char* data = buf_.data() + static_cast<std::size_t>(i) * slot_;
        const std::size_t seg = gso_size > 0 ? static_cast<std::size_t>(gso_size) : len;
        const std::size_t segments = seg ? (len + seg - 1) / seg : 1;
        received_ += segments;
        if (segments > 1) ++gro_messages_;
        if (gso_ && segments > 1) {
            // One message, the kernel splits it by seg (at most 64 segments per message).
            std::size_t off = 0;
            while (off < len) {
                const std::size_t take = std::min(len - off, seg * 64);
                oiov_.push_back({data + off, take});
                mmsghdr o{};
                o.msg_hdr.msg_name = const_cast<void*>(m.msg_hdr.msg_name);
                o.msg_hdr.msg_namelen = m.msg_hdr.msg_namelen;
                o.msg_hdr.msg_iov = &oiov_.back();  // fixed up in flush (the vector may move)
                o.msg_hdr.msg_iovlen = 1;
                if (take > seg) {
                    char* ctl = octl_.data() + out_.size() * CMSG_SPACE(sizeof(std::uint16_t));
                    o.msg_hdr.msg_control = ctl;
                    o.msg_hdr.msg_controllen = CMSG_SPACE(sizeof(std::uint16_t));
                    cmsghdr* c = CMSG_FIRSTHDR(&o.msg_hdr);
                    c->cmsg_level = SOL_UDP;
                    c->cmsg_type = UDP_SEGMENT;
                    c->cmsg_len = CMSG_LEN(sizeof(std::uint16_t));
                    const std::uint16_t s = static_cast<std::uint16_t>(seg);
                    std::memcpy(CMSG_DATA(c), &s, sizeof s);
                }
                out_.push_back(o);
                off += take;
            }
            return;
        }
        for (std::size_t s = 0; s < segments; ++s) {
            const std::size_t off = s * seg;
            oiov_.push_back({data + off, std::min(seg, len - off)});
            mmsghdr o{};
            o.msg_hdr.msg_name = const_cast<void*>(m.msg_hdr.msg_name);
            o.msg_hdr.msg_namelen = m.msg_hdr.msg_namelen;
            o.msg_hdr.msg_iovlen = 1;
            out_.push_back(o);
        }
    }

    void flush() {
        for (std::size_t k = 0; k < out_.size(); ++k) out_[k].msg_hdr.msg_iov = &oiov_[k];
        const int fd = sock_.native_handle();
        std::size_t done = 0;
        while (done < out_.size()) {
            const int r = sendmmsg(fd, out_.data() + done, static_cast<unsigned>(out_.size() - done), 0);
            ++send_calls_;
            if (r < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    pollfd p{fd, POLLOUT, 0};
                    poll(&p, 1, 100);
                    continue;
                }
                std::perror("sendmmsg");
                return;
            }
            for (int i = 0; i < r; ++i) {
                const mmsghdr& o = out_[done + static_cast<std::size_t>(i)];
                sent_ += o.msg_hdr.msg_control ? (o.msg_hdr.msg_iov[0].iov_len + gso_of(o) - 1) / gso_of(o) : 1;
            }
            done += static_cast<std::size_t>(r);
        }
    }

    static std::size_t gso_of(const mmsghdr& o) {
        std::uint16_t s = 0;
        std::memcpy(&s, CMSG_DATA(CMSG_FIRSTHDR(const_cast<msghdr*>(&o.msg_hdr))), sizeof s);
        return s ? s : 1;
    }

    Mode mode_;
    int batch_;
    bool gro_, gso_;
    asio::io_context ctx_{1};
    asio::ip::udp::socket sock_;
    asio::steady_timer timer_;
    asio::ip::udp::endpoint peer_;
    std::size_t slot_ = 0;
    std::vector<char> buf_;
    std::vector<mmsghdr> msgs_;
    std::vector<iovec> iov_;
    std::vector<sockaddr_storage> addrs_;
    std::vector<char> ctl_;
    std::vector<mmsghdr> out_;
    std::vector<iovec> oiov_;
    std::vector<char> octl_;
    unsigned inline_ = 0;
    unsigned long long received_ = 0, sent_ = 0, wakeups_ = 0, recv_calls_ = 0, send_calls_ = 0, gro_messages_ = 0;
    double cpu0_ = 0;
    clock_type::time_point t0_;
};

// ---- client ----

struct Totals {
    std::atomic<unsigned long long> sent{0}, received{0}, lost{0};
};

void pin(const std::vector<int>& cpus, int index) {
    if (cpus.empty()) return;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpus[static_cast<std::size_t>(index) % cpus.size()], &set);
    sched_setaffinity(0, sizeof set, &set);
}

std::vector<int> parse_cpus(const char* list) {
    std::vector<int> out;
    if (!list || !*list) return out;
    std::string s(list);
    std::size_t pos = 0;
    while (pos < s.size()) {
        std::size_t comma = s.find(',', pos);
        if (comma == std::string::npos) comma = s.size();
        const std::string part = s.substr(pos, comma - pos);
        const std::size_t dash = part.find('-');
        if (dash == std::string::npos) out.push_back(std::atoi(part.c_str()));
        else
            for (int c = std::atoi(part.substr(0, dash).c_str()); c <= std::atoi(part.substr(dash + 1).c_str()); ++c) out.push_back(c);
        pos = comma + 1;
    }
    return out;
}

void client_thread(int index, const std::vector<int>& cpus, const char* host, unsigned short port, int flows, int window,
                   int size, int seconds, bool gso, Totals& totals) {
    pin(cpus, index);
    struct Flow {
        int fd;
        int outstanding = 0;
        clock_type::time_point sent_at;
    };
    std::vector<Flow> fl;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    for (int f = 0; f < flows; ++f) {
        const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        set_buffers(fd);
        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) { std::perror("connect"); std::exit(2); }
        fl.push_back({fd, 0, {}});
    }
    std::vector<char> payload(static_cast<std::size_t>(window) * static_cast<std::size_t>(size), 'x');
    std::vector<char> rbuf(64 * 2048);
    std::vector<mmsghdr> msgs(64);
    std::vector<iovec> iov(64);
    std::vector<pollfd> pfds(static_cast<std::size_t>(flows));
    const auto deadline = clock_type::now() + std::chrono::seconds(seconds);
    unsigned long long sent = 0, received = 0, lost = 0;
    while (clock_type::now() < deadline) {
        const auto now = clock_type::now();
        for (Flow& f : fl) {
            if (f.outstanding > 0 && now - f.sent_at > std::chrono::milliseconds(200)) {
                lost += static_cast<unsigned long long>(f.outstanding);
                f.outstanding = 0;
            }
            if (f.outstanding == 0) {
                if (gso) {
                    // The burst as one message the kernel splits (at most 64 segments, 64 KB).
                    std::size_t off = 0;
                    const std::size_t total = payload.size();
                    while (off < total) {
                        const std::size_t take = std::min(total - off, std::min<std::size_t>(static_cast<std::size_t>(size) * 64, 65535 / static_cast<std::size_t>(size) * static_cast<std::size_t>(size)));
                        iovec v{payload.data() + off, take};
                        char ctl[CMSG_SPACE(sizeof(std::uint16_t))] = {};
                        msghdr mh{};
                        mh.msg_iov = &v;
                        mh.msg_iovlen = 1;
                        if (take > static_cast<std::size_t>(size)) {
                            mh.msg_control = ctl;
                            mh.msg_controllen = sizeof ctl;
                            cmsghdr* c = CMSG_FIRSTHDR(&mh);
                            c->cmsg_level = SOL_UDP;
                            c->cmsg_type = UDP_SEGMENT;
                            c->cmsg_len = CMSG_LEN(sizeof(std::uint16_t));
                            const std::uint16_t s = static_cast<std::uint16_t>(size);
                            std::memcpy(CMSG_DATA(c), &s, sizeof s);
                        }
                        while (sendmsg(f.fd, &mh, 0) < 0) {
                            if (errno != EAGAIN && errno != EWOULDBLOCK) { std::perror("sendmsg"); std::exit(2); }
                            pollfd p{f.fd, POLLOUT, 0};
                            poll(&p, 1, 100);
                        }
                        off += take;
                    }
                } else {
                    for (int i = 0; i < window; ++i)
                        while (send(f.fd, payload.data(), static_cast<std::size_t>(size), 0) < 0) {
                            if (errno != EAGAIN && errno != EWOULDBLOCK) { std::perror("send"); std::exit(2); }
                            pollfd p{f.fd, POLLOUT, 0};
                            poll(&p, 1, 100);
                        }
                }
                f.outstanding = window;
                f.sent_at = now;
                sent += static_cast<unsigned long long>(window);
            }
        }
        for (std::size_t i = 0; i < fl.size(); ++i) pfds[i] = {fl[i].fd, POLLIN, 0};
        poll(pfds.data(), pfds.size(), 1);
        for (std::size_t i = 0; i < fl.size(); ++i) {
            if (!(pfds[i].revents & POLLIN)) continue;
            for (;;) {
                for (int k = 0; k < 64; ++k) {
                    iov[static_cast<std::size_t>(k)] = {rbuf.data() + static_cast<std::size_t>(k) * 2048, 2048};
                    msghdr& h = msgs[static_cast<std::size_t>(k)].msg_hdr;
                    h = {};
                    h.msg_iov = &iov[static_cast<std::size_t>(k)];
                    h.msg_iovlen = 1;
                }
                const int r = recvmmsg(fl[i].fd, msgs.data(), 64, MSG_DONTWAIT, nullptr);
                if (r <= 0) break;
                received += static_cast<unsigned long long>(r);
                fl[i].outstanding = std::max(0, fl[i].outstanding - r);
                if (r < 64) break;
            }
        }
    }
    totals.sent += sent;
    totals.received += received;
    totals.lost += lost;
    for (Flow& f : fl) close(f.fd);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: udpbench server MODE PORT [...] | udpbench client HOST PORT [...]\n");
        return 2;
    }
    const std::string role = argv[1];
    if (role == "server") {
        const std::string m = argv[2];
        const Mode mode = m == "asio" ? Mode::asio : m == "spec" ? Mode::spec : Mode::wait;
        Server s(mode, static_cast<unsigned short>(std::atoi(argv[3])), arg_int(argc, argv, "--batch", 64), arg_flag(argc, argv, "--gro"),
                 arg_flag(argc, argv, "--gso"));
        s.run(arg_int(argc, argv, "--seconds", 5));
        return 0;
    }
    const char* host = argv[2];
    const unsigned short port = static_cast<unsigned short>(std::atoi(argv[3]));
    const int threads = arg_int(argc, argv, "--threads", 4);
    const int flows = arg_int(argc, argv, "--flows", 4);
    const int window = arg_int(argc, argv, "--window", 8);
    const int size = arg_int(argc, argv, "--size", 1200);
    const int seconds = arg_int(argc, argv, "--seconds", 5);
    const bool gso = arg_flag(argc, argv, "--gso");
    const std::vector<int> cpus = parse_cpus(arg_str(argc, argv, "--cpus", ""));
    Totals totals;
    std::vector<std::thread> ts;
    const auto t0 = clock_type::now();
    for (int i = 0; i < threads; ++i)
        ts.emplace_back(client_thread, i, std::cref(cpus), host, port, flows, window, size, seconds, gso, std::ref(totals));
    for (auto& t : ts) t.join();
    const double secs = std::chrono::duration<double>(clock_type::now() - t0).count();
    std::printf("client threads=%d flows=%d window=%d size=%d gso=%d sent=%llu received=%llu lost=%llu received_per_sec=%.0f\n", threads,
                flows, window, size, gso ? 1 : 0, totals.sent.load(), totals.received.load(), totals.lost.load(),
                static_cast<double>(totals.received.load()) / secs);
    return 0;
}
