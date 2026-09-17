#include "upstream/cgi_client.hpp"

#include "upstream/fcgi.hpp"

#include <cerrno>
#include <csignal>
#include <cstring>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace agensio {

CgiRequest::~CgiRequest() { on_end(false); }

#ifndef _WIN32
namespace {

// Closes every descriptor from `from` up in the child (after fork, before exec): the
// listeners, the cache's files and the other connections must not leak into a CGI process.
void close_from(int from) noexcept {
#if defined(__linux__) && defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
    if (::close_range(static_cast<unsigned>(from), ~0U, 0) == 0) return;
#endif
    const long max = ::sysconf(_SC_OPEN_MAX);
    for (int fd = from; fd < (max > 0 ? static_cast<int>(max) : 65536); ++fd) ::close(fd);
}

}  // namespace
#endif

// fork + exec with a socketpair for stdin/stdout and a pipe for stderr; the parent side of
// the pair becomes the exchange's connection (a unix stream socket, so the base class
// reads and writes it like any upstream).
void CgiRequest::connect() {
#ifdef _WIN32
    fail(UpstreamFailure::connect_error, std::error_code(asio::error::operation_not_supported));
#else
    int sv[2] = {-1, -1};
    int errp[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0 || ::pipe(errp) != 0) {
        const int e = errno;
        for (int fd : {sv[0], sv[1], errp[0], errp[1]})
            if (fd >= 0) ::close(fd);
        fail(UpstreamFailure::connect_error, std::error_code(e, std::generic_category()));
        return;
    }
    std::vector<char*> argv, envp;
    for (auto& a : argv_) argv.push_back(a.data());
    argv.push_back(nullptr);
    for (auto& e : env_) envp.push_back(e.data());
    envp.push_back(nullptr);
    const pid_t pid = ::fork();
    if (pid < 0) {
        const int e = errno;
        for (int fd : {sv[0], sv[1], errp[0], errp[1]}) ::close(fd);
        fail(UpstreamFailure::connect_error, std::error_code(e, std::generic_category()));
        return;
    }
    if (pid == 0) {  // the child: only async-signal-safe calls until exec
        ::dup2(sv[1], 0);
        ::dup2(sv[1], 1);
        ::dup2(errp[1], 2);
        close_from(3);
        if (!cwd_.empty() && ::chdir(cwd_.c_str()) != 0) ::_exit(126);
        ::execve(argv[0], argv.data(), envp.data());
        ::_exit(127);
    }
    ::close(sv[1]);
    ::close(errp[1]);
    pid_ = pid;
    ::fcntl(sv[0], F_SETFD, FD_CLOEXEC);
    ::fcntl(errp[0], F_SETFD, FD_CLOEXEC);
    asio::error_code ec;
    conn_->socket.assign(asio::generic::stream_protocol(AF_UNIX, 0), sv[0], ec);
    if (ec) {
        ::close(sv[0]);
        ::close(errp[0]);
        fail(UpstreamFailure::connect_error, ec);
        return;
    }
    conn_->socket.non_blocking(true, ec);
    stderr_ = std::make_unique<asio::posix::stream_descriptor>(conn_->socket.get_executor(), errp[0]);
    read_stderr();
    connected();
#endif
}

void CgiRequest::read_stderr() {
#ifndef _WIN32
    if (!stderr_) return;
    if (errbuf_.size() < 4096) errbuf_.resize(4096);
    auto self = std::static_pointer_cast<CgiRequest>(shared_from_this());
    stderr_->async_read_some(asio::buffer(errbuf_), [self](const asio::error_code& ec, std::size_t n) {
        if (ec || !self->stderr_) return;  // EOF: the child closed its stderr
        if (self->result_.stderr_text.size() < kStderrCap)
            self->result_.stderr_text.append(self->errbuf_.data(),
                                             std::min(n, kStderrCap - self->result_.stderr_text.size()));
        self->read_stderr();
    });
#endif
}

// The body went out: shut the write side so the script sees EOF on stdin.
void CgiRequest::on_body_sent() {
#ifndef _WIN32
    asio::error_code ec;
    conn_->sock().shutdown(asio::socket_base::shutdown_send, ec);
#endif
}

UpstreamRequest::HeadStatus CgiRequest::parse_head(std::string_view in, int& status, Headers& headers,
                                                    std::size_t& length) {
    fcgi::CgiHead head;
    const auto hs = fcgi::parse_cgi_head(in, head);
    if (hs == fcgi::HeadStatus::incomplete) return HeadStatus::incomplete;
    if (hs == fcgi::HeadStatus::error) return HeadStatus::error;
    status = head.status;
    headers = head.headers;
    length = head.length;
    return HeadStatus::complete;
}

// The head, then everything until the process closes its stdout is body.
bool CgiRequest::decode() {
    std::string_view in(conn_->in.data(), conn_->in_len);
    if (in.empty()) return true;
    if (!head_done()) {
        std::size_t used = 0;
        const HeadStatus hs = feed_head(in, used);
        if (hs == HeadStatus::error) return false;
        consume(used);
        if (hs == HeadStatus::incomplete) return true;
        in = std::string_view(conn_->in.data(), conn_->in_len);
    }
    if (!store_body(in)) return false;
    consume(in.size());
    return true;
}

bool CgiRequest::on_eof() {
    if (!head_done()) return false;  // exited without a head: closed_early, logged with its stderr
    finish();
    return true;
}

// Reap the child; one that is still running after the exchange ended (a timeout, the
// client gone) is killed. A child that has not exited yet is left to the pool's tick.
void CgiRequest::on_end(bool ok) {
#ifndef _WIN32
    stderr_.reset();
    if (pid_ <= 0) return;
    const pid_t pid = static_cast<pid_t>(pid_);
    pid_ = 0;
    int status = 0;
    if (::waitpid(pid, &status, WNOHANG) == pid) return;
    if (!ok) ::kill(pid, SIGKILL);
    if (::waitpid(pid, &status, WNOHANG) != pid) pool_.reap_later(pid);
#else
    (void)ok;
#endif
}

}  // namespace agensio
