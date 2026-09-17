// CGI/1.1 as an upstream exchange (phase D5): the "connection" is a process. The child gets
// one end of a socketpair as its stdin and stdout, so the request body goes out as plain
// bytes (then the write side is shut to give it EOF) and its output comes back as a CGI
// head plus a body that ends with the process's exit, the way an HTTP close-delimited body
// does. Its stderr is captured for the error log. Everything else (pool cap and queue,
// timeouts, buffering, spill, streaming) is UpstreamRequest's. One process per request,
// nothing kept: legacy applications, not a fast path.
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "upstream/client.hpp"

namespace agensio {

class CgiRequest final : public UpstreamRequest {
public:
    CgiRequest(UpstreamPool& pool, const std::vector<UpstreamAddress>& group, const UpstreamOptions& options)
        : UpstreamRequest(pool, group, options) {}
    ~CgiRequest() override;

    // `env`: the CGI variables as "NAME=value" strings; `argv`: the interpreter (if any)
    // and the script; `cwd`: the script's directory. See UpstreamRequest::begin for the rest.
    void start(std::vector<std::string> env, std::vector<std::string> argv, std::string cwd, UpstreamBodyInput body,
               bool priority, Completion done) {
        env_ = std::move(env);
        argv_ = std::move(argv);
        cwd_ = std::move(cwd);
        begin(std::move(body), priority, false, std::move(done));
    }

private:
    void connect() override;  // spawns the process instead of connecting a socket
    void encode_head(std::string&) override {}
    void encode_body_chunk(std::string& out, std::string_view bytes, bool) override { out.append(bytes); }
    void on_body_sent() override;  // EOF on the child's stdin
    bool decode() override;
    HeadStatus parse_head(std::string_view in, int& status, Headers& headers, std::size_t& length) override;
    bool on_eof() override;
    bool keep_alive_ok() const noexcept override { return false; }
    void on_end(bool ok) override;  // reap or kill the child
    void read_stderr();

    std::vector<std::string> env_;
    std::vector<std::string> argv_;
    std::string cwd_;
    long pid_ = 0;
#ifndef _WIN32
    std::unique_ptr<asio::posix::stream_descriptor> stderr_;
#endif
    std::vector<char> errbuf_;
    static constexpr std::size_t kStderrCap = 64 * 1024;
};

}  // namespace agensio
