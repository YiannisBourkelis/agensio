// `agensio mcp` (F5): a Model Context Protocol server on stdin/stdout that exposes the
// control API as tools. It is spawned by the agent host (locally, or over SSH:
// `ssh admin@vps agensio mcp`), connects to the control socket as the invoking user, and
// holds no secret of its own. It is not a listener: nothing can connect to it.
#pragma once

#include <iosfwd>
#include <string>
#include <string_view>

namespace agensio {

// Serves newline-delimited JSON-RPC on `in`/`out` until EOF. Returns the exit code.
int run_mcp(const std::string& socket_path, std::istream& in, std::ostream& out);

// What the bridge tells the agent when it and the server are different builds ("" when they
// are the same, or the server does not say): a long-lived bridge keeps the tools and texts it
// started with after an upgrade (2026-09-27 report: an alpha.23 bridge in front of alpha.25,
// no site_task, the old enum, and nothing said so). Pure.
std::string version_mismatch_note(std::string_view bridge, std::string_view server);

}  // namespace agensio
