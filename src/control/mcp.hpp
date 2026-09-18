// `agensio mcp` (F5): a Model Context Protocol server on stdin/stdout that exposes the
// control API as tools. It is spawned by the agent host (locally, or over SSH:
// `ssh admin@vps agensio mcp`), connects to the control socket as the invoking user, and
// holds no secret of its own. It is not a listener: nothing can connect to it.
#pragma once

#include <iosfwd>
#include <string>

namespace agensio {

// Serves newline-delimited JSON-RPC on `in`/`out` until EOF. Returns the exit code.
int run_mcp(const std::string& socket_path, std::istream& in, std::ostream& out);

}  // namespace agensio
