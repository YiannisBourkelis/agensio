// The configuration reference (F11): every key agensio reads, in one table, for the agent
// and the administrator. Each row says what the key does, its type and default, whether a
// change applies on reload or needs a restart, and who can change it: the root-owned main
// file, a site file (managed ones through site-create/site-update, hand-written ones by
// hand), or the control plane's per-site `settings`. The MCP tool `config_reference`, the
// CLI (`agensio keys`, `agensio ctl reference`) and the generated `docs/keys.md` all come
// from this table, and the tests hold it to the parser and to the reference document.
#pragma once

#include <string>
#include <vector>

#include "config.hpp"
#include "services/json.hpp"

namespace agensio::control {

struct KeyDef {
    const char* table;    // "[server]", "[cache]", "[log]", "[control]", "[server] acme", "[[site]]", "php = {}", "proxy = {}", "[[site.location]]", "cgi = {}", "top level"
    const char* key;
    const char* type;     // int, seconds, size, bool, string, path, list, table, or "enum: a | b"
    const char* def;      // the default, in words
    const char* meaning;  // one or two sentences: what it does and when to use it
    const char* applies;  // "reload" (agensio reload / the control plane's reload) or "restart" (systemctl restart agensio)
    const char* via;      // "file" (root edits the main file), "site file" (a hand-written site file), "site-create" (a field of site-create / site-update), "settings" (site-update's settings, within [control] site_limits)
    const char* doc;      // the section of docs/configuration.md that explains it ("7", "12b")
};

const std::vector<KeyDef>& key_defs();

// The reference as JSON: {"keys": [...], "note": ...}. With a running configuration the
// server-level rows carry their current value ("running") and the file it comes from.
json::Value config_reference(const Config* running);

// The same as Markdown, what docs/keys.md holds (generated: `agensio keys --markdown`).
std::string reference_markdown();

}  // namespace agensio::control
