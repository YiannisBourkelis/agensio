#include "control/approvals.hpp"

#include <algorithm>

#include "services/tasks.hpp"

#ifdef AGENSIO_HAS_TLS
#include <openssl/rand.h>
#endif

namespace agensio::control {

std::string escape_for_terminal(std::string_view text) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7f)) {
            out.push_back(static_cast<char>(c));
            continue;
        }
        out += "\\x";
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 15]);
    }
    return out;
}

std::string new_approval_id() {
#ifdef AGENSIO_HAS_TLS
    unsigned char bytes[6];
    if (RAND_bytes(bytes, sizeof bytes) != 1) return "";
    static constexpr char kHex[] = "0123456789abcdef";
    std::string id;
    for (const unsigned char b : bytes) {
        id.push_back(kHex[b >> 4]);
        id.push_back(kHex[b & 15]);
    }
    return id;
#else
    return "";
#endif
}

const char* state_name(PendingChange::State s) noexcept {
    switch (s) {
        case PendingChange::State::waiting: return "waiting";
        case PendingChange::State::running: return "running";
        case PendingChange::State::done: return "done";
        case PendingChange::State::failed: return "failed";
        case PendingChange::State::rejected: return "rejected";
    }
    return "?";
}

void ApprovalStore::expire(std::time_t now) {
    changes_.remove_if([&](const PendingChange& c) {
        if (c.state == PendingChange::State::running) return false;
        const std::time_t since = c.state == PendingChange::State::waiting ? c.created : c.finished;
        return now - since >= kTtl;
    });
}

bool ApprovalStore::add(PendingChange change, std::time_t now) {
    expire(now);
    if (waiting(now).size() >= kMaxWaiting) return false;
    change.created = now;
    changes_.push_back(std::move(change));
    return true;
}

PendingChange* ApprovalStore::find(std::string_view id, std::time_t now) {
    expire(now);
    for (auto& c : changes_)
        if (c.id == id) return &c;
    return nullptr;
}

std::vector<PendingChange*> ApprovalStore::waiting(std::time_t now) {
    expire(now);
    std::vector<PendingChange*> out;
    for (auto& c : changes_)
        if (c.state == PendingChange::State::waiting) out.push_back(&c);
    return out;
}

std::vector<PendingChange*> ApprovalStore::all(std::time_t now) {
    expire(now);
    std::vector<PendingChange*> out;
    for (auto& c : changes_) out.push_back(&c);
    return out;
}

bool ApprovalStore::reject(std::string_view id, std::time_t now) {
    PendingChange* c = find(id, now);
    if (!c || c->state != PendingChange::State::waiting) return false;
    c->state = PendingChange::State::rejected;
    c->finished = now;
    return true;
}

json::Value pending_json(const PendingChange& c, std::time_t now, bool with_result) {
    json::Value reasons = json::Value::array();
    for (const auto& r : c.reasons) reasons.push(r);
    json::Value v = json::Value::object()
                        .set("id", c.id)
                        .set("path", c.path)
                        .set("state", state_name(c.state))
                        .set("queued_by_uid", static_cast<double>(c.uid))
                        .set("client", c.client)
                        .set("age_s", static_cast<double>(now - c.created))
                        .set("needs_approval", std::move(reasons))
                        .set("preview", c.preview)
                        .set("their_reason", c.reason);
    if (c.state == PendingChange::State::waiting) v.set("expires_in_s", static_cast<double>(ApprovalStore::kTtl - (now - c.created)));
    if (!c.approver.empty()) v.set("approved_by", c.approver);
    if (with_result && (c.state == PendingChange::State::done || c.state == PendingChange::State::failed)) {
        v.set("status", c.status);
        v.set("result", c.result);
    }
    return v;
}

std::string pending_text(const PendingChange& c, std::time_t now) {
    std::string t = "[" + c.id + "] " + c.path + "  (queued " + std::to_string((now - c.created) / 60) + " min ago by uid " + std::to_string(c.uid) +
                    (c.client.empty() ? std::string() : " via " + c.client) + ")\n";
    for (const auto& r : c.reasons) t += "  !! " + r + "\n";
    std::string body = c.preview;
    std::size_t at = 0;
    while (at < body.size()) {
        const std::size_t end = std::min(body.find('\n', at), body.size());
        t += "  | " + body.substr(at, end - at) + "\n";
        at = end + 1;
    }
    if (!c.reason.empty()) t += "  the requester's own words (not checked): \"" + c.reason + "\"\n";
    return escape_for_terminal(t);
}

std::vector<std::string> approval_reasons(std::string_view path, std::string_view action, const json::Value& body) {
    std::vector<std::string> out;
    const bool site_path = path.starts_with("/v1/sites/");
    // A task whose caller names what gets installed (pip_install, row 32): code from a package index
    // runs as the site's account.
    if (site_path && action == "task" && tasks::needs_user_confirmation(body.get("task")))
        out.push_back("installs the Python packages it names into the site's virtualenv: their code runs as the site's account");
    return out;
}

}  // namespace agensio::control
