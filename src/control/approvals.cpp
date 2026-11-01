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

std::string pending_text(const PendingChange& c, std::time_t now, std::size_t max_lines) {
    std::string t = "[" + c.id + "] " + c.path + "  (queued " + std::to_string((now - c.created) / 60) + " min ago by uid " + std::to_string(c.uid) +
                    (c.client.empty() ? std::string() : " via " + c.client) + ")\n";
    for (const auto& r : c.reasons) t += "  !! " + r + "\n";
    std::string body = c.preview;
    std::size_t at = 0, shown = 0, rest = 0;
    while (at < body.size()) {
        const std::size_t end = std::min(body.find('\n', at), body.size());
        if (max_lines == 0 || shown < max_lines) {
            t += "  | " + body.substr(at, end - at) + "\n";
            ++shown;
        } else {
            ++rest;
        }
        at = end + 1;
    }
    if (rest) t += "  | ... " + std::to_string(rest) + " more lines: agensio ctl approve --show " + c.id + " prints them all\n";
    if (!c.reason.empty()) t += "  the requester's own words (not checked): \"" + c.reason + "\"\n";
    return escape_for_terminal(t);
}

namespace {

std::vector<std::string_view> lines_of(std::string_view text) {
    std::vector<std::string_view> out;
    std::size_t at = 0;
    while (at < text.size()) {
        const std::size_t end = text.find('\n', at);
        if (end == std::string_view::npos) {
            out.push_back(text.substr(at));
            break;
        }
        out.push_back(text.substr(at, end - at));
        at = end + 1;
    }
    return out;
}

}  // namespace

std::string unified_diff(std::string_view before, std::string_view after, std::size_t max_lines) {
    const std::vector<std::string_view> a = lines_of(before), b = lines_of(after);
    const int n = static_cast<int>(a.size()), m = static_cast<int>(b.size());
    // Myers' O((N+M)D) shortest edit script; each step's furthest reaches kept for the way back.
    constexpr int kMaxEdits = 1500;
    const int max = n + m;
    const int limit = std::min(max, kMaxEdits);
    std::vector<std::vector<int>> trace;
    std::vector<int> v(2 * static_cast<std::size_t>(max) + 3, 0);
    const int off = max + 1;
    int found = -1;
    for (int d = 0; d <= limit && found < 0; ++d) {
        for (int k = -d; k <= d; k += 2) {
            int x = (k == -d || (k != d && v[off + k - 1] < v[off + k + 1])) ? v[off + k + 1] : v[off + k - 1] + 1;
            int y = x - k;
            while (x < n && y < m && a[static_cast<std::size_t>(x)] == b[static_cast<std::size_t>(y)]) ++x, ++y;
            v[off + k] = x;
            if (x >= n && y >= m) {
                found = d;
                break;
            }
        }
        trace.emplace_back(v.begin() + (off - d), v.begin() + (off + d + 1));
    }
    std::string out;
    if (found < 0) {  // too different to be worth a diff: the new text whole
        out = "the file is replaced whole (" + std::to_string(n) + " lines before, " + std::to_string(m) + " after); its new text:\n";
        std::size_t shown = 0;
        for (const auto& l : b) {
            if (max_lines && shown >= max_lines) break;
            out += "+" + std::string(l) + "\n";
            ++shown;
        }
        if (max_lines && b.size() > shown) out += "... " + std::to_string(b.size() - shown) + " more lines\n";
        return out;
    }
    // The way back: per line, ' ' kept, '-' gone, '+' new.
    struct Edit {
        char kind;
        int ai, bi;
    };
    std::vector<Edit> edits;
    int x = n, y = m;
    for (int d = found; d >= 0; --d) {
        const std::vector<int>& vd = trace[static_cast<std::size_t>(d)];
        auto at = [&](const std::vector<int>& row, int dd, int k) { return row[static_cast<std::size_t>(k + dd)]; };
        const int k = x - y;
        int prev_k = k;
        if (d > 0) {
            const std::vector<int>& vp = trace[static_cast<std::size_t>(d - 1)];
            const bool down = k == -d || (k != d && at(vp, d - 1, k - 1) < at(vp, d - 1, k + 1));
            prev_k = down ? k + 1 : k - 1;
            const int prev_x = at(vp, d - 1, prev_k), prev_y = prev_x - prev_k;
            while (x > prev_x && y > prev_y) edits.push_back({' ', --x, --y});
            if (down) edits.push_back({'+', x, --y});
            else edits.push_back({'-', --x, y});
        } else {
            while (x > 0 && y > 0) edits.push_back({' ', --x, --y});
        }
        (void)vd;
    }
    std::reverse(edits.begin(), edits.end());
    if (std::none_of(edits.begin(), edits.end(), [](const Edit& e) { return e.kind != ' '; })) return "no change\n";
    // Hunks: the changed lines with three lines of context around each.
    std::vector<bool> keep(edits.size(), false);
    for (std::size_t i = 0; i < edits.size(); ++i)
        if (edits[i].kind != ' ')
            for (std::size_t j = i >= 3 ? i - 3 : 0; j <= i + 3 && j < edits.size(); ++j) keep[j] = true;
    std::size_t written = 0, total = 0;
    for (std::size_t i = 0; i < edits.size();) {
        if (!keep[i]) {
            ++i;
            continue;
        }
        std::size_t j = i;
        int a_start = -1, b_start = -1, a_len = 0, b_len = 0;
        std::string body;
        for (; j < edits.size() && keep[j]; ++j) {
            const Edit& e = edits[j];
            if (e.kind != '+') {
                if (a_start < 0) a_start = e.ai;
                ++a_len;
            }
            if (e.kind != '-') {
                if (b_start < 0) b_start = e.bi;
                ++b_len;
            }
            const std::string_view line = e.kind == '+' ? b[static_cast<std::size_t>(e.bi)] : a[static_cast<std::size_t>(e.ai)];
            ++total;
            if (!max_lines || written < max_lines) {
                body += std::string(1, e.kind) + std::string(line) + "\n";
                ++written;
            }
        }
        out += "@@ -" + std::to_string(a_start < 0 ? 0 : a_start + 1) + "," + std::to_string(a_len) + " +" + std::to_string(b_start < 0 ? 0 : b_start + 1) + "," +
               std::to_string(b_len) + " @@\n" + body;
        i = j;
    }
    if (max_lines && total > written) out += "... " + std::to_string(total - written) + " more lines of the diff\n";
    return out;
}

std::vector<std::string> approval_reasons(std::string_view path, std::string_view action, const json::Value& body, bool secret_read) {
    std::vector<std::string> out;
    const bool site_path = path.starts_with("/v1/sites/");
    // The site's files (F12): every change, whatever it is; a read only of a secret, which would leave
    // the server for whoever asked (docs/design-site-operations.md 27.2).
    if (site_path && action == "file") {
        const std::string op(body.get("op")), rel(body.get("path"));
        if (op == "write") out.push_back("writes " + rel + " into the site: what the site serves, or runs, changes");
        else if (op == "edit") out.push_back("changes " + rel + " in the site: what the site serves, or runs, changes");
        else if (op == "mkdir") out.push_back("creates the directory " + rel + " in the site");
        else if (op == "move") out.push_back("moves " + rel + " to " + std::string(body.get("to")) + " in the site");
        else if (op == "delete") out.push_back("deletes " + rel + " from the site");
        else if (op == "restore") out.push_back("puts an earlier version of " + rel + " back into the site");
        else if (op == "read" && secret_read) out.push_back("reveals " + rel + ", a credential or database file, to whoever asked");
    }
    // A task whose caller names what gets installed (pip_install, row 32): code from a package index
    // runs as the site's account.
    if (site_path && action == "task" && tasks::needs_user_confirmation(body.get("task")))
        out.push_back("installs the Python packages it names into the site's virtualenv: their code runs as the site's account");
    return out;
}

}  // namespace agensio::control
