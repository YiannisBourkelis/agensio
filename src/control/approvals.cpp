#include "control/approvals.hpp"

#include <algorithm>
#include <cctype>
#include <deque>
#include <filesystem>

#include "core/log_exclude.hpp"
#include "services/dotenv.hpp"
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

std::string escape_line(std::string_view text) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(text.size());
    for (const char ch : text) {
        const auto c = static_cast<unsigned char>(ch);
        if (c >= 0x20 && c < 0x7f && c != '\\') {  // the backslash too: a name spelled "\x0a" stays apart from one with a newline
            out.push_back(ch);
            continue;
        }
        out += "\\x";
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 15]);
    }
    return out;
}

PhpScan scan_php(const std::string& root, bool for_static) {
    namespace fs = std::filesystem;
    PhpScan out;
    std::error_code ec;
    if (root.empty() || !fs::is_directory(fs::path(root), ec)) return out;
    const auto php_name = [for_static](std::string n) {
        for (char& ch : n) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (!for_static) return n.size() > 4 && n.ends_with(".php");
        for (const auto& suffix : php_suffixes())
            if (n.size() > suffix.size() && n.ends_with(suffix)) return true;
        return false;
    };
    const auto config_name = [](std::string n) {
        for (char& ch : n) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        return n.find("config") != std::string::npos || n.find("settings") != std::string::npos;
    };
    // A served path is shown to a person: kept to a line's length (escaped where the reason is made).
    const auto shown = [](std::string p) { return p.size() > 200 ? p.substr(0, 200) + "..." : p; };
    std::string first;
    std::deque<std::pair<fs::path, std::string>> dirs{{fs::path(root), std::string()}};  // a directory and its served path
    std::size_t seen = 0;
    while (!dirs.empty()) {
        const auto [at, served_at] = std::move(dirs.front());
        dirs.pop_front();
        fs::directory_iterator it(at, ec), end;
        if (ec) {
            if (out.unread.empty()) out.unread = shown(served_at.empty() ? "/" : served_at);
            ec.clear();
            continue;
        }
        for (; it != end; it.increment(ec)) {
            if (++seen > PhpScan::kScanEntries) {
                out.capped = true;
                out.found = first;
                return out;
            }
            const std::string n = it->path().filename().string();
            if (for_static && !n.empty() && n[0] == '.') continue;  // a dot name static answers 404, below it too
            const std::string served = served_at + "/" + n;
            std::error_code e2;
            const bool link = it->is_symlink(e2);
            if (it->is_directory(e2)) {  // a link's target
                if (!link) dirs.emplace_back(it->path(), served);
                else if (out.link.empty()) out.link = shown(served);
                continue;
            }
            if (!php_name(n) || !it->is_regular_file(e2)) continue;
            if (!for_static || config_name(n)) {  // breadth first: the shallowest configuration file
                out.found = shown(served);
                return out;
            }
            if (first.empty()) first = shown(served);
        }
        if (ec) {  // a directory that stopped answering midway
            if (out.unread.empty()) out.unread = shown(served_at.empty() ? "/" : served_at);
            ec.clear();
        }
    }
    out.found = first;
    return out;
}

std::vector<std::string> preset_files_served(const SiteSpec& site, const std::string& root) {
    namespace fs = std::filesystem;
    std::vector<std::string> candidates;
    if (python_app(site.app) && !site.project.empty()) candidates.push_back("/" + site.project + "/settings.py");  // its SECRET_KEY: the .py ending
    for (const char* p : preset_refused_paths(site.app)) candidates.emplace_back(p);
    std::string base = root;
    while (base.size() > 1 && base.back() == '/') base.pop_back();
    std::vector<std::string> out;
    for (const auto& p : candidates) {
        if (out.size() == 3 || base.empty()) break;
        if (p.find("/.") != std::string::npos) continue;  // static answers a dot name 404
        std::error_code ec;
        const fs::path at = fs::path(base + (p.ends_with('/') ? p.substr(0, p.size() - 1) : p));
        if (p.ends_with('/') ? fs::is_directory(at, ec) : fs::is_regular_file(at, ec)) out.push_back(p);
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
        case PendingChange::State::skipped: return "skipped";
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
    if (with_result && (c.state == PendingChange::State::done || c.state == PendingChange::State::failed || c.state == PendingChange::State::skipped)) {
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

namespace {

// One line of an env-like file as "NAME=" with what follows the '=' masked; the leading blanks, a
// comment's '#' and "export " kept. False when the line is no assignment, and for a comment whose
// "name" is none of `names`, the file's variables.
bool masked_assignment(std::string_view line, std::string& out, const std::vector<std::string>& names) {
    std::size_t i = 0;
    auto blanks = [&] {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
    };
    blanks();
    bool comment = false;
    if (i < line.size() && line[i] == '#') {
        comment = true;
        ++i;
        blanks();
    }
    if (line.substr(i).starts_with("export ")) {
        i += 7;
        blanks();
    }
    // The name's bytes in ASCII whatever the locale, as dotenv::parse reads them.
    auto letter = [](char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'; };
    const std::size_t name = i;
    if (i >= line.size() || !letter(line[i])) return false;
    while (i < line.size() && (letter(line[i]) || (line[i] >= '0' && line[i] <= '9') || line[i] == '.')) ++i;
    if (i - name > 64) return false;
    // A comment is free text: its "name" is shown only when the file has that variable (# APP_KEY=...
    // beside APP_KEY), never a commented-out key that happens to end in '=' padding, base64 or base32
    // in capitals (the alpha.125 report: #JBSWY3DPEHPK3PXP== showed as #JBSWY3DPEHPK3PXP=<1 bytes>).
    if (comment && std::find(names.begin(), names.end(), line.substr(name, i - name)) == names.end()) return false;
    blanks();
    if (i >= line.size() || line[i] != '=') return false;
    ++i;
    const std::size_t value = line.size() - i;
    out = std::string(line.substr(0, i)) + (value ? "<" + std::to_string(value) + " bytes>" : std::string());
    return true;
}

std::string masked_line(std::string_view line, bool env_like, const std::vector<std::string>& names) {
    if (line.find_first_not_of(" \t\r") == std::string_view::npos) return std::string(line);
    std::string out;
    if (env_like && masked_assignment(line, out, names)) return out;
    if (env_like && line.find_first_not_of(" \t") != std::string_view::npos && line[line.find_first_not_of(" \t")] == '#')
        return "#<" + std::to_string(line.size()) + " bytes>";
    return "<" + std::to_string(line.size()) + " bytes>";
}

}  // namespace

bool env_like_text(std::string_view text) {
    // Read as phpdotenv reads it (services/dotenv): a value over several lines makes the file no
    // env-like one, since a line of that value may look like an assignment, and its "name" would be
    // shown (before 2026-11-04 a base64 line ending in '=' padding was shown that way).
    for (const auto& l : dotenv::parse(text)) {
        if (l.assignment) {
            if (!l.readable) return false;
            continue;
        }
        const std::size_t first = l.raw.find_first_not_of(" \t\r");
        if (first == std::string::npos || l.raw[first] == '#') continue;
        return false;
    }
    return true;
}

std::vector<std::string> env_names(std::string_view text) {
    std::vector<std::string> out;
    for (const auto& l : dotenv::parse(text))
        if (l.assignment && std::find(out.begin(), out.end(), l.name) == out.end()) out.push_back(l.name);
    return out;
}

std::string mask_credential_diff(std::string_view diff, bool env_like, const std::vector<std::string>& names) {
    std::string out;
    std::size_t at = 0;
    while (at < diff.size()) {
        const std::size_t end = std::min(diff.find('\n', at), diff.size());
        const std::string_view line = diff.substr(at, end - at);
        at = end + 1;
        // The diff writer's content lines carry one prefix (' ', '-', '+'); its own lines do not.
        if (!line.empty() && (line[0] == ' ' || line[0] == '-' || line[0] == '+'))
            out += std::string(1, line[0]) + masked_line(line.substr(1), env_like, names) + "\n";
        else
            out += std::string(line) + "\n";
    }
    return out;
}

std::string url_host(std::string_view url) {
    const std::size_t scheme = url.find("://");
    if (scheme == std::string_view::npos) return "";
    std::string_view rest = url.substr(scheme + 3);
    const std::size_t end = rest.find_first_of("/?#");
    std::string_view hp = end == std::string_view::npos ? rest : rest.substr(0, end);
    if (const std::size_t at = hp.rfind('@'); at != std::string_view::npos) hp = hp.substr(at + 1);
    std::string host;
    if (!hp.empty() && hp.front() == '[') {
        const std::size_t close = hp.find(']');
        host = std::string(hp.substr(1, close == std::string_view::npos ? std::string_view::npos : close - 1));
    } else {
        const std::size_t colon = hp.rfind(':');
        host = std::string(colon == std::string_view::npos ? hp : hp.substr(0, colon));
    }
    for (char& c : host) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return host;
}

bool upstream_off_host(std::string_view upstream) {
    if (upstream.starts_with("unix:")) return false;
    const std::string host = url_host(upstream);
    if (host.empty()) return false;  // not a URL this reads: the loader refuses it anyway
    return !(host == "localhost" || host == "::1" || host.starts_with("127."));
}

namespace {

bool has_name(const std::vector<std::string>& names, std::string_view host) {
    for (const auto& n : names) {
        if (n.size() != host.size()) continue;
        bool same = true;
        for (std::size_t i = 0; i < n.size() && same; ++i) same = std::tolower(static_cast<unsigned char>(n[i])) == std::tolower(static_cast<unsigned char>(host[i]));
        if (same) return true;
    }
    return false;
}

std::vector<std::string> strings_of(const json::Value& v) {
    std::vector<std::string> out;
    for (const auto& e : v.items())
        if (e.is_string()) out.push_back(std::string(e.str()));
    return out;
}

bool contains(const std::vector<std::string>& v, const std::string& s) { return std::find(v.begin(), v.end(), s) != v.end(); }

const json::Value* rule_at(const json::Value& list, std::string_view path) {
    for (const auto& r : list.items())
        if (r.get("path") == path) return &r;
    return nullptr;
}

// A site's protections before and after a site_update's `rules`: what the change removes or widens
// (docs/design-site-operations.md 27.2, "granting access"); adding or narrowing is free.
void rules_widened(const json::Value& before, const json::Value& after, std::vector<std::string>& out) {
    for (const auto& old : before["restricted"].items()) {
        const std::string path(old.get("path"));
        const json::Value* now = rule_at(after["restricted"], path);
        if (!now) {
            out.push_back("removes the address rule on " + path + ": every client reaches it");
            continue;
        }
        const std::vector<std::string> was = strings_of(old["allow"]), is = strings_of((*now)["allow"]);
        for (const auto& a : is)
            if (!contains(was, a)) out.push_back("widens the address rule on " + path + " to " + a);
        if (now->get("mode") == "report" && old.get("mode") != "report") out.push_back("turns the address rule on " + path + " to report mode: nothing is refused");
    }
    if (before["admin"].is_object()) {
        const json::Value& old = before["admin"];
        if (!after["admin"].is_object()) {
            out.push_back("removes the admin rule: the administration pages open to every client");
        } else {
            const json::Value& now = after["admin"];
            const std::vector<std::string> was = strings_of(old["allow"]), is = strings_of(now["allow"]);
            for (const auto& a : is)
                if (!contains(was, a)) out.push_back("widens the admin rule to " + a);
            if (now.get("mode") == "report" && old.get("mode") != "report") out.push_back("turns the admin rule to report mode: nothing is refused");
            if (old["login"].boolean() && !now["login"].boolean()) out.push_back("opens the login page the admin rule covered");
        }
    }
    for (const auto& old : before["auth"].items()) {
        const std::string path(old.get("path"));
        if (old["open"].boolean()) continue;
        const json::Value* now = rule_at(after["auth"], path);
        if (!now) {
            out.push_back("removes the password on " + path);
            continue;
        }
        if ((*now)["open"].boolean()) out.push_back("opens " + path + ": no password asked there any more");
        const std::vector<std::string> was = strings_of(old["skip_for"]), is = strings_of((*now)["skip_for"]);
        for (const auto& a : is)
            if (!contains(was, a)) out.push_back("lets " + a + " in without a password on " + path);
        if (now->get("plain_http") == "allow" && old.get("plain_http") != "allow") out.push_back("lets the password on " + path + " be sent over plain HTTP");
    }
    for (const auto& now : after["auth"].items())  // a new open rule inside a protected tree opens it
        if (now["open"].boolean() && !rule_at(before["auth"], now.get("path"))) out.push_back("opens " + std::string(now.get("path")) + " inside the site's password rules");
}

}  // namespace

std::vector<std::string> approval_reasons(std::string_view path, std::string_view action, const json::Value& body, const ApprovalContext& ctx) {
    std::vector<std::string> out;
    const bool site_path = path.starts_with("/v1/sites/");
    // A task whose caller names what gets installed (pip_install, row 32): code from a package index
    // runs as the site's account.
    if (site_path && action == "task" && tasks::needs_user_confirmation(body.get("task")))
        out.push_back("installs the Python packages it names into the site's virtualenv: their code runs as the site's account");
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
        else if (op == "read" && ctx.secret_read) out.push_back("reveals " + rel + ", a credential or database file, to whoever asked");
    }
    // Code and installs: an archive from anywhere, a copy within the site.
    if (site_path && action == "install") {
        const std::string url(body.get("url")), file(body.get("file")), target(body.get("path"));
        out.push_back("installs an application's files into the site" + (target.empty() ? std::string() : " under " + target) + " from " +
                      (!url.empty() ? url : !file.empty() ? "the upload " + file : std::string("its preset's official archive")) + ": whatever they hold, the site then serves or runs them");
    }
    if (site_path && action == "copy")
        out.push_back("copies " + std::string(body.get("from")) + " to " + std::string(body.get("to")) + " within the site: what the site serves, or runs, changes");
    // Secrets leaving, and data sent elsewhere: the site's environment.
    if (site_path && action == "env") {
        if (body["reveal"].is_array() && body["set"].is_null() && body["unset"].is_null() && body["generate"].is_null()) {
            std::string names;
            for (const auto& n : body["reveal"].items()) names += (names.empty() ? "" : ", ") + std::string(n.is_string() ? n.str() : "?");
            out.push_back("reveals the values of " + names + " from the site's environment to whoever asked");
        } else {
            // Each name once: a rotation gives it in unset and generate both (the alpha.125 report's small item).
            std::vector<std::string> listed;
            auto add = [&](std::string n) {
                if (std::find(listed.begin(), listed.end(), n) == listed.end()) listed.push_back(std::move(n));
            };
            for (const auto& [k, v] : body["set"].members()) add(k);
            for (const char* key : {"unset", "generate"})
                for (const auto& n : body[key].items()) add(n.is_string() ? std::string(n.str()) : "?");
            std::string names;
            for (const auto& n : listed) names += (names.empty() ? "" : ", ") + n;
            out.push_back("changes the site's application environment (" + (names.empty() ? std::string("its variables") : names) +
                          "): where the application keeps its data, what it trusts, its secrets");
        }
    }
    // Granting access: a password user.
    if (site_path && action == "auth-users") out.push_back("adds or changes the password user " + std::string(body.get("user")) + " of the site: who may log in");
    // Destroying beyond undo: the trash.
    if (path.starts_with("/v1/trash/") && path.ends_with("/delete"))
        out.push_back("removes the trash entry " + std::string(path.substr(10, path.size() - 10 - 7)) + " for good: nothing brings its files back");
    if (path == "/v1/trash/expire") out.push_back("removes every expired trash entry for good: nothing brings their files back");
    // Making files run, sending visitors or data elsewhere, widening access: a site's fields.
    const bool update = site_path && action.empty(), create = path == "/v1/sites";
    if (update || create) {
        const SiteSpec* cur = ctx.current;
        const auto changed = [&](const char* key, const std::string& was) {
            return body[key].is_string() && (create || !cur || std::string(body[key].str()) != was);
        };
        if (update && changed("app", cur ? cur->app : "")) {
            std::string line = "changes what the site runs: app " + (cur ? cur->app : std::string("?")) + " becomes " + std::string(body["app"].str());
            // From PHP to static (N1): no request-path refusal stands in for this decision, so the person approving
            // reads what it serves.
            if (cur && php_app(cur->app) && body["app"].str() == "static") {
                const std::string root = body["root"].is_string() ? std::string(body["root"].str()) : cur->root;
                // What the walk saw (the alpha.132 report, F1): a file named, or how far it looked; "none" only after a
                // whole walk, a directory the server cannot read included (the alpha.133 report, S1).
                const PhpScan& scan = ctx.root_scan;
                const std::string seen = !scan.found.empty() ? scan.found + " among them"
                                         : scan.capped ? "none in the first " + std::to_string(PhpScan::kScanEntries) + " entries, which is as far as the check reads"
                                         : !scan.link.empty() ? "none outside " + scan.link + ", a link to a directory, which the check does not follow and static does"
                                         : !scan.unread.empty() ? "none outside " + scan.unread + ", which the server cannot read and so cannot serve either"
                                                                : std::string("none is there now; any put there later is served so");
                line += ": static runs no PHP, so every PHP file under " + root + " is served to anyone as its source, with the passwords and keys in it (" + seen +
                        "), and so is every other file the " + cur->app + " preset refuses there (its logs, backups, databases and the like)";
            } else if (cur && body["app"].str() == "static" && !preset_refused_paths(cur->app).empty()) {
                // From an application server (the alpha.132 report, S2): its project directory is served whole.
                const std::string root = body["root"].is_string() ? std::string(body["root"].str()) : cur->root;
                line += ": static serves every file under " + root + " to anyone (hidden ones aside)";
                std::string names;
                for (const auto& p : ctx.preset_served) names += (names.empty() ? "" : ", ") + p;
                if (!names.empty()) line += ", among them what the " + cur->app + " preset refused: " + names;
            }
            out.push_back(std::move(line));
        }
        if (update && changed("root", cur ? cur->root : "")) {
            std::string line = "serves, or runs, files from another directory: " + std::string(body["root"].str());
            // A static site moved onto PHP files (the alpha.132 report, F3b), unless the app's line says it already (N1).
            const std::string app_after = body["app"].is_string() ? std::string(body["app"].str()) : cur ? cur->app : std::string();
            const bool said = cur && php_app(cur->app) && app_after == "static";
            if (app_after == "static" && !said && !ctx.root_scan.found.empty())
                line += ": it holds PHP files, which a static site serves to anyone as their source, with the passwords and keys in them (" + ctx.root_scan.found + " among them)";
            out.push_back(std::move(line));
        }
        if (update && changed("served_dir", cur ? cur->served_dir : "")) {
            // Both directories named whole, "" being the project directory itself (the alpha.133 report, S2).
            const std::string was_root = cur ? cur->root : std::string();
            const std::string root = body["root"].is_string() ? std::string(body["root"].str()) : was_root;
            const auto served = [](const std::string& project, const std::string& dir) {
                return dir.empty() ? "the project directory " + project + " itself" : project + "/" + dir;
            };
            out.push_back("serves, or runs, files from another directory of the project: " + served(root, std::string(body["served_dir"].str())) + ", in place of " +
                          served(was_root, cur ? cur->served_dir : std::string()));
        }
        if (create && body.get("app") == "static") {
            // Over PHP files (the alpha.132 report, F3a, the owner's decision): static serves them as their source. A
            // walk that found none adds nothing: a large static tree or a link in it is no PHP site.
            if (!ctx.root_scan.found.empty())
                out.push_back("the directory " + std::string(body.get("root")) + " holds PHP files, which a static site serves to anyone as their source, with the passwords and keys in them (" +
                              ctx.root_scan.found + " among them)");
        } else if (create) {  // the scan is there for a PHP preset only; one that could not see everything waits too (F1)
            const PhpScan& scan = ctx.root_scan;
            const std::string dir = "the directory " + std::string(body.get("root"));
            if (!scan.found.empty()) out.push_back(dir + " already holds PHP files, which the site would run as soon as it exists (" + scan.found + " among them)");
            else if (scan.capped)
                out.push_back(dir + " may hold PHP files, which the site would run as soon as it exists: it holds more than " + std::to_string(PhpScan::kScanEntries) +
                              " entries, and the check reads only that many");
            else if (!scan.link.empty())
                out.push_back(dir + " may hold PHP files, which the site would run as soon as it exists: " + scan.link + " is a link to a directory, which the check does not follow");
            else if (!scan.unread.empty())
                out.push_back(dir + " may hold PHP files, which the site would run as soon as it exists: the server cannot read " + scan.unread + ", so the check could not look inside");
        }
        if (body["rules"].is_object()) {
            const json::Value& r = ctx.rules_after ? *ctx.rules_after : body["rules"];
            const json::Value& before = cur ? cur->rules : json::Value();
            if (update && (!r["entry_points"].is_null() || !r["front_controller"].is_null()) &&
                (r["entry_points"].dump() != before["entry_points"].dump() || r["front_controller"].dump() != before["front_controller"].dump()))
                out.push_back("changes which PHP files of the site run (entry points, the front controller)");
            if (update && cur) rules_widened(before, r, out);
        }
        if (body["upstream"].is_string()) {
            const std::string up(body["upstream"].str());
            if (update && (!cur || up != cur->upstream)) out.push_back("sends the site's visitors to another application: " + up + (upstream_off_host(up) ? ", off this host" : ""));
            else if (create && upstream_off_host(up)) out.push_back("sends the site's visitors to an application off this host: " + up);
        }
        // Records kept out of the logs, or deleted sooner (docs/configuration.md 8b): the paths a change
        // adds or widens, the days it sets or lowers; removing a path or raising the days is free.
        if (body["access_log_exclude_paths"].is_array()) {
            const std::vector<std::string> was = cur ? cur->access_log_exclude_paths : std::vector<std::string>{};
            for (const auto& e : body["access_log_exclude_paths"].items()) {
                if (!e.is_string()) continue;
                const std::string p(e.str());
                if (std::any_of(was.begin(), was.end(), [&](const std::string& w) { return log_exclude::covers(w, p); })) continue;  // within one it had
                out.push_back("keeps requests under " + p + " out of the site's access log, and their client address out of the error log: what happens there leaves no record");
            }
        }
        if (body["access_log_keep_days"].type() == json::Value::Type::number && body["access_log_keep_days"].num() >= 1) {
            const int days = static_cast<int>(body["access_log_keep_days"].num());
            const int was = cur ? cur->access_log_keep_days : 0;
            if (create || was == 0 || days < was)
                out.push_back("deletes the site's rotated access-log lines older than " + std::to_string(days) + (days == 1 ? " day" : " days") + " (" +
                              (was ? std::to_string(was) + " until now" : std::string("logrotate's 14 until now")) + "): nothing brings them back");
        }
        for (const auto& rule : body["redirects"].items()) {
            const std::string to(rule.get("to"));
            const std::string host = url_host(to);
            if (host.empty() || has_name(ctx.site_names, host)) continue;
            bool had = false;
            if (cur)
                for (const auto& old : cur->redirects.items()) had = had || (old.get("from") == rule.get("from") && old.get("to") == to);
            if (!had) out.push_back("redirects " + std::string(rule.get("from")) + " to another host: " + to);
        }
    }
    // One line each, wherever shown: a reason carries names from the request and from the site's tree (F2).
    for (auto& line : out) line = escape_line(line);
    return out;
}

}  // namespace agensio::control
