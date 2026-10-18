// libFuzzer target for [[site.response_headers]] (core/response_rules.hpp, core/response_fields.hpp,
// docs/headers.md 2): the input is rules, one per line (path, flags, verb, name, value, endings,
// separated by tabs; flags 'e' exact, 's' success only), up to an empty line, then probes (path,
// status, served file, flags, then the answer's own fields as name:value separated by tabs; flags
// 'p' behind a password, 'o' the fields sit in agensio's own block, 'u' an application's answer,
// 'a' the request carried Authorization).
// The rules load as path_check's preview loads them (the parse, checks and resolution of a site
// file); for each probe the node is the one a request finds and the fields are applied as the
// writers and the upstream loop apply them. Whatever the input:
//   - no value a rule sends holds a byte outside printable ASCII, and no rule sends a field the
//     server owns (framing, representation, Location, HSTS, Server, cookies, the password fields);
//   - set leaves exactly one copy, remove none, default adds one only where the answer had none,
//     and a field no decision names passes unchanged, in order;
//   - the guards stand: behind a password the cache fields are untouched, a field of agensio's own
//     block is never replaced, removed or doubled;
//   - HTTP/1's prebuilt lines equal what the general path writes for an answer with nothing to look at;
//   - an application's answer keeps the restrictions of its Cache-Control (no-store, private,
//     no-cache) and of each field only shared caches read, whatever a rule sets or removes; a
//     rule's CDN field or Expires never comes over a restriction in any of its CDN fields (or, for
//     one it lacks and for Expires, in its Cache-Control); and one that is one user's (Set-Cookie,
//     Vary naming Cookie or Authorization or "*", a request with Authorization) gets no line from
//     a rule that lets a shared cache keep it (docs/headers.md 2.4);
//   - the node's decisions agree with a scan of every rule for the most specific one naming a field,
//     the security baseline's (docs/headers.md 4: the site is php, static or without app by the
//     input's length) below the written ones at its path, its nosniff leaving an application's
//     answer as it was.
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "core/private_cache.hpp"
#include "core/response_fields.hpp"
#include "path.hpp"
#include "services/json.hpp"

namespace {

using agensio::FieldDecision;
using agensio::HeaderRule;
using agensio::HeaderSet;
using agensio::Headers;

std::vector<std::string_view> split(std::string_view s, char sep) {
    std::vector<std::string_view> out;
    std::size_t from = 0;
    while (true) {
        const std::size_t at = s.find(sep, from);
        out.push_back(s.substr(from, at == std::string_view::npos ? std::string_view::npos : at - from));
        if (at == std::string_view::npos) break;
        from = at + 1;
    }
    return out;
}

std::string lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = static_cast<char>((c >= 'A' && c <= 'Z') ? c + 32 : c);
    return out;
}

// docs/headers.md 2.5: the fields no rule may send (set or default).
bool owned(std::string_view name) {
    static const char* const kOwned[] = {"connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
                                         "content-length", "content-range", "content-type", "content-encoding", "etag", "last-modified",
                                         "accept-ranges", "age", "date", "vary", "location", "refresh", "strict-transport-security", "server",
                                         "alt-svc", "set-cookie", "clear-site-data", "service-worker-allowed", "www-authenticate",
                                         "proxy-authenticate", "authentication-info", "expect-ct", "public-key-pins", "public-key-pins-report-only"};
    const std::string l = lower(name);
    for (const char* o : kOwned)
        if (l == o) return true;
    return false;
}

void check_decisions(const HeaderSet& hs) {
    for (const FieldDecision& d : hs.fields) {
        assert(!d.name.empty() && d.name.size() <= 128);
        for (const char ch : d.name) {
            const auto c = static_cast<unsigned char>(ch);
            assert(c > 0x20 && c < 0x7f && c != ':');
        }
        if (d.verb != FieldDecision::Verb::remove) {
            assert(!owned(d.name));
            assert(!d.value.empty() && d.value.size() <= 4096 && d.value.front() != ' ' && d.value.back() != ' ');
            for (const char ch : d.value) {
                const auto c = static_cast<unsigned char>(ch);
                assert(c >= 0x20 && c < 0x7f && c != '$');
            }
        }
    }
    // One decision per field name.
    for (std::size_t i = 0; i < hs.fields.size(); ++i)
        for (std::size_t j = i + 1; j < hs.fields.size(); ++j) assert(!Headers::iequals(hs.fields[i].name, hs.fields[j].name));
}

// The most specific rule naming `name` that applies to an answer of this kind and file, by a scan.
const HeaderRule* scan(const std::vector<HeaderRule>& rules, std::string_view path, bool success, std::string_view file, std::string_view name,
                       FieldDecision::Verb& verb, std::string& value) {
    const HeaderRule* best = nullptr;
    bool best_ending = false;
    const std::string file_l = lower(file.substr(file.rfind('/') == std::string_view::npos ? 0 : file.rfind('/') + 1));
    for (const HeaderRule& r : rules) {
        if (!agensio::response_rules::covers(r.path, r.exact, path) || (!success && r.success_only)) continue;
        bool names = false;
        FieldDecision::Verb v{};
        std::string val;
        for (const auto& [n, x] : r.set) if (Headers::iequals(n, name)) { names = true; v = FieldDecision::Verb::set; val = x; }
        for (const auto& [n, x] : r.fallback) if (Headers::iequals(n, name)) { names = true; v = FieldDecision::Verb::fallback; val = x; }
        for (const auto& n : r.remove) if (Headers::iequals(n, name)) { names = true; v = FieldDecision::Verb::remove; val.clear(); }
        if (!names) continue;
        const bool ending = !r.endings.empty();
        if (ending) {
            bool has = false;
            for (const auto& e : r.endings)
                has = has || (file_l.size() > e.size() + 1 && file_l.compare(file_l.size() - e.size() - 1, std::string::npos, "." + e) == 0);
            if (file.empty() || !has) continue;
        }
        // Longer path, then exact before prefix, then (one path and match) a written rule before the
        // security baseline's, then a rule whose endings the file has.
        const bool same_place = best && r.path.size() == best->path.size() && r.exact == best->exact;
        const bool better = !best || r.path.size() > best->path.size() || (r.path.size() == best->path.size() && r.exact && !best->exact) ||
                            (same_place && !r.baseline && best->baseline) || (same_place && r.baseline == best->baseline && ending && !best_ending);
        if (!better) continue;
        best = &r;
        best_ending = ending;
        verb = v;
        value = val;
    }
    return best;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 16384) return 0;
    const std::string_view in(reinterpret_cast<const char*>(data), size);
    const std::size_t blank = in.find("\n\n");
    const std::string_view rule_text = in.substr(0, blank);
    const std::string_view probe_text = blank == std::string_view::npos ? std::string_view() : in.substr(blank + 2);

    agensio::json::Value rules = agensio::json::Value::array();
    std::size_t count = 0;
    for (const std::string_view line : split(rule_text, '\n')) {
        if (line.empty() || ++count > 70) continue;
        const auto f = split(line, '\t');
        agensio::json::Value r = agensio::json::Value::object().set("path", std::string(f[0]));
        const std::string_view flags = f.size() > 1 ? f[1] : std::string_view();
        if (flags.find('e') != std::string_view::npos) r.set("match", "exact");
        if (flags.find('s') != std::string_view::npos) r.set("when", "success");
        const std::string_view verb = f.size() > 2 ? f[2] : std::string_view("set");
        const std::string name(f.size() > 3 ? f[3] : std::string_view("X-A"));
        const std::string value(f.size() > 4 ? f[4] : std::string_view("1"));
        if (verb == "remove") r.set("remove", agensio::json::Value::array().push(name));
        else r.set(verb == "default" ? "default" : "set", agensio::json::Value::object().set(name, value));
        if (f.size() > 5 && !f[5].empty()) {
            agensio::json::Value endings = agensio::json::Value::array();
            for (const std::string_view e : split(f[5], ',')) endings.push(std::string(e));
            r.set("endings", std::move(endings));
        }
        rules.push(std::move(r));
    }
    agensio::SiteConfig site;
    site.server_names = {"f.test"};
    site.app = size % 3 == 0 ? "php" : size % 3 == 1 ? "static" : "";  // the first two with the security baseline
    if (!agensio::load_response_header_rules(rules, site).empty()) return 0;  // refused, as a load would
    const agensio::ResponseRules& rr = site.response_headers;
    for (const auto& n : rr.nodes) {
        check_decisions(n.success);
        check_decisions(n.other);
        for (const auto& e : n.by_ending) {
            check_decisions(e.success);
            check_decisions(e.other);
        }
    }

    std::size_t probes = 0;
    for (const std::string_view line : split(probe_text, '\n')) {
        if (line.empty() || ++probes > 16) continue;
        const auto f = split(line, '\t');
        std::string path;
        bool encoded = false;
        if (f[0].empty() || f[0].front() != '/' || !agensio::normalize_target(f[0], path, &encoded)) continue;
        const int status = f.size() > 1 && !f[1].empty() ? static_cast<int>(static_cast<unsigned char>(f[1][0])) + 100 : 200;
        const std::string_view file = f.size() > 2 ? f[2] : std::string_view();
        const std::string_view flags = f.size() > 3 ? f[3] : std::string_view();
        const bool guarded = flags.find('p') != std::string_view::npos, own = flags.find('o') != std::string_view::npos,
                   upstream = flags.find('u') != std::string_view::npos, credentials = flags.find('a') != std::string_view::npos;
        std::vector<std::pair<std::string, std::string>> fields;  // the answer's own, names as tokens
        for (std::size_t i = 4; i < f.size() && fields.size() < 24; ++i) {
            const std::size_t colon = f[i].find(':');
            if (colon == std::string_view::npos || colon == 0) continue;
            fields.emplace_back(std::string(f[i].substr(0, colon)), std::string(f[i].substr(colon + 1)));
        }

        agensio::Stream s;
        s.header_node = rr.lookup(path);
        if (!file.empty()) agensio::response_fields::served_file(s, file);
        s.response.status = status;
        s.auth.protected_path = guarded;
        const bool success = agensio::response_fields::success(status);

        // The node's decisions agree with the most specific rule naming each field, by a scan.
        if (s.header_node) {
            const HeaderSet& hs = s.header_ending ? (success ? s.header_ending->success : s.header_ending->other)
                                                  : (success ? s.header_node->success : s.header_node->other);
            std::vector<std::string> named;
            for (const auto& r : rr.rules) {
                for (const auto& [n, _] : r.set) named.push_back(n);
                for (const auto& [n, _] : r.fallback) named.push_back(n);
                for (const auto& n : r.remove) named.push_back(n);
            }
            for (const auto& n : named) {
                FieldDecision::Verb verb{};
                std::string value;
                const HeaderRule* best = scan(rr.rules, path, success, s.header_ending ? file : std::string_view(), n, verb, value);
                const int i = agensio::response_fields::find(hs, n);
                assert((best == nullptr) == (i < 0));
                if (best) assert(hs.fields[static_cast<std::size_t>(i)].verb == verb && hs.fields[static_cast<std::size_t>(i)].value == value);
            }
        } else {
            for (const auto& r : rr.rules) assert(!agensio::response_rules::covers(r.path, r.exact, path));
        }

        // What goes out, by name: the answer's own fields, then the rules'.
        std::vector<std::pair<std::string, std::string>> out;
        const HeaderSet* hs = nullptr;
        agensio::response_fields::Upstream seen;
        std::size_t from_rules = 0;                         // out[from_rules...] are the rules' lines
        std::size_t added_private = std::string::npos;      // the Cache-Control: private one user's answer got
        if (upstream) {
            hs = s.header_node && status >= 200 ? (success ? &s.header_node->success : &s.header_node->other) : nullptr;
            if (hs && hs->empty()) hs = nullptr;
            if (hs && hs->cache_watch && !guarded) {
                for (const auto& [n, v] : fields) agensio::response_fields::note_cache(*hs, n, v, seen);
                seen.personal = seen.personal || credentials;
                agensio::response_fields::settle(*hs, seen);
            }
            std::string block;
            for (const auto& [n, v] : fields)
                if (!hs || agensio::response_fields::keep_upstream(*hs, n, guarded, seen)) out.emplace_back(n, v);
            from_rules = out.size();
            if (hs) {
                agensio::response_fields::append_upstream(block, *hs, guarded, seen);
                for (const std::string_view l : split(block, '\n')) {
                    if (l.empty()) continue;
                    assert(l.back() == '\r');
                    const std::size_t colon = l.find(": ");
                    assert(colon != std::string_view::npos);
                    out.emplace_back(std::string(l.substr(0, colon)), std::string(l.substr(colon + 2, l.size() - colon - 3)));
                    // A Cache-Control line no rule wrote: none names it, or one removes it.
                    const int cc = agensio::response_fields::find(*hs, "cache-control");
                    if (Headers::iequals(out.back().first, "cache-control") &&
                        (cc < 0 || hs->fields[static_cast<std::size_t>(cc)].verb == FieldDecision::Verb::remove)) {
                        assert(out.back().second == "private" && seen.personal && added_private == std::string::npos);
                        added_private = out.size() - 1;
                    }
                }
            }
        } else {
            std::string own_block;
            if (own) {
                for (const auto& [n, v] : fields) own_block.append(n).append(": ").append(v).append("\r\n");
                s.response.scratch = own_block;
                s.response.prebuilt_headers = s.response.scratch;
                s.response.own_fields = true;
            } else {
                for (const auto& [n, v] : fields) s.response.headers.add(n, v);
            }
            hs = agensio::response_fields::pending(s);
            if (own) out = fields;  // the block goes out as it is
            if (hs) {
                std::string general;
                agensio::response_fields::apply(s, *hs, [&](std::string_view n, std::string_view v) {
                    out.emplace_back(std::string(n), std::string(v));
                    general.append(n).append(": ").append(v).append("\r\n");
                });
                if (agensio::response_fields::plain(s)) assert(general == hs->h1);  // HTTP/1's borrowed lines
            } else if (!own) {
                out = fields;
            }
        }

        // Each decision did what its verb says, the guards standing.
        auto copies = [&](const std::vector<std::pair<std::string, std::string>>& list, std::string_view name) {
            std::size_t c = 0;
            for (const auto& [n, _] : list) c += Headers::iequals(n, name) ? 1 : 0;
            return c;
        };
        if (hs)
            for (std::size_t i = 0; i < hs->fields.size(); ++i) {
                const FieldDecision& d = hs->fields[i];
                const std::size_t before = copies(fields, d.name),
                                  after = copies(out, d.name) - (added_private != std::string::npos && d.cache_control ? 1 : 0);
                // A decision for agensio's own answers (the baseline's nosniff) leaves an application's
                // field as it is, and so does a cache decision that gives way to its restrictions.
                const bool standing = (!upstream && own && before > 0) || (guarded && d.cache_field) || (upstream && d.own_only) ||
                                      (upstream && (seen.stands & agensio::response_fields::bit(i)));
                if (standing) {
                    assert(after == before);
                    continue;
                }
                // One user's answer: a lifetime the rules give shared caches is left out, or for
                // Cache-Control sent private.
                if (upstream && seen.personal && d.lifetime && !d.cache_control && d.verb != FieldDecision::Verb::remove) {
                    assert(after == (d.verb == FieldDecision::Verb::set ? 0 : before));
                    continue;
                }
                if (d.verb == FieldDecision::Verb::set) assert(after == 1);
                if (d.verb == FieldDecision::Verb::remove) assert(after == 0);
                if (d.verb == FieldDecision::Verb::fallback) assert(after == (before > 0 ? before : 1));
            }
        // A field no decision names passes through unchanged, in order.
        std::vector<std::pair<std::string, std::string>> kept_in, kept_out;
        for (const auto& fv : fields)
            if (!hs || agensio::response_fields::find(*hs, fv.first) < 0) kept_in.push_back(fv);
        for (std::size_t i = 0; i < out.size(); ++i)
            if ((!hs || agensio::response_fields::find(*hs, out[i].first) < 0) && i != added_private) kept_out.push_back(out[i]);
        assert(kept_in == kept_out);

        // What an application's answer says to caches (docs/headers.md 2.4): the restrictions of its
        // Cache-Control and of each field only shared caches read stand (a field it lacks answers to
        // its Cache-Control's, which a CDN would otherwise follow), and one user's answer gets no
        // rule's line letting a shared cache keep it.
        if (upstream && !guarded) {
            using namespace agensio::private_cache;
            auto bits = [&](const std::vector<std::pair<std::string, std::string>>& list, std::string_view name, bool& any) {
                std::uint8_t b = 0;
                any = false;
                for (const auto& [n, v] : list)
                    if (Headers::iequals(n, name)) {
                        b |= restrictions(v, true);
                        any = true;
                    }
                return b;
            };
            bool app_cc = false, out_cc = false;
            const std::uint8_t app_bits = bits(fields, "cache-control", app_cc), out_bits = bits(out, "cache-control", out_cc);
            assert(covers(out_bits, app_bits));
            for (const auto& [n, _] : out)
                if (shared_only_field(n)) {
                    bool app_has = false, out_has = false;
                    const std::uint8_t app_field = bits(fields, n, app_has), out_field = bits(out, n, out_has);
                    assert(covers(out_field, app_has ? app_field : app_bits));
                }
            // A rule's CDN field or Expires never over a restriction in any of the application's CDN
            // fields or, for a CDN field it lacks and for Expires, its Cache-Control (the alpha.99 report).
            std::uint8_t cdn = 0;
            for (const auto& [n, v] : fields)
                if (shared_only_field(n)) cdn |= restrictions(v, true);
            for (std::size_t i = from_rules; i < out.size(); ++i) {
                const auto& [n, v] = out[i];
                if (shared_only_field(n)) {
                    bool app_has = false;
                    (void)bits(fields, n, app_has);
                    assert(covers(restrictions(v, true), static_cast<std::uint8_t>(cdn | (app_has ? 0 : app_bits))));
                }
                if (Headers::iequals(n, "expires")) assert((app_bits | cdn) == 0);
            }
            // One user's answer: it sets a cookie, varies on Cookie or Authorization (or is Vary: *),
            // or answers a request with Authorization.
            bool cookie = credentials;
            for (const auto& [n, v] : fields) {
                cookie = cookie || Headers::iequals(n, "set-cookie");
                if (Headers::iequals(n, "vary"))
                    for_each_directive(v, [&](std::string_view m) {
                        cookie = cookie || m == "*" || Headers::iequals(m, "cookie") || Headers::iequals(m, "authorization");
                    });
            }
            if (cookie)
                for (std::size_t i = from_rules; i < out.size(); ++i) {
                    const auto& [n, v] = out[i];
                    if (Headers::iequals(n, "cache-control")) assert(!shared_lifetime(v));
                    if (shared_only_field(n)) assert(restrictions(v, false) != 0);
                    if (Headers::iequals(n, "expires")) assert(v == "0");
                }
        }
    }
    return 0;
}
