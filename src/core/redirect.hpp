// Path redirects (`[[site.redirect]]`, alpha.82, docs/redirects.md 5): exact and whole-segment
// prefix rules matched by the path the client asked for, normalised once and compared
// case-sensitively; the most specific rule decides (the longest `from`, an exact rule before a
// prefix of the same path), never the order they are written in.
//
//   from = "/blog"        to = "/news"                 /blog/2024/x?y=1 -> /news/2024/x?y=1
//   from = "/old/"        to = "/"                     /old/x           -> /x (one '/' at the join)
//   from = "/?p=123"      match = "exact"              /?p=123&utm=x    -> the rule (other parameters ignored)
//   from = "/"            to = "https://new.example"   /a?b             -> https://new.example/a?b
//
// The Location is written here byte by byte: a target of the site stays relative, the remainder
// of the path and the client's query are percent-encoded again, so neither a control character
// nor a backslash ever reaches it, a relative Location never starts with "//" or "/\" (another host
// to a browser), and an absolute one names exactly the host of `to` (fuzz_redirect). Used by the
// dispatcher, the configuration's load checks, the tests and the fuzzer. Allocates only into the
// caller's string.
#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "path.hpp"

namespace agensio::redirect {

inline constexpr std::size_t kMaxRules = 1000;    // per site (docs/redirects.md 6.3)
inline constexpr std::size_t kMaxLength = 2048;   // `from` and `to`
inline constexpr std::size_t kMaxParams = 8;      // query parameters an exact rule names

inline int hex(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// RFC 3986 pchar without '%': what a path segment may hold as it is.
inline bool path_char(unsigned char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
           c == '~' || c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' || c == '*' || c == '+' || c == ',' ||
           c == ';' || c == '=' || c == ':' || c == '@';
}

// A written target's part: pchar, '/', '%XX', and for a query or fragment '?' too.
inline bool valid_part(std::string_view s, bool query) noexcept {
    for (std::size_t i = 0; i < s.size(); ++i) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c == '%') {
            if (i + 2 >= s.size() || hex(s[i + 1]) < 0 || hex(s[i + 2]) < 0) return false;
            i += 2;
        } else if (!path_char(c) && c != '/' && !(query && c == '?')) {
            return false;
        }
    }
    return true;
}

inline void append_escaped(std::string& out, unsigned char c) {
    static constexpr char digits[] = "0123456789ABCDEF";
    out.push_back('%');
    out.push_back(digits[c >> 4]);
    out.push_back(digits[c & 15]);
}

// A decoded path's bytes into a Location's path: pchar and '/' as they are, the rest escaped
// ('%' itself, '?', '#', '\', a space, controls, non-ASCII).
inline void append_path(std::string& out, std::string_view s) {
    for (const char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        if (path_char(c) || c == '/') out.push_back(ch);
        else append_escaped(out, c);
    }
}

// The client's query as it came: what a query may hold kept, a '%' kept when it starts an escape,
// anything else escaped, so no control character, space or '#' reaches the Location raw.
inline void append_query(std::string& out, std::string_view s) {
    for (std::size_t i = 0; i < s.size(); ++i) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (path_char(c) || c == '/' || c == '?') out.push_back(s[i]);
        else if (c == '%' && i + 2 < s.size() && hex(s[i + 1]) >= 0 && hex(s[i + 2]) >= 0) out.push_back('%');
        else append_escaped(out, c);
    }
}

// `raw` (a query part as sent) percent-decoded equals `decoded`; '+' is a '+'.
inline bool decoded_equals(std::string_view raw, std::string_view decoded) noexcept {
    std::size_t j = 0;
    for (std::size_t i = 0; i < raw.size(); ++i, ++j) {
        char c = raw[i];
        if (c == '%' && i + 2 < raw.size() && hex(raw[i + 1]) >= 0 && hex(raw[i + 2]) >= 0) {
            c = static_cast<char>(hex(raw[i + 1]) * 16 + hex(raw[i + 2]));
            i += 2;
        }
        if (j >= decoded.size() || decoded[j] != c) return false;
    }
    return j == decoded.size();
}

inline bool decode(std::string_view in, std::string& out) {
    out.clear();
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '%') {
            out.push_back(in[i]);
            continue;
        }
        if (i + 2 >= in.size() || hex(in[i + 1]) < 0 || hex(in[i + 2]) < 0) return false;
        out.push_back(static_cast<char>(hex(in[i + 1]) * 16 + hex(in[i + 2])));
        i += 2;
    }
    return true;
}

// `from` as written: a normalised path, as a browser's request decodes to, and for an exact rule
// the query parameters it requires ("/index.php?page=about"). "" when it compiles, else why not.
inline std::string compile_from(std::string_view text, bool exact, RedirectRule& r) {
    if (text.empty() || text.front() != '/') return "from must be a path starting with '/' (\"/old-page\")";
    if (text.size() > kMaxLength) return "from is longer than " + std::to_string(kMaxLength) + " bytes";
    if (text.find('#') != std::string_view::npos) return "from cannot name a fragment (#...): browsers never send it";
    const std::size_t q = text.find('?');
    const std::string_view path = text.substr(0, q);
    std::string norm;
    if (!normalize_target(path, norm) || norm != path)
        return "from must be a normalised path, written as it decodes: no '.', '..' or '//' segments and no %-escapes" +
               std::string(norm.empty() || norm == path ? "" : " (\"" + norm + "\")");
    r.text = std::string(text);
    r.from = std::move(norm);
    r.exact = exact;
    if (q == std::string_view::npos) return "";
    if (!exact) return "only an exact rule (match = \"exact\") can name query parameters";
    std::string_view rest = text.substr(q + 1);
    if (rest.empty()) return "from ends with '?' and names no query parameter";
    while (!rest.empty()) {
        const std::size_t amp = rest.find('&');
        const std::string_view pair = rest.substr(0, amp);
        rest = amp == std::string_view::npos ? std::string_view() : rest.substr(amp + 1);
        const std::size_t eq = pair.find('=');
        std::string name, value;
        if (!decode(pair.substr(0, eq), name) || name.empty() || (eq != std::string_view::npos && !decode(pair.substr(eq + 1), value)))
            return "from's query parameter '" + std::string(pair) + "' is not name=value with valid %-escapes";
        for (const auto& p : r.params)
            if (p.first == name) return "from names the query parameter '" + name + "' twice";
        r.params.emplace_back(std::move(name), std::move(value));
        if (r.params.size() > kMaxParams) return "from names more than " + std::to_string(kMaxParams) + " query parameters";
    }
    return "";
}

// `to` as written: a path of this site ("/news", "/support?tab=faq#contact") or an http(s) URL
// ("https://docs.example.com/x"), every byte already valid in a URI.
inline std::string compile_to(std::string_view text, RedirectRule& r) {
    if (text.size() > kMaxLength) return "to is longer than " + std::to_string(kMaxLength) + " bytes";
    for (const char ch : text) {
        const auto c = static_cast<unsigned char>(ch);
        if (c <= 0x20 || c >= 0x7f || c == '\\')
            return "to holds a space, a control character, a backslash or a byte beyond ASCII: percent-encode it (%20, %C3%A9)";
    }
    r.to = std::string(text);
    std::string_view rest = text;
    const bool https = text.starts_with("https://"), http = text.starts_with("http://");
    if (https || http) {
        rest.remove_prefix(https ? 8 : 7);
        const std::size_t end = std::min(rest.find_first_of("/?#"), rest.size());
        const std::string_view authority = rest.substr(0, end);
        if (authority.empty()) return "to names no host after " + std::string(https ? "https://" : "http://");
        if (authority.find('@') != std::string_view::npos) return "to cannot carry a user name or password (user@host)";
        std::string_view host = authority, port;
        if (host.front() == '[') {
            const std::size_t close = host.find(']');
            if (close == std::string_view::npos) return "to's host has an unclosed '['";
            port = host.substr(close + 1);
            host = host.substr(0, close + 1);
            if (!port.empty() && port.front() != ':') return "to's host is followed by '" + std::string(port) + "'";
            if (!port.empty()) port.remove_prefix(1);
            if (host.find_first_not_of("[]0123456789abcdefABCDEF:.") != std::string_view::npos) return "to's IPv6 host is not one";
        } else {
            if (const std::size_t colon = host.find(':'); colon != std::string_view::npos) {
                port = host.substr(colon + 1);
                host = host.substr(0, colon);
            }
            if (host.empty() || host.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") != std::string_view::npos)
                return "to's host '" + std::string(host) + "' is not a host name";
        }
        if (!port.empty() && (port.size() > 5 || port.find_first_not_of("0123456789") != std::string_view::npos))
            return "to's port '" + std::string(port) + "' is not a number";
        r.origin.assign(https ? "https://" : "http://");
        for (const char c : authority) r.origin.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c);
        rest.remove_prefix(end);
    } else if (text.find("://") != std::string_view::npos || !text.starts_with("/")) {
        return "to must be a path of this site (\"/new\") or an http:// or https:// URL";
    } else if (text.starts_with("//")) {
        return "to cannot start with \"//\": browsers read it as another host";
    }
    const std::size_t hash = rest.find('#');
    const std::string_view before = rest.substr(0, hash);
    if (hash != std::string_view::npos) r.to_fragment = std::string(rest.substr(hash + 1));
    const std::size_t q = before.find('?');
    r.to_path = std::string(before.substr(0, q));
    if (q != std::string_view::npos) r.to_query = std::string(before.substr(q + 1));
    if (!valid_part(r.to_path, false) || !valid_part(r.to_query, true) || !valid_part(r.to_fragment, true))
        return "to holds a byte a URL cannot carry as it is, or a broken %-escape: percent-encode it";
    const std::string_view p = r.to_path;
    if (p == "." || p == ".." || p.find("/./") != std::string_view::npos || p.find("/../") != std::string_view::npos || p.ends_with("/.") ||
        p.ends_with("/.."))
        return "to's path has '.' or '..' segments: write the path they lead to";
    return "";
}

inline bool covers(const RedirectRule& r, std::string_view path) noexcept {
    if (!path.starts_with(r.from)) return false;
    return r.from.back() == '/' || path.size() == r.from.size() || path[r.from.size()] == '/';
}

// Every parameter the rule names is in the query (as sent) with that value, in any order.
inline bool params_match(const RedirectRule& r, std::string_view query) noexcept {
    for (const auto& [name, value] : r.params) {
        bool found = false;
        std::string_view rest = query;
        while (!found && !rest.empty()) {
            const std::size_t amp = rest.find('&');
            const std::string_view pair = rest.substr(0, amp);
            rest = amp == std::string_view::npos ? std::string_view() : rest.substr(amp + 1);
            const std::size_t eq = pair.find('=');
            found = decoded_equals(pair.substr(0, eq), name) && decoded_equals(eq == std::string_view::npos ? std::string_view() : pair.substr(eq + 1), value);
        }
        if (!found) return false;
    }
    return true;
}

// After the rules are in: the lookup tables. The exact rules of one path with the most parameters
// first (the most specific), then by their text, so the choice never depends on the file's order.
inline void index(RedirectSet& set) {
    set.exact.clear();
    set.prefixes.clear();
    set.first = {};
    set.root_prefix = false;
    for (std::size_t i = 0; i < set.rules.size(); ++i) {
        const RedirectRule& r = set.rules[i];
        if (r.exact) {
            set.exact[r.from].push_back(static_cast<std::uint16_t>(i));
        } else {
            set.prefixes.push_back(static_cast<std::uint16_t>(i));
            if (r.from == "/") set.root_prefix = true;
            else set.first[static_cast<unsigned char>(r.from[1]) >> 6] |= std::uint64_t{1} << (static_cast<unsigned char>(r.from[1]) & 63);
        }
    }
    for (auto& [path, list] : set.exact)
        std::sort(list.begin(), list.end(), [&](std::uint16_t a, std::uint16_t b) {
            const RedirectRule &x = set.rules[a], &y = set.rules[b];
            return x.params.size() != y.params.size() ? x.params.size() > y.params.size() : x.text < y.text;
        });
    std::stable_sort(set.prefixes.begin(), set.prefixes.end(),
                     [&](std::uint16_t a, std::uint16_t b) { return set.rules[a].from.size() > set.rules[b].from.size(); });
}

// The deciding rule for a request, or null: `path` normalised (the worker's), `query` the target's
// after '?', as sent. A prefix rule never takes a path that spelled a separator as an escape (%2F):
// its remainder would carry a '/' the client did not write as one.
inline const RedirectRule* match(const RedirectSet& set, std::string_view path, std::string_view query, bool encoded_separator) noexcept {
    if (!set.exact.empty())
        if (const auto it = set.exact.find(path); it != set.exact.end())
            for (const std::uint16_t i : it->second)
                if (params_match(set.rules[i], query)) return &set.rules[i];
    if (set.prefixes.empty() || encoded_separator) return nullptr;
    if (!set.root_prefix) {
        if (path.size() < 2) return nullptr;
        const auto b = static_cast<unsigned char>(path[1]);
        if (!(set.first[b >> 6] & (std::uint64_t{1} << (b & 63)))) return nullptr;
    }
    for (const std::uint16_t i : set.prefixes)
        if (covers(set.rules[i], path)) return &set.rules[i];
    return nullptr;
}

// The Location of rule `r` for `path` (normalised, which the rule covers) and `query` (as sent):
// into `out`, cleared first. `origin` is put before a target of the site ("https://example.com"
// when a plain request is redirected in one hop with the scheme), "" for a relative Location.
inline void write_location(std::string& out, const RedirectRule& r, std::string_view path, std::string_view query, std::string_view origin) {
    out.clear();
    out.append(r.origin.empty() ? origin : std::string_view(r.origin));
    const std::size_t at = out.size();
    out.append(r.to_path);
    if (!r.exact && r.keep_remainder && path.size() > r.from.size()) {
        std::string_view rest = path.substr(r.from.size());
        const bool slash = out.size() > at && out.back() == '/';
        if (slash && rest.front() == '/') rest.remove_prefix(1);
        else if (!slash && rest.front() != '/') out.push_back('/');
        append_path(out, rest);
    }
    if (out.size() == at) out.push_back('/');  // "https://new.example" alone
    bool asked = false;
    if (!r.to_query.empty()) {
        out.push_back('?');
        out.append(r.to_query);
        asked = true;
    }
    if (r.keep_query && !query.empty()) {
        out.push_back(asked ? '&' : '?');
        append_query(out, query);
    }
    if (!r.to_fragment.empty()) {
        out.push_back('#');
        out.append(r.to_fragment);
    }
}

// The query of a request target, "" without one.
inline std::string_view query_of(std::string_view target) noexcept {
    const std::size_t q = target.find('?');
    return q == std::string_view::npos ? std::string_view() : target.substr(q + 1);
}

// The Location of a directory asked for without its slash (the static handler's 301; the review of
// 2026-10-14, D5): the decoded, normalised path encoded again with its slash, then the client's
// query, as every other redirect writes them; nginx escapes there since 1.21.0 and keeps the query,
// as Apache, Caddy and h2o do. Relative, and never "//" or "/\" at the start: the path is normalised
// and a backslash is escaped (before, a directory named "\evil.example" gave "/\evil.example/",
// another host to a browser).
inline void directory_location(std::string& out, std::string_view path, std::string_view query) {
    out.clear();
    append_path(out, path);
    out.push_back('/');
    if (!query.empty()) {
        out.push_back('?');
        append_query(out, query);
    }
}

// The target as a path of this site (decoded) and its query, for the load checks that follow a
// rule's target through the other rules; false for a target on another host.
inline bool target_on_site(const RedirectRule& r, const std::vector<std::string>& names, std::string& path, std::string& query) {
    if (r.status == 410) return false;
    if (!r.origin.empty()) {
        std::string_view host = std::string_view(r.origin).substr(r.origin.starts_with("https://") ? 8 : 7);
        if (const std::size_t colon = host.rfind(':'); colon != std::string_view::npos && host.find(']') == std::string_view::npos) host = host.substr(0, colon);
        if (std::find(names.begin(), names.end(), host) == names.end()) return false;
    }
    if (!decode(r.to_path.empty() ? std::string_view("/") : std::string_view(r.to_path), path)) return false;
    query = r.to_query;
    return true;
}

}  // namespace agensio::redirect
