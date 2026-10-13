// [[site.response_headers]] (docs/headers.md 2, alpha.89): the fields a site sets, defaults or
// removes by path, resolved per field when the configuration loads. For each field the most
// specific rule naming it decides (the longest path; at one path an exact rule before a prefix);
// rules naming different fields all apply, and the order they are written in never matters. The
// result is one node per rule path, each with what a successful answer (2xx, 304) and any other
// answer get, so a request finds its node once, when its site is known, and the writers and the
// upstream loop apply it (core/response_fields.hpp). A site without rules has no nodes and pays
// one test of an empty vector.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace agensio {

// One rule as written, kept for -t --explain and the control plane.
struct HeaderRule {
    std::string path;  // normalised; a prefix without its trailing '/' ("/" stays)
    bool exact = false;
    bool success_only = false;  // when = "success"
    std::vector<std::pair<std::string, std::string>> set, fallback;  // fallback: the `default` table
    std::vector<std::string> remove;
};

// One field's decision for the answers of a node.
struct FieldDecision {
    enum class Verb : std::uint8_t { set, fallback, remove };
    std::string name;   // as written (HTTP/2 and HTTP/3 send it in lower case)
    std::string value;  // set and default; empty for remove
    Verb verb = Verb::set;
    bool cache_field = false;  // Cache-Control or a field only shared caches read: the password guard decides those
    std::uint16_t rule = 0;    // the deciding rule, an index into ResponseRules::rules (a copy of the site keeps it)
};

// What one kind of answer gets at a node: one decision per field name (at most 64), and the set
// and default lines as HTTP/1 text, sent as they are when the answer has nothing for the rules to
// look at (a cached file: HTTP/1's borrowed block stays borrowed).
struct HeaderSet {
    std::vector<FieldDecision> fields;
    std::string h1;
    bool empty() const noexcept { return fields.empty(); }
};

struct HeaderNode {
    std::string path;  // as HeaderRule::path
    bool exact = false;
    HeaderSet success, other;  // 2xx and 304; every other answer (when = "always" rules only)
};

namespace response_rules {

inline bool iequal_prefix(std::string_view path, std::string_view prefix) noexcept {
    if (path.size() < prefix.size()) return false;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        unsigned char a = static_cast<unsigned char>(path[i]), b = static_cast<unsigned char>(prefix[i]);
        if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + 32);
        if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b + 32);
        if (a != b) return false;
    }
    return true;
}

// As the access rules: a prefix covers its path and everything below it on a segment boundary, in
// any capitalisation ("/admin": /admin, /Admin/ and /admin/x, never /administrator); "/" covers the
// whole site; an exact rule its path alone.
inline bool covers(std::string_view rule_path, bool exact, std::string_view path) noexcept {
    if (exact) return path.size() == rule_path.size() && iequal_prefix(path, rule_path);
    if (rule_path.size() == 1) return true;
    return iequal_prefix(path, rule_path) && (path.size() == rule_path.size() || path[rule_path.size()] == '/');
}

inline unsigned char first_byte(std::string_view path) noexcept {
    if (path.size() < 2) return 0;
    unsigned char c = static_cast<unsigned char>(path[1]);
    if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c + 32);
    return c;
}

}  // namespace response_rules

struct ResponseRules {
    std::vector<HeaderRule> rules;  // as written
    std::vector<HeaderNode> nodes;  // longest path first, an exact node before the prefix one of its path; "/" last
    std::array<std::uint64_t, 4> first{};  // the first byte after '/' of every node path but "/"
    bool empty() const noexcept { return nodes.empty(); }

    // The node deciding `path` (normalised), or null when no rule covers it.
    const HeaderNode* lookup(std::string_view path) const noexcept {
        if (nodes.empty()) return nullptr;
        const unsigned char c = response_rules::first_byte(path);
        if (((first[c >> 6] >> (c & 63)) & 1u) != 0)
            for (const HeaderNode& n : nodes)
                if (response_rules::covers(n.path, n.exact, path)) return &n;
        const HeaderNode& last = nodes.back();  // only "/" can cover a path no deeper node's first byte names
        return last.path.size() == 1 && !last.exact ? &last : nullptr;
    }
};

}  // namespace agensio
