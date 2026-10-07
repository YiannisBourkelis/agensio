// Paths a site refuses by pattern (`refuse`, 2026-10-08, docs/configuration.md 6, design
// section 24): gitignore-style globs, written in a site file or rendered from a managed site's
// rules.refuse, most often translated from an application's official server configuration.
//
//   "/vendor/"                          from the site's root: the directory and everything below
//   "composer.json", "*.yaml", "_temp_/"  a name in any directory (no '/' but a trailing one)
//   "/typo3/sysext/*/Resources/Private/"  '*' is any run of characters within one segment
//   "/fileadmin/templates/**/*.ts"        "**" is any number of directories, zero included
//
// A pattern refuses the path it matches and everything below it. No regex, no order, no
// exception: a match is a 404 whichever location would have served the path, so nothing can
// be shadowed the way an nginx regex location shadows another. Matching ignores ASCII case
// and a segment's trailing dots (as the endings rule does), allocates nothing, and is linear:
// at most one "**" per pattern. Used by the dispatcher on every request of a site that has
// patterns, by the static handler on a directory's index file, by path_check and by the tests.
#pragma once

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "core/access.hpp"

namespace agensio::refuse {

inline constexpr std::size_t kMaxPatterns = 64;
inline constexpr std::size_t kMaxLength = 200;

inline char lower(char c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }

// `s` (from a path) against `lit` (from a pattern, lower case already).
inline bool ieq(std::string_view s, std::string_view lit) noexcept {
    if (s.size() != lit.size()) return false;
    for (std::size_t i = 0; i < s.size(); ++i)
        if (lower(s[i]) != lit[i]) return false;
    return true;
}

inline std::size_t ifind(std::string_view s, std::string_view lit) noexcept {
    for (std::size_t i = 0; i + lit.size() <= s.size(); ++i)
        if (ieq(s.substr(i, lit.size()), lit)) return i;
    return std::string_view::npos;
}

// One path segment against one pattern segment. The literals between the stars are taken
// leftmost, which is exact for a pattern made of literals and '*' only.
inline bool segment_matches(const RefuseSegment& g, std::string_view s) noexcept {
    if (!g.star) return ieq(s, g.first);
    if (s.size() < g.first.size() + g.last.size()) return false;
    if (!ieq(s.substr(0, g.first.size()), g.first) || !ieq(s.substr(s.size() - g.last.size()), g.last)) return false;
    std::string_view rest = s.substr(g.first.size(), s.size() - g.first.size() - g.last.size());
    for (const std::string& m : g.mid) {
        const std::size_t at = ifind(rest, m);
        if (at == std::string_view::npos) return false;
        rest.remove_prefix(at + m.size());
    }
    return true;
}

// The next segment of `path` from `pos` (left past it), its trailing dots dropped.
inline bool next_segment(std::string_view path, std::size_t& pos, std::string_view& out) noexcept {
    while (pos < path.size() && path[pos] == '/') ++pos;
    if (pos >= path.size()) return false;
    std::size_t end = path.find('/', pos);
    if (end == std::string_view::npos) end = path.size();
    out = path.substr(pos, end - pos);
    pos = end;
    while (out.size() > 1 && out.back() == '.') out.remove_suffix(1);
    return true;
}

// Whether `p` refuses `path`: its head matches the first segments and, after a "**", its tail
// matches at some depth below them. Matching a prefix of the path refuses the rest of it.
inline bool matches(const RefusePattern& p, std::string_view path) noexcept {
    std::size_t pos = 0;
    std::string_view s;
    for (const RefuseSegment& g : p.head)
        if (!next_segment(path, pos, s) || !segment_matches(g, s)) return false;
    if (!p.deep || p.tail.empty()) return true;
    for (;;) {
        std::size_t q = pos;
        bool all = true;
        for (const RefuseSegment& g : p.tail)
            if (!next_segment(path, q, s) || !segment_matches(g, s)) {
                all = false;
                break;
            }
        if (all) return true;
        if (!next_segment(path, pos, s)) return false;
    }
}

// The pattern refusing `path` (normalised, from its leading '/'), or null. The path is split
// into segments once; each is compared with the name patterns of its last byte's bucket, and
// the first segment, lowered once, picks the one group of anchored patterns that begins with
// it (twenty TYPO3 patterns begin with "typo3...": comparing each from the start cost 200 ns).
inline const RefusePattern* match(const RefuseSet& set, std::string_view path) noexcept {
    if (set.patterns.empty()) return nullptr;
    constexpr std::size_t kSplit = 16;  // deeper paths: anchored patterns rescan (matches())
    std::size_t at[kSplit], len[kSplit];
    std::size_t n = 0, pos = 0;
    std::string_view s;
    while (next_segment(path, pos, s)) {
        if (n < kSplit) {
            at[n] = static_cast<std::size_t>(s.data() - path.data());
            len[n] = s.size();
        }
        ++n;
        for (const unsigned key : {static_cast<unsigned>(static_cast<unsigned char>(lower(s.back()))), 256u})
            for (std::size_t i = set.name_at[key]; i < set.name_at[key + 1]; ++i)
                if (segment_matches(set.patterns[set.names[i]].tail.front(), s)) return &set.patterns[set.names[i]];
    }
    if (n == 0) return nullptr;
    auto head_matches = [&](const RefusePattern& p, std::size_t from) {
        if (p.head.size() > n) return false;
        if (p.deep || n > kSplit) return matches(p, path);
        for (std::size_t k = from; k < p.head.size(); ++k)
            if (!segment_matches(p.head[k], path.substr(at[k], len[k]))) return false;
        return true;
    };
    if (!set.groups.empty() && len[0] <= set.longest_first) {
        char first[kMaxLength];
        for (std::size_t i = 0; i < len[0]; ++i) first[i] = lower(path[at[0] + i]);
        const std::string_view lowered(first, len[0]);
        for (const RefuseSet::Group& g : set.groups) {
            if (g.first != lowered) continue;
            for (const std::uint8_t i : g.members)
                if (head_matches(set.patterns[i], 1)) return &set.patterns[i];
            break;
        }
    }
    for (const std::uint8_t i : set.anchored_any)
        if (head_matches(set.patterns[i], 0)) return &set.patterns[i];
    for (const std::uint8_t i : set.anywhere)
        if (matches(set.patterns[i], path)) return &set.patterns[i];
    return nullptr;
}

// The path and the other ways an origin may read it (access::other_readings: a ";parameter",
// a second decoding, the path after a script), so a proxied application's own reading cannot
// reach what the site refuses either. An ordinary path is judged once.
inline const RefusePattern* decide(const RefuseSet& set, std::string_view path, std::string& scratch) {
    if (set.patterns.empty()) return nullptr;
    if (const RefusePattern* p = match(set, path)) return p;
    const RefusePattern* hit = nullptr;
    access::other_readings(path, scratch, [&](std::string_view r) {
        if (!hit) hit = match(set, r);
    });
    return hit;
}

inline RefuseSegment compile_segment(std::string_view seg) {
    RefuseSegment g;
    std::string low(seg);
    for (char& c : low) c = lower(c);
    const std::size_t star = low.find('*');
    if (star == std::string::npos) {
        g.first = std::move(low);
        return g;
    }
    const std::size_t last = low.rfind('*');
    g.star = true;
    g.first = low.substr(0, star);
    g.last = low.substr(last + 1);
    std::size_t from = star + 1;
    while (from < last) {
        const std::size_t next = low.find('*', from);
        if (next > from) g.mid.push_back(low.substr(from, next - from));
        from = next + 1;
    }
    return g;
}

// `text` compiled into `out`, or why the pattern is refused: what it would mean is said
// back in the message, so whoever translated it from another server's syntax can correct it.
inline std::string compile(std::string_view text, RefusePattern& out) {
    out = RefusePattern{};
    out.text = std::string(text);
    const std::string quoted = "'" + std::string(text.substr(0, kMaxLength)) + "'";
    if (text.empty()) return "an empty pattern refuses nothing";
    if (text.size() > kMaxLength) return quoted + "... is longer than " + std::to_string(kMaxLength) + " characters";
    for (const char c : text) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x21 || u == 0x7f) return quoted + " holds a space or a control character";
        if (c == '%') return quoted + ": write the character itself, not its percent escape (paths are matched decoded)";
        if (c == '?' || c == '[' || c == ']' || c == '{' || c == '}')
            return quoted + ": the wildcards are '*' (within one segment) and '**' (any number of directories); write one pattern per alternative";
        if (c == '\\' || c == '#' || c == '"' || c == '<' || c == '>' || c == '^' || c == '`' || c == '|')
            return quoted + " holds '" + std::string(1, c) + "', which a path never does";
    }
    std::string_view rest = text;
    const bool anchored = rest.front() == '/';
    if (anchored) rest.remove_prefix(1);
    if (!rest.empty() && rest.back() == '/') rest.remove_suffix(1);  // a directory: it and everything below, as without the '/'
    if (rest.empty() || rest == "**") return quoted + " refuses the whole site: disable the site, or restrict it by address, instead";
    std::vector<std::string_view> segs;
    for (std::size_t from = 0;;) {
        const std::size_t slash = rest.find('/', from);
        segs.push_back(rest.substr(from, slash == std::string_view::npos ? std::string_view::npos : slash - from));
        if (slash == std::string_view::npos) break;
        from = slash + 1;
    }
    if (!anchored && segs.size() > 1 && segs.front() != "**")
        return quoted + " has a '/' inside: anchor it at the site's root with a leading '/' ('/" + std::string(rest) +
               (text.back() == '/' ? "/" : "") + "'), or begin it with '**/' to refuse it at any depth";
    if (!anchored && segs.size() == 1) out.deep = true;  // a name: in any directory
    bool only_wildcards = true;
    for (const std::string_view seg : segs) {
        if (seg.empty()) return quoted + " has an empty segment ('//')";
        if (seg == "." || seg == "..") return quoted + " has a '" + std::string(seg) + "' segment; paths are matched normalised";
        if (seg == "**") {
            if (out.deep) return quoted + " has more than one '**'; one is any number of directories";
            out.deep = true;
            continue;
        }
        if (seg.find("**") != std::string_view::npos)
            return quoted + ": '**' is a whole segment (any number of directories); within a segment the wildcard is '*'";
        if (seg.back() == '.') return quoted + ": a segment ending in '.' never matches (trailing dots are ignored, x.yaml. is x.yaml)";
        if (seg.find_first_not_of('*') != std::string_view::npos) only_wildcards = false;
        (out.deep ? out.tail : out.head).push_back(compile_segment(seg));
    }
    if (only_wildcards) return quoted + " matches every path below some depth; name what to refuse";
    return "";
}

// What match() looks in; called once the patterns are in place.
inline void index(RefuseSet& set) {
    set.names.clear();
    set.anchored_any.clear();
    set.anywhere.clear();
    set.groups.clear();
    set.longest_first = 0;
    std::array<std::uint8_t, 258> names{};
    auto name_key = [](const RefuseSegment& g) {
        const std::string& end = g.star ? g.last : g.first;
        return end.empty() ? 256u : static_cast<unsigned>(static_cast<unsigned char>(end.back()));
    };
    for (const RefusePattern& p : set.patterns)
        if (p.head.empty() && p.tail.size() == 1) ++names[name_key(p.tail.front()) + 1];
    for (std::size_t k = 1; k < names.size(); ++k) names[k] = static_cast<std::uint8_t>(names[k] + names[k - 1]);
    set.name_at = names;
    set.names.resize(names[257]);
    for (std::size_t i = 0; i < set.patterns.size(); ++i) {
        const RefusePattern& p = set.patterns[i];
        const auto at = static_cast<std::uint8_t>(i);
        if (p.head.empty() && p.tail.size() == 1) {
            set.names[names[name_key(p.tail.front())]++] = at;
        } else if (p.head.empty()) {
            set.anywhere.push_back(at);
        } else if (p.head.front().star) {
            set.anchored_any.push_back(at);
        } else {
            const std::string& first = p.head.front().first;
            auto g = std::find_if(set.groups.begin(), set.groups.end(), [&](const RefuseSet::Group& x) { return x.first == first; });
            if (g == set.groups.end()) g = set.groups.insert(set.groups.end(), RefuseSet::Group{first, {}});
            g->members.push_back(at);
            set.longest_first = std::max(set.longest_first, first.size());
        }
    }
}

}  // namespace agensio::refuse
