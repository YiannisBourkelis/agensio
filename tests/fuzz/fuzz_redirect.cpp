// libFuzzer target for path redirects ([[site.redirect]], core/redirect.hpp, docs/redirects.md 5.3):
// the input is rules, three lines each (from, to, flags: 'e' exact, 'd' remainder drop, 'q' query
// drop), up to an empty line, then request targets. Each rule is compiled as a site file's would be;
// each target is normalised as a request is and looked up as the dispatcher does. Whatever a rule
// takes, its Location must hold no control character, space or backslash, a relative one must
// start with one '/' (never "//" or "/\", another host to a browser), and an absolute one must
// start with exactly the target's origin and then '/', so no path or query can change the host.
// The indexed lookup must agree with a scan of every rule for the most specific one. A directory's
// slash redirect (redirect::directory_location) is held to the relative rules for every target, and
// its path must decode back to the request's with the slash.
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "core/redirect.hpp"
#include "path.hpp"

namespace {

std::string_view next_line(std::string_view in, std::size_t& pos) {
    const std::size_t nl = in.find('\n', pos);
    const std::string_view line = in.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
    pos = nl == std::string_view::npos ? in.size() + 1 : nl + 1;
    return line;
}

void check_location(std::string_view loc, std::string_view origin) {
    for (const char ch : loc) {
        const auto c = static_cast<unsigned char>(ch);
        assert(c > 0x20 && c < 0x7f && c != '\\');
    }
    if (origin.empty()) {
        assert(loc.size() >= 1 && loc[0] == '/');
        assert(loc.size() < 2 || (loc[1] != '/' && loc[1] != '\\'));
    } else {
        assert(loc.starts_with(origin));
        assert(loc.size() > origin.size() && loc[origin.size()] == '/');
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view in(reinterpret_cast<const char*>(data), size);
    agensio::RedirectSet set;
    std::size_t pos = 0;
    while (pos <= in.size() && set.rules.size() < 64) {
        const std::string_view from = next_line(in, pos);
        if (from.empty() || pos > in.size()) break;
        const std::string_view to = next_line(in, pos);
        const std::string_view flags = pos <= in.size() ? next_line(in, pos) : std::string_view();
        agensio::RedirectRule r;
        const bool exact = flags.find('e') != std::string_view::npos;
        if (!agensio::redirect::compile_from(from, exact, r).empty()) continue;
        if (to == "410") r.status = 410;
        else if (!agensio::redirect::compile_to(to, r).empty()) continue;
        r.keep_remainder = flags.find('d') == std::string_view::npos;
        r.keep_query = flags.find('q') == std::string_view::npos && r.params.empty();
        set.rules.push_back(std::move(r));
    }
    agensio::redirect::index(set);
    std::string path, loc;
    while (pos <= in.size()) {
        const std::string_view target = next_line(in, pos);
        bool encoded = false;
        if (!agensio::normalize_target(target, path, &encoded)) continue;
        const std::string_view query = agensio::redirect::query_of(target);
        // A directory asked for without its slash (the static handler's 301): the same guarantees, and
        // its path decodes back to the request's with the slash.
        if (path.back() != '/') {
            agensio::redirect::directory_location(loc, path, query);
            check_location(loc, "");
            std::string back;
            assert(agensio::redirect::decode(loc.substr(0, loc.find('?')), back) && back == path + "/");
        }
        const agensio::RedirectRule* hit = agensio::redirect::match(set, path, query, encoded);
        // The scan: an exact rule of the path whose parameters are there (the most parameters), else
        // the longest prefix that covers it; the index must find a rule exactly when the scan does.
        const agensio::RedirectRule* scan = nullptr;
        for (const auto& r : set.rules)
            if (r.exact && r.from == path && agensio::redirect::params_match(r, query) && (!scan || r.params.size() > scan->params.size())) scan = &r;
        if (!scan && !encoded)
            for (const auto& r : set.rules)
                if (!r.exact && agensio::redirect::covers(r, path) && (!scan || r.from.size() > scan->from.size())) scan = &r;
        assert((hit != nullptr) == (scan != nullptr));
        if (!hit) continue;
        assert(hit->exact == scan->exact && hit->from == scan->from);
        if (hit->status == 410) continue;
        agensio::redirect::write_location(loc, *hit, path, query, "");
        check_location(loc, hit->origin);
        agensio::redirect::write_location(loc, *hit, path, query, "https://h.example");  // one hop with the scheme
        check_location(loc, hit->origin.empty() ? std::string_view("https://h.example") : std::string_view(hit->origin));
    }
    return 0;
}
