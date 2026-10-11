// libFuzzer target for the refused-path patterns (`refuse` on a site, core/refuse.hpp): the input
// is patterns, one per line, an empty line, then paths. Each pattern is compiled as a site file's
// would be; each path is normalised as a request target is, then judged by the indexed lookup the
// dispatcher uses on every request (refuse::match) and by a plain scan of every pattern
// (refuse::matches): the two must agree, or a path slips past a refusal or a page answers 404
// for nothing. decide() adds the other readings of the path an origin may take. The run's timeout
// catches a pattern and path whose matching is not linear (one "**" per pattern keeps it so).
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "core/refuse.hpp"
#include "path.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::string_view in(reinterpret_cast<const char*>(data), size);
    agensio::RefuseSet set;
    std::size_t pos = 0;
    while (pos <= in.size()) {  // the patterns, up to the empty line
        const std::size_t nl = in.find('\n', pos);
        const std::string_view line = in.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = nl == std::string_view::npos ? in.size() + 1 : nl + 1;
        if (line.empty()) break;
        if (set.patterns.size() == agensio::refuse::kMaxPatterns || line.size() > agensio::refuse::kMaxLength) continue;
        agensio::RefusePattern p;
        if (agensio::refuse::compile(line, p).empty()) set.patterns.push_back(std::move(p));
    }
    agensio::refuse::index(set);
    std::string path, scratch;
    while (pos <= in.size()) {  // the paths
        const std::size_t nl = in.find('\n', pos);
        const std::string_view raw = in.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = nl == std::string_view::npos ? in.size() + 1 : nl + 1;
        if (!agensio::normalize_target(raw, path)) continue;
        const agensio::RefusePattern* hit = agensio::refuse::match(set, path);
        bool any = false;
        for (const auto& p : set.patterns) any = any || agensio::refuse::matches(p, path);
        assert((hit != nullptr) == any);  // the index finds what a scan of every pattern finds
        if (hit) assert(agensio::refuse::matches(*hit, path));
        const agensio::RefusePattern* decided = agensio::refuse::decide(set, path, scratch);
        if (hit) assert(decided != nullptr);  // the other readings only add refusals
    }
    return 0;
}
