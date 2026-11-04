// libFuzzer target for the crontab reader of a Laravel site's scheduler (control::scheduler_cron_lines):
// the provisioning helper runs it as root over the account's own crontab, which the account writes,
// and over /etc/crontab and /etc/cron.d. Input: the first byte's low bit is any_line and the next byte
// the limit, then the project directory up to the first newline, then the crontab's text.
// Promise: the numbers, from 1, of the first `limit` lines that are no comment, run schedule:run and,
// unless any_line, name the project directory as a path (followed by '/', a blank or the end of the
// line): none missed, none extra.
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "control/sites.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 2) return 0;
    const bool any = (data[0] & 1) != 0;
    const std::size_t max = data[1] % 20;
    const std::string_view in(reinterpret_cast<const char*>(data + 2), size - 2);
    const std::size_t nl = in.find('\n');
    const std::string_view project = in.substr(0, nl);
    const std::string_view text = nl == std::string_view::npos ? std::string_view() : in.substr(nl + 1);
    std::vector<std::string_view> lines;
    for (std::size_t at = 0; at < text.size();) {
        const std::size_t end = std::min(text.find('\n', at), text.size());
        lines.push_back(text.substr(at, end - at));
        at = end + 1;
    }
    // Every line that qualifies, in order: the answer is their first `max`, so none is missed.
    std::vector<std::size_t> expect;
    for (std::size_t k = 0; k < lines.size() && expect.size() < max; ++k) {
        const std::string_view line = lines[k];
        const std::size_t first = line.find_first_not_of(" \t");
        if (first == std::string_view::npos || line[first] == '#' || line.find("schedule:run") == std::string_view::npos) continue;
        bool named = false;
        for (std::size_t p = project.empty() ? std::string_view::npos : line.find(project); p != std::string_view::npos && !named; p = line.find(project, p + 1)) {
            const std::size_t after = p + project.size();
            named = after == line.size() || line[after] == '/' || line[after] == ' ';
        }
        if (named || any) expect.push_back(k + 1);
    }
    const std::vector<std::size_t> found = agensio::control::scheduler_cron_lines(text, project, any, max);
    assert(found == expect);
    return 0;
}
