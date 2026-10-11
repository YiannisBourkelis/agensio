// libFuzzer target for the log lines the control plane reads back (agensio ctl logs, MCP
// logs_query; control/loglines.*): the error log, the combined and the JSON access log, whose
// request lines and User-Agents clients wrote. The escaped text is valid UTF-8, unchanged when the
// line already was, and escaping it again changes nothing.
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <string_view>

#include "control/loglines.hpp"
#include "core/strings.hpp"

namespace {
bool valid_utf8(std::string_view s) {
    for (std::size_t i = 0; i < s.size();) {
        if (static_cast<unsigned char>(s[i]) < 0x80) {
            ++i;
            continue;
        }
        const std::size_t n = agensio::utf8_sequence(s, i);
        if (n == 0) return false;
        i += n;
    }
    return true;
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace agensio::control;
    const std::string_view line(reinterpret_cast<const char*>(data), size);
    LogLine out;
    (void)parse_log_line(line, out);
    const std::string escaped = utf8_escaped(line);
    assert(valid_utf8(escaped));
    if (valid_utf8(line)) assert(escaped == line);
    assert(utf8_escaped(escaped) == escaped);
    std::time_t since = 0;
    (void)parse_since(line, 1760000000, since);
    return 0;
}
