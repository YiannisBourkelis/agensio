// libFuzzer target for request-target normalisation and the path policies.
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "path.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::string_view target(reinterpret_cast<const char*>(data), size);
    std::string out;
    if (agensio::normalize_target(target, out)) {
        // Invariants a traversal would violate.
        assert(!out.empty() && out[0] == '/');
        assert(out.find("//") == std::string::npos);
        assert(out.find("/./") == std::string::npos && out.find("/../") == std::string::npos);
        assert(!(out.size() >= 3 && out.compare(out.size() - 3, 3, "/..") == 0));
        assert(!(out.size() >= 2 && out.compare(out.size() - 2, 2, "/.") == 0));
        for (unsigned char c : out)
            assert(c >= 0x20 && c != 0x7f);
        (void)agensio::has_hidden_segment(out);
        (void)agensio::windows_path_ok(out);
    }
    return 0;
}
