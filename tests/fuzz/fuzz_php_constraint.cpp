// libFuzzer target for what an installed PHP application declares of itself (services/php_requirements):
// the input's first line is a PHP version, the rest a Composer constraint, and then the same bytes as a
// composer.json and as WordPress's version.php. Read from archives a user uploads, so bounded and total:
// any input gives an answer, and a constraint the reader does not understand is said to be unknown,
// never read as one that refuses. A version always satisfies its own exact constraint and "*".
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "services/php_requirements.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view in(reinterpret_cast<const char*>(data), size);
    const std::size_t nl = in.find('\n');
    const std::string_view version = in.substr(0, nl);
    const std::string_view constraint = nl == std::string_view::npos ? std::string_view() : in.substr(nl + 1);
    bool known = false;
    const bool allows = agensio::php::constraint_allows(constraint, version, known);
    if (!known) assert(allows);  // what is not understood refuses nothing
    bool k2 = false;
    const bool self = agensio::php::constraint_allows(version, version, k2);  // a version is its own exact constraint
    if (k2) {
        assert(self);
        bool k3 = false;
        assert(agensio::php::constraint_allows("*", version, k3) && k3);
    }
    (void)agensio::php::compare_versions(version, constraint);
    const agensio::php::Declared d = agensio::php::parse_composer(in);
    if (!d.php.empty()) {
        bool k4 = false;
        (void)agensio::php::constraint_allows(d.php, "8.4.0", k4);
    }
    const std::string wp = agensio::php::parse_wp_required(in);
    if (!wp.empty()) assert(agensio::php::compare_versions(wp, wp) == 0);
    return 0;
}
