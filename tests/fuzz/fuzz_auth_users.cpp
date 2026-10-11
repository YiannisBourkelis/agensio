// libFuzzer target for the password files and the Basic credentials ([[site.auth]], core/auth.*):
// a users file (`name:hash[:expires=...][:note=...]`, comments, blank lines), its dates, and an
// Authorization value. A user parsed has a name without ':' or a line break; a Basic value
// decoded gives a user without ':' (the password keeps any). Built with authentication only.
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "core/auth.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace agensio::auth;
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    std::vector<User> users;
    if (parse_users(text, users).empty())
        for (const auto& u : users) {
            assert(!u.name.empty() && u.name.find(':') == std::string::npos && u.name.find('\n') == std::string::npos);
            assert(u.hash.find('\n') == std::string::npos && u.note.find('\n') == std::string::npos);
        }
    std::int64_t when = 0;
    (void)parse_date(text, when);
    std::string scratch;
    Credentials c;
    if (parse_basic(text, scratch, c) == Parsed::ok) assert(c.user.find(':') == std::string_view::npos);
    return 0;
}
