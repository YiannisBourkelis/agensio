// Small string_view helpers that never throw, for use in noexcept hot-path code.
#pragma once

#include <algorithm>
#include <cstddef>
#include <string_view>

namespace agensio {

// Like string_view::substr but clamps instead of throwing when pos is past the end.
constexpr std::string_view slice(std::string_view s, std::size_t pos,
                                 std::size_t len = std::string_view::npos) noexcept {
    if (pos >= s.size()) return {};
    return std::string_view(s.data() + pos, std::min(len, s.size() - pos));
}

}  // namespace agensio
