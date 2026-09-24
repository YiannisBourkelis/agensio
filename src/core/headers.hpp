// Header fields as name/value views into a buffer owned by the stream (the HTTP/1 receive
// buffer today; an HPACK/QPACK-decoded arena for HTTP/2 and HTTP/3 later). Fixed capacity,
// no allocation, linear case-insensitive lookup (typical requests carry 5-15 fields).
#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace agensio {

struct HeaderField {
    std::string_view name;
    std::string_view value;
};

class Headers {
public:
    static constexpr std::size_t kCapacity = 100;  // also the parser's hard limit

    // False when full; callers treat that as "too many headers".
    bool add(std::string_view name, std::string_view value) noexcept {
        if (count_ >= kCapacity) return false;
        fields_[count_++] = HeaderField{name, value};
        return true;
    }
    void clear() noexcept { count_ = 0; }

    std::size_t size() const noexcept { return count_; }
    bool empty() const noexcept { return count_ == 0; }
    const HeaderField* begin() const noexcept { return fields_.data(); }
    const HeaderField* end() const noexcept { return fields_.data() + count_; }
    // The fields' bytes moved: every view into [from, from + len) now points into `to`.
    void rebase(const char* from, std::size_t len, const char* to) noexcept {
        for (std::size_t i = 0; i < count_; ++i) {
            rebase_view(fields_[i].name, from, len, to);
            rebase_view(fields_[i].value, from, len, to);
        }
    }
    static void rebase_view(std::string_view& v, const char* from, std::size_t len, const char* to) noexcept {
        if (v.data() >= from && v.data() < from + len) v = std::string_view(to + (v.data() - from), v.size());
    }
    const HeaderField& operator[](std::size_t i) const noexcept { return fields_[i]; }

    // First field with this name (case-insensitive), or an empty view.
    std::string_view get(std::string_view name) const noexcept {
        for (std::size_t i = 0; i < count_; ++i)
            if (iequals(fields_[i].name, name)) return fields_[i].value;
        return {};
    }
    bool contains(std::string_view name) const noexcept {
        for (std::size_t i = 0; i < count_; ++i)
            if (iequals(fields_[i].name, name)) return true;
        return false;
    }

    static bool iequals(std::string_view a, std::string_view b) noexcept {
        if (a.size() != b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i)
            if (lower(a[i]) != lower(b[i])) return false;
        return true;
    }

private:
    static constexpr char lower(char c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }
    std::array<HeaderField, kCapacity> fields_{};
    std::size_t count_ = 0;
};

}  // namespace agensio
