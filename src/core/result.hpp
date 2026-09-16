// Result<T>: a value or a std::error_code, for data-plane code that must not throw.
//
// TODO(std::expected): replace with std::expected<T, std::error_code> once the project
// moves to C++23 (needs GCC 13+, i.e. after Debian 12 support is dropped).
#pragma once

#include <cassert>
#include <system_error>
#include <type_traits>
#include <utility>

namespace agensio {

template <class T>
class [[nodiscard]] Result {
public:
    static_assert(!std::is_reference_v<T>, "Result<T&> is not supported");

    Result(T value) noexcept(std::is_nothrow_move_constructible_v<T>) : value_(std::move(value)), ok_(true) {}
    Result(std::error_code ec) noexcept : error_(ec), ok_(false) { assert(ec && "Result error must be non-zero"); }
    Result(std::errc e) noexcept : Result(std::make_error_code(e)) {}

    Result(Result&& o) noexcept(std::is_nothrow_move_constructible_v<T>) : ok_(o.ok_) {
        if (ok_) new (&value_) T(std::move(o.value_));
        else error_ = o.error_;
    }
    Result& operator=(Result&& o) noexcept(std::is_nothrow_move_constructible_v<T>) {
        if (this != &o) {
            destroy();
            ok_ = o.ok_;
            if (ok_) new (&value_) T(std::move(o.value_));
            else error_ = o.error_;
        }
        return *this;
    }
    Result(const Result&) = delete;
    Result& operator=(const Result&) = delete;
    ~Result() { destroy(); }

    bool ok() const noexcept { return ok_; }
    explicit operator bool() const noexcept { return ok_; }
    std::error_code error() const noexcept { return ok_ ? std::error_code() : error_; }

    T& value() & noexcept { assert(ok_); return value_; }
    const T& value() const& noexcept { assert(ok_); return value_; }
    T&& value() && noexcept { assert(ok_); return std::move(value_); }
    T* operator->() noexcept { assert(ok_); return &value_; }
    const T* operator->() const noexcept { assert(ok_); return &value_; }
    T& operator*() & noexcept { return value(); }
    const T& operator*() const& noexcept { return value(); }

private:
    void destroy() noexcept {
        if (ok_) value_.~T();
    }
    union {
        T value_;
        std::error_code error_;
    };
    bool ok_;
};

template <>
class [[nodiscard]] Result<void> {
public:
    Result() noexcept = default;
    Result(std::error_code ec) noexcept : error_(ec) {}
    Result(std::errc e) noexcept : error_(std::make_error_code(e)) {}
    bool ok() const noexcept { return !error_; }
    explicit operator bool() const noexcept { return ok(); }
    std::error_code error() const noexcept { return error_; }

private:
    std::error_code error_;
};

}  // namespace agensio
