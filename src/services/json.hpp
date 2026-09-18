// A small JSON value, parser and writer: enough for ACME (RFC 8555) documents and the
// control API later. Objects keep their keys in order; numbers are doubles; no comments,
// no NaN, strings with the standard escapes. Header-only, no dependencies.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace agensio::json {

class Value {
public:
    enum class Type { null, boolean, number, string, array, object };

    Value() = default;
    Value(std::nullptr_t) {}
    Value(bool b) : type_(Type::boolean), bool_(b) {}
    Value(double d) : type_(Type::number), number_(d) {}
    Value(int i) : type_(Type::number), number_(i) {}
    Value(std::string s) : type_(Type::string), string_(std::move(s)) {}
    Value(const char* s) : type_(Type::string), string_(s) {}
    Value(std::string_view s) : type_(Type::string), string_(s) {}
    static Value array() { Value v; v.type_ = Type::array; return v; }
    static Value object() { Value v; v.type_ = Type::object; return v; }

    Type type() const noexcept { return type_; }
    bool is_null() const noexcept { return type_ == Type::null; }
    bool is_string() const noexcept { return type_ == Type::string; }
    bool is_object() const noexcept { return type_ == Type::object; }
    bool is_array() const noexcept { return type_ == Type::array; }
    const std::string& str() const noexcept { return string_; }
    double num() const noexcept { return number_; }
    bool boolean() const noexcept { return bool_; }
    const std::vector<Value>& items() const noexcept { return array_; }
    const std::vector<std::pair<std::string, Value>>& members() const noexcept { return object_; }

    // Object access: a missing key or a non-object yields a shared null.
    const Value& operator[](std::string_view key) const noexcept {
        static const Value null;
        if (type_ != Type::object) return null;
        for (const auto& m : object_)
            if (m.first == key) return m.second;
        return null;
    }
    // String of a key, or "" when absent.
    std::string_view get(std::string_view key) const noexcept {
        const Value& v = (*this)[key];
        return v.is_string() ? std::string_view(v.string_) : std::string_view();
    }
    Value& set(std::string key, Value v) {
        type_ = Type::object;
        for (auto& m : object_)
            if (m.first == key) {
                m.second = std::move(v);
                return *this;
            }
        object_.emplace_back(std::move(key), std::move(v));
        return *this;
    }
    Value& push(Value v) {
        type_ = Type::array;
        array_.push_back(std::move(v));
        return *this;
    }

    // Compact serialisation (no whitespace), keys in insertion order: what JWS needs.
    std::string dump() const {
        std::string out;
        write(out);
        return out;
    }

private:
    static void write_string(std::string& out, std::string_view s) {
        out.push_back('"');
        for (unsigned char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        static const char hex[] = "0123456789abcdef";
                        out += "\\u00";
                        out.push_back(hex[c >> 4]);
                        out.push_back(hex[c & 15]);
                    } else {
                        out.push_back(static_cast<char>(c));
                    }
            }
        }
        out.push_back('"');
    }
    void write(std::string& out) const {
        switch (type_) {
            case Type::null: out += "null"; break;
            case Type::boolean: out += bool_ ? "true" : "false"; break;
            case Type::number: {
                char buf[32];
                const auto n = static_cast<long long>(number_);
                if (static_cast<double>(n) == number_) std::snprintf(buf, sizeof buf, "%lld", n);
                else std::snprintf(buf, sizeof buf, "%.17g", number_);
                out += buf;
                break;
            }
            case Type::string: write_string(out, string_); break;
            case Type::array:
                out.push_back('[');
                for (std::size_t i = 0; i < array_.size(); ++i) {
                    if (i) out.push_back(',');
                    array_[i].write(out);
                }
                out.push_back(']');
                break;
            case Type::object:
                out.push_back('{');
                for (std::size_t i = 0; i < object_.size(); ++i) {
                    if (i) out.push_back(',');
                    write_string(out, object_[i].first);
                    out.push_back(':');
                    object_[i].second.write(out);
                }
                out.push_back('}');
                break;
        }
    }

    Type type_ = Type::null;
    bool bool_ = false;
    double number_ = 0;
    std::string string_;
    std::vector<Value> array_;
    std::vector<std::pair<std::string, Value>> object_;
};

// Parses a document; `error` names the position of a problem. Depth is bounded.
class Parser {
public:
    static bool parse(std::string_view text, Value& out, std::string& error) {
        Parser p{text};
        p.skip();
        if (!p.value(out, 0)) {
            error = p.error_ + " at offset " + std::to_string(p.pos_);
            return false;
        }
        p.skip();
        if (p.pos_ != text.size()) {
            error = "trailing characters at offset " + std::to_string(p.pos_);
            return false;
        }
        return true;
    }

private:
    explicit Parser(std::string_view t) : t_(t) {}
    static constexpr int kMaxDepth = 64;

    void skip() {
        while (pos_ < t_.size() && (t_[pos_] == ' ' || t_[pos_] == '\t' || t_[pos_] == '\n' || t_[pos_] == '\r')) ++pos_;
    }
    bool fail(const char* what) {
        error_ = what;
        return false;
    }
    bool literal(std::string_view word) {
        if (t_.substr(pos_, word.size()) != word) return false;
        pos_ += word.size();
        return true;
    }
    bool value(Value& out, int depth) {
        if (depth > kMaxDepth) return fail("nesting too deep");
        if (pos_ >= t_.size()) return fail("unexpected end");
        const char c = t_[pos_];
        if (c == '{') return object(out, depth);
        if (c == '[') return array(out, depth);
        if (c == '"') {
            std::string s;
            if (!string(s)) return false;
            out = Value(std::move(s));
            return true;
        }
        if (literal("true")) { out = Value(true); return true; }
        if (literal("false")) { out = Value(false); return true; }
        if (literal("null")) { out = Value(nullptr); return true; }
        return number(out);
    }
    bool number(Value& out) {
        const std::size_t start = pos_;
        if (pos_ < t_.size() && t_[pos_] == '-') ++pos_;
        while (pos_ < t_.size() && ((t_[pos_] >= '0' && t_[pos_] <= '9') || t_[pos_] == '.' || t_[pos_] == 'e' ||
                                    t_[pos_] == 'E' || t_[pos_] == '+' || t_[pos_] == '-'))
            ++pos_;
        if (pos_ == start) return fail("unexpected character");
        const std::string text(t_.substr(start, pos_ - start));
        char* end = nullptr;
        const double d = std::strtod(text.c_str(), &end);
        if (!end || *end != '\0') return fail("bad number");
        out = Value(d);
        return true;
    }
    static bool hex4(std::string_view s, unsigned& v) {
        if (s.size() < 4) return false;
        v = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = s[i];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0';
            else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
            else return false;
        }
        return true;
    }
    static void utf8(std::string& out, unsigned cp) {
        if (cp < 0x80) out.push_back(static_cast<char>(cp));
        else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    bool string(std::string& out) {
        ++pos_;  // opening quote
        for (;;) {
            if (pos_ >= t_.size()) return fail("unterminated string");
            const char c = t_[pos_++];
            if (c == '"') return true;
            if (static_cast<unsigned char>(c) < 0x20) return fail("control character in string");
            if (c != '\\') {
                out.push_back(c);
                continue;
            }
            if (pos_ >= t_.size()) return fail("unterminated escape");
            const char e = t_[pos_++];
            switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    unsigned cp = 0;
                    if (!hex4(t_.substr(pos_), cp)) return fail("bad \\u escape");
                    pos_ += 4;
                    if (cp >= 0xD800 && cp < 0xDC00 && t_.substr(pos_, 2) == "\\u") {  // surrogate pair
                        unsigned lo = 0;
                        if (hex4(t_.substr(pos_ + 2), lo) && lo >= 0xDC00 && lo < 0xE000) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            pos_ += 6;
                        }
                    }
                    utf8(out, cp);
                    break;
                }
                default: return fail("bad escape");
            }
        }
    }
    bool array(Value& out, int depth) {
        ++pos_;
        out = Value::array();
        skip();
        if (pos_ < t_.size() && t_[pos_] == ']') { ++pos_; return true; }
        for (;;) {
            Value item;
            skip();
            if (!value(item, depth + 1)) return false;
            out.push(std::move(item));
            skip();
            if (pos_ >= t_.size()) return fail("unterminated array");
            if (t_[pos_] == ',') { ++pos_; continue; }
            if (t_[pos_] == ']') { ++pos_; return true; }
            return fail("expected , or ]");
        }
    }
    bool object(Value& out, int depth) {
        ++pos_;
        out = Value::object();
        skip();
        if (pos_ < t_.size() && t_[pos_] == '}') { ++pos_; return true; }
        for (;;) {
            skip();
            if (pos_ >= t_.size() || t_[pos_] != '"') return fail("expected a key");
            std::string key;
            if (!string(key)) return false;
            skip();
            if (pos_ >= t_.size() || t_[pos_] != ':') return fail("expected :");
            ++pos_;
            skip();
            Value item;
            if (!value(item, depth + 1)) return false;
            out.set(std::move(key), std::move(item));
            skip();
            if (pos_ >= t_.size()) return fail("unterminated object");
            if (t_[pos_] == ',') { ++pos_; continue; }
            if (t_[pos_] == '}') { ++pos_; return true; }
            return fail("expected , or }");
        }
    }

    std::string_view t_;
    std::size_t pos_ = 0;
    std::string error_;
};

inline bool parse(std::string_view text, Value& out, std::string& error) { return Parser::parse(text, out, error); }

}  // namespace agensio::json
