#include "core/auth.hpp"

#include <crypt.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <memory>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace agensio::auth {

namespace {

bool control(unsigned char c) noexcept { return c < 0x20 || c == 0x7f; }

// Days from 1970-01-01 to a civil date (Howard Hinnant's algorithm), for `expires`.
std::int64_t days_from_civil(int y, unsigned m, unsigned d) noexcept {
    y -= m <= 2;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return static_cast<std::int64_t>(era) * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

}  // namespace

bool parse_date(std::string_view s, std::int64_t& out) noexcept {
    if (s.size() != 10 || s[4] != '-' || s[7] != '-') return false;
    auto num = [&](std::size_t from, std::size_t len, int& v) {
        v = 0;
        for (std::size_t i = from; i < from + len; ++i) {
            if (s[i] < '0' || s[i] > '9') return false;
            v = v * 10 + (s[i] - '0');
        }
        return true;
    };
    int y = 0, m = 0, d = 0;
    if (!num(0, 4, y) || !num(5, 2, m) || !num(8, 2, d) || y < 1970 || m < 1 || m > 12 || d < 1) return false;
    static constexpr int kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    if (d > kDays[m - 1] + (m == 2 && leap ? 1 : 0)) return false;
    out = days_from_civil(y, static_cast<unsigned>(m), static_cast<unsigned>(d)) * 86400;
    return true;
}

namespace {

// The characters a crypt hash is written in: the setting and the output of every accepted
// method use these and '$' (and ',' / '=' in some parameter strings).
bool crypt_chars(std::string_view s) noexcept {
    for (const char c : s)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '/' || c == '$' ||
              c == ',' || c == '='))
            return false;
    return true;
}

const char* kMakeOne = "make the hash with `htpasswd -B -C 12` (bcrypt) or `mkpasswd -m yescrypt` (yescrypt)";

}  // namespace

std::string refused_hash(std::string_view h) {
    if (h.empty()) return "an empty hash (a user without a password); write ! to lock a user instead";
    if (h.front() == '!' || h == "*") return "";  // a locked user
    if (h.starts_with("{SHA}")) return std::string("{SHA} is unsalted SHA-1, refused; ") + kMakeOne;
    if (h.starts_with("{SSHA}")) return std::string("{SSHA} is salted SHA-1, too fast to resist guessing, refused; ") + kMakeOne;
    if (h.starts_with("{PLAIN}")) return std::string("{PLAIN} stores the password in plain text, refused; ") + kMakeOne;
    if (h.starts_with("{")) return std::string("an RFC 2307 {scheme} hash, refused; ") + kMakeOne;
    if (h.starts_with("$apr1$") || h.starts_with("$1$")) return std::string("an MD5 hash ($apr1$ or $1$, htpasswd's old default), refused; ") + kMakeOne;
    if (h.starts_with("$2x$")) return std::string("$2x$ is bcrypt from the buggy 8-bit implementation, refused; ") + kMakeOne;
    if (!crypt_chars(h)) return std::string("not a crypt hash; ") + kMakeOne;
    for (const char* ok : {"$y$", "$gy$", "$7$", "$2b$", "$2y$", "$2a$", "$6$", "$5$"})
        if (h.starts_with(ok)) return h.size() > std::strlen(ok) + 8 ? std::string() : std::string("a truncated hash; ") + kMakeOne;
    if (h.front() != '$' && h.front() != '_' && h.size() == 13) return std::string("a DES crypt hash (passwords cut at 8 characters), refused; ") + kMakeOne;
    return std::string("a hash method that is not accepted (yescrypt, bcrypt, sha512crypt, sha256crypt or scrypt are); ") + kMakeOne;
}

std::string parse_users(std::string_view text, std::vector<User>& out) {
    out.clear();
    std::size_t line_no = 0;
    while (!text.empty()) {
        ++line_no;
        const std::size_t nl = text.find('\n');
        std::string_view line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view() : text.substr(nl + 1);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        const std::string where = "line " + std::to_string(line_no) + ": ";
        std::size_t lead = 0;
        while (lead < line.size() && (line[lead] == ' ' || line[lead] == '\t')) ++lead;
        if (lead == line.size() || line[lead] == '#') continue;
        for (const char c : line)
            if (control(static_cast<unsigned char>(c))) return where + "a control character; a line is name:hash with optional :expires= and :note= fields";
        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos) return where + "no ':' after the user name; a line is name:hash";
        User u;
        u.name = std::string(line.substr(0, colon));
        if (u.name.empty() || u.name.size() > 255) return where + "a user name of 1 to 255 characters before the first ':'";
        if (u.name.find_first_of(" \t") != std::string::npos) return where + "a user name without spaces";
        std::string_view rest = line.substr(colon + 1);
        const std::size_t next = rest.find(':');
        u.hash = std::string(rest.substr(0, next));
        if (const std::string why = refused_hash(u.hash); !why.empty()) return where + "user " + u.name + ": " + why;
        u.locked = u.hash.front() == '!' || u.hash == "*";
        rest = next == std::string_view::npos ? std::string_view() : rest.substr(next + 1);
        while (!rest.empty()) {
            if (rest.starts_with("note=")) {  // the rest of the line, colons included
                u.note = std::string(rest.substr(5));
                break;
            }
            const std::size_t end = rest.find(':');
            const std::string_view field = rest.substr(0, end);
            rest = end == std::string_view::npos ? std::string_view() : rest.substr(end + 1);
            if (field.starts_with("expires=")) {
                if (!parse_date(field.substr(8), u.expires))
                    return where + "user " + u.name + ": expires must be a date, YYYY-MM-DD (from that day, UTC, the login is refused)";
                continue;
            }
            const std::string name(field.substr(0, field.find('=')));
            return where + "user " + u.name + ": unknown field '" + name + "' (expires=YYYY-MM-DD, note=text)";
        }
        for (const User& o : out)
            if (o.name == u.name) return where + "user " + u.name + " is listed twice";
        out.push_back(std::move(u));
    }
    if (out.empty()) return "no users: the file needs at least one line name:hash";
    return "";
}

Parsed parse_basic(std::string_view value, std::string& scratch, Credentials& out) {
    out = {};
    if (value.size() < 5) return Parsed::none;
    for (std::size_t i = 0; i < 5; ++i) {
        const char c = value[i];
        const char want = "basic"[i];
        if (c != want && c != want - 32) return Parsed::none;
    }
    if (value.size() == 5) return Parsed::malformed;
    if (value[5] != ' ') return Parsed::none;  // "Basicx": another scheme
    std::size_t at = 5;
    while (at < value.size() && value[at] == ' ') ++at;
    const std::string_view token = value.substr(at);
    constexpr std::size_t kMaxDecoded = 255 + 1 + 512;
    if (token.empty() || token.size() % 4 != 0 || token.size() / 4 * 3 > kMaxDecoded + 2) return Parsed::malformed;
    auto sextet = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    scratch.clear();
    for (std::size_t i = 0; i < token.size(); i += 4) {
        const bool last = i + 4 == token.size();
        int v[4];
        int pad = 0;
        for (int k = 0; k < 4; ++k) {
            const char c = token[i + static_cast<std::size_t>(k)];
            if (c == '=') {
                if (!last || k < 2) return Parsed::malformed;
                ++pad;
                v[k] = 0;
                continue;
            }
            if (pad) return Parsed::malformed;  // a character after '='
            v[k] = sextet(c);
            if (v[k] < 0) return Parsed::malformed;
        }
        const unsigned n = (static_cast<unsigned>(v[0]) << 18) | (static_cast<unsigned>(v[1]) << 12) | (static_cast<unsigned>(v[2]) << 6) |
                           static_cast<unsigned>(v[3]);
        scratch.push_back(static_cast<char>(n >> 16));
        if (pad < 2) scratch.push_back(static_cast<char>((n >> 8) & 0xff));
        if (pad < 1) scratch.push_back(static_cast<char>(n & 0xff));
    }
    if (scratch.size() > kMaxDecoded) return Parsed::malformed;
    for (const char c : scratch)
        if (control(static_cast<unsigned char>(c))) return Parsed::malformed;  // a NUL would end the password for crypt
    const std::size_t colon = scratch.find(':');
    if (colon == std::string::npos || colon == 0 || colon > 255 || scratch.size() - colon - 1 > 512) return Parsed::malformed;
    out.user = std::string_view(scratch).substr(0, colon);
    out.password = std::string_view(scratch).substr(colon + 1);
    return Parsed::ok;
}

std::string make_hash(std::string_view password, std::string_view method, unsigned long cost, std::string& error) {
    error.clear();
    if (password.empty() || password.size() > 512) {
        error = "a password of 1 to 512 bytes";
        return "";
    }
    for (const char c : password)
        if (control(static_cast<unsigned char>(c))) {
            error = "a password without control characters (a browser cannot send them)";
            return "";
        }
    const char* prefix = nullptr;
    if (method.empty() || method == "yescrypt") prefix = "$y$";
    else if (method == "bcrypt") {
        prefix = "$2b$";
        if (cost == 0) cost = 12;
        if (cost < 4 || cost > 31) {
            error = "a bcrypt cost of 4 to 31";
            return "";
        }
        if (password.size() > 72) {
            error = "bcrypt reads only the first 72 bytes of a password; use yescrypt for a longer one";
            return "";
        }
    } else if (method == "sha512") {
        prefix = "$6$";
        if (cost == 0) cost = 500000;
    } else {
        error = "the method is yescrypt, bcrypt or sha512";
        return "";
    }
    char setting[CRYPT_GENSALT_OUTPUT_SIZE];
    if (!crypt_gensalt_rn(prefix, cost, nullptr, 0, setting, sizeof setting)) {
        error = std::string("libxcrypt refused the setting for ") + prefix + " with this cost";
        return "";
    }
    const auto data = std::make_unique<crypt_data>();
    std::string pw(password);
    const char* out = crypt_rn(pw.c_str(), setting, data.get(), static_cast<int>(sizeof *data));
    OPENSSL_cleanse(pw.data(), pw.size());
    if (!out || out[0] == '*') {
        error = "libxcrypt could not hash the password";
        return "";
    }
    return out;
}

bool equal(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

bool verify(std::string_view password, const std::string& hash) {
    if (hash.empty() || hash.front() == '!' || hash == "*") return false;
    // crypt_rn keeps its work in a 32 KB crypt_data, one per thread (zeroed once, as the
    // man page asks); the password goes in as a C string, which parse_basic made safe (no NUL).
    thread_local const std::unique_ptr<crypt_data> data = std::make_unique<crypt_data>();
    std::string pw(password);
    const char* out = crypt_rn(pw.c_str(), hash.c_str(), data.get(), static_cast<int>(sizeof *data));
    OPENSSL_cleanse(pw.data(), pw.size());
    if (!out || out[0] == '*') return false;
    return equal(out, hash);
}

namespace {
const unsigned char* process_key() noexcept {
    static const unsigned char* key = [] {
        static unsigned char bytes[32];
        RAND_bytes(bytes, sizeof bytes);
        return bytes;
    }();
    return key;
}
}  // namespace

// HMAC-SHA256 (RFC 2104) with the keyed inner and outer states made once per thread and
// copied per call: fetching and keying an EVP_MAC per call cost 640 ns, too much for a
// lookup that runs on the request path when a connection's memo misses.
namespace {
struct Hmac {
    EVP_MD_CTX* inner = EVP_MD_CTX_new();
    EVP_MD_CTX* outer = EVP_MD_CTX_new();
    EVP_MD_CTX* work = EVP_MD_CTX_new();
    Hmac() {
        unsigned char ipad[64], opad[64];
        const unsigned char* key = process_key();
        for (std::size_t i = 0; i < 64; ++i) {
            const unsigned char k = i < 32 ? key[i] : 0;
            ipad[i] = k ^ 0x36;
            opad[i] = k ^ 0x5c;
        }
        EVP_DigestInit_ex(inner, EVP_sha256(), nullptr);
        EVP_DigestUpdate(inner, ipad, 64);
        EVP_DigestInit_ex(outer, EVP_sha256(), nullptr);
        EVP_DigestUpdate(outer, opad, 64);
        OPENSSL_cleanse(ipad, sizeof ipad);
        OPENSSL_cleanse(opad, sizeof opad);
    }
    ~Hmac() {
        EVP_MD_CTX_free(inner);
        EVP_MD_CTX_free(outer);
        EVP_MD_CTX_free(work);
    }
};
}  // namespace

Key cache_key(std::string_view user, std::string_view hash, std::string_view password) noexcept {
    thread_local Hmac h;
    Key k{};
    unsigned char digest[32];
    unsigned len = 0;
    const auto put = [&](std::string_view s) {
        const unsigned char n[4] = {static_cast<unsigned char>(s.size() >> 24), static_cast<unsigned char>(s.size() >> 16),
                                    static_cast<unsigned char>(s.size() >> 8), static_cast<unsigned char>(s.size())};
        EVP_DigestUpdate(h.work, n, 4);
        EVP_DigestUpdate(h.work, s.data(), s.size());
    };
    if (!EVP_MD_CTX_copy_ex(h.work, h.inner)) return k;
    put(user);
    put(hash);
    put(password);
    EVP_DigestFinal_ex(h.work, digest, &len);
    if (!EVP_MD_CTX_copy_ex(h.work, h.outer)) return k;
    EVP_DigestUpdate(h.work, digest, sizeof digest);
    EVP_DigestFinal_ex(h.work, k.data(), &len);
    OPENSSL_cleanse(digest, sizeof digest);
    return k;
}

bool Cache::find(const Key& key, std::int64_t now) const noexcept {
    const std::size_t set = key[0] % kSets;
    for (std::size_t w = 0; w < kWays; ++w) {
        const Entry& e = entries_[set * kWays + w];
        if (e.until > now && CRYPTO_memcmp(e.key.data(), key.data(), key.size()) == 0) return true;
    }
    return false;
}

void Cache::insert(const Key& key, std::int64_t until) noexcept {
    const std::size_t set = key[0] % kSets;
    Entry* slot = nullptr;
    for (std::size_t w = 0; w < kWays; ++w) {
        Entry& e = entries_[set * kWays + w];
        if (e.until != 0 && e.key == key) {
            slot = &e;
            break;
        }
        if (!slot || e.until == 0 || (slot->until != 0 && e.stamp < slot->stamp)) slot = &e;
    }
    slot->key = key;
    slot->until = until;
    slot->stamp = ++clock_;
}

std::size_t Cache::size() const noexcept {
    return static_cast<std::size_t>(std::count_if(entries_.begin(), entries_.end(), [](const Entry& e) { return e.until != 0; }));
}

Verifier::Verifier(unsigned threads, std::size_t queue_limit) : limit_(queue_limit) {
    for (unsigned i = 0; i < std::max(1u, threads); ++i) threads_.emplace_back([this] { run(); });
}

Verifier::~Verifier() {
    {
        const std::lock_guard lock(mutex_);
        stopping_ = true;
    }
    wake_.notify_all();
    for (auto& t : threads_) t.join();
}

bool Verifier::submit(std::string password, std::string hash, std::function<void(bool)> done) {
    {
        const std::lock_guard lock(mutex_);
        if (stopping_ || queue_.size() >= limit_) {
            OPENSSL_cleanse(password.data(), password.size());
            return false;
        }
        queue_.push_back(Job{std::move(password), std::move(hash), std::move(done)});
    }
    wake_.notify_one();
    return true;
}

void Verifier::run() {
    for (;;) {
        Job job;
        {
            std::unique_lock lock(mutex_);
            wake_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
            if (queue_.empty()) return;  // stopping, nothing left
            job = std::move(queue_.front());
            queue_.pop_front();
        }
        const bool ok = verify(job.password, job.hash);
        OPENSSL_cleanse(job.password.data(), job.password.size());
        count_.fetch_add(1, std::memory_order_relaxed);
        job.done(ok);
    }
}

}  // namespace agensio::auth
