// Basic authentication, the core (2026-10-08, docs/design-site-operations.md section 25): the
// user file, the Authorization value, verification through libxcrypt, the cache of successes.
// Built only with libxcrypt (crypt_rn) and OpenSSL (HMAC-SHA256, the process key); a build
// without them refuses a configuration that asks for a password (config.cpp).
//
// The slow part is verify(): a deliberate tens of milliseconds per hash. It never runs on a
// worker's loop (the request path hands it to a pool); what runs there is parse_basic, a
// connection's memo of the last verified value, and Cache::find over an HMAC.
#pragma once

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <string>
#include <string_view>
#include <vector>

namespace agensio::auth {

struct User {
    std::string name;
    std::string hash;          // as in the file ("$y$...", "$2b$...")
    std::int64_t expires = 0;  // refused from this time on (00:00 UTC of the `expires` date); 0: never
    std::string note;          // whose login it is (`note=`), shown to the owner and in the log lines
    bool locked = false;       // the hash is "!" or "*" (or starts with "!"): never verifies
};

// The user file: `name:hash[:expires=YYYY-MM-DD][:note=text to the end of the line]`, `#`
// comments, blank lines. "" or the first error with its line number and what to do. An
// htpasswd file made with `htpasswd -B` reads as is.
std::string parse_users(std::string_view text, std::vector<User>& out);

// Why a stored hash is refused, with the command to make an accepted one; "" when accepted
// (yescrypt, gost-yescrypt, scrypt, bcrypt $2b$ $2y$ $2a$, sha512crypt, sha256crypt, a lock).
std::string refused_hash(std::string_view hash);

// An `Authorization` value. none: not the Basic scheme (absent or another scheme);
// malformed: Basic but not usable (bad base64, no colon, an empty user, a control character,
// longer than 255 + 512 bytes). The views point into `scratch`.
enum class Parsed { none, ok, malformed };
struct Credentials {
    std::string_view user;
    std::string_view password;
};
Parsed parse_basic(std::string_view value, std::string& scratch, Credentials& out);

// The password against a stored hash, through crypt_rn with this thread's own state;
// compared in constant time. Slow by design: never on a worker's loop.
bool verify(std::string_view password, const std::string& hash);

// A new hash of `password` for a user file: method "yescrypt" (the default, libxcrypt's cost
// unless `cost` says otherwise), "bcrypt" (cost 4 to 31, default 12) or "sha512" (rounds,
// default 500,000). "" and `error` when the method, the cost or the password is refused.
std::string make_hash(std::string_view password, std::string_view method, unsigned long cost, std::string& error);

// Constant-time equality of two byte strings of the same length (false when they differ).
bool equal(std::string_view a, std::string_view b) noexcept;

// The cache key: HMAC-SHA256, under a random key made once per process, of the length-prefixed
// user, the stored hash and the password. The stored hash makes a changed password or another
// area with the same user name a miss; the password never stays in memory.
using Key = std::array<unsigned char, 32>;
Key cache_key(std::string_view user, std::string_view hash, std::string_view password) noexcept;

// One worker's verified logins (no lock: a worker's own). 256 sets of four entries; the
// oldest entry of a set gives way. Successes only, each until its time.
class Cache {
public:
    static constexpr std::size_t kSets = 256;
    static constexpr std::size_t kWays = 4;
    static constexpr std::size_t kCapacity = kSets * kWays;
    bool find(const Key& key, std::int64_t now) const noexcept;
    void insert(const Key& key, std::int64_t until) noexcept;
    std::size_t size() const noexcept;

private:
    struct Entry {
        Key key{};
        std::int64_t until = 0;  // 0: empty
        std::uint64_t stamp = 0; // insertion order, for the oldest of a set
    };
    std::array<Entry, kCapacity> entries_{};
    std::uint64_t clock_ = 0;
};

// The pool that runs verify() off the workers' loops: a few threads and a bounded queue. A
// job's completion runs on the pool's thread with the result; the caller posts it back to its
// worker. The password is wiped once checked. `verifications()` counts the hashes run, which
// `status` reports and the tests read to prove one hash per login, none per request.
class Verifier {
public:
    explicit Verifier(unsigned threads, std::size_t queue_limit = 256);
    ~Verifier();
    Verifier(const Verifier&) = delete;
    Verifier& operator=(const Verifier&) = delete;
    // False, and nothing queued, when the queue is full: the caller answers 503.
    bool submit(std::string password, std::string hash, std::function<void(bool)> done);
    std::uint64_t verifications() const noexcept { return count_.load(std::memory_order_relaxed); }

private:
    struct Job {
        std::string password;
        std::string hash;
        std::function<void(bool)> done;
    };
    void run();
    std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<Job> queue_;
    std::size_t limit_;
    bool stopping_ = false;
    std::atomic<std::uint64_t> count_{0};
    std::vector<std::thread> threads_;
};

}  // namespace agensio::auth
