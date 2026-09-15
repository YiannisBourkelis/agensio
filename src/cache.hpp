// In-memory file cache.
//
// Two layers:
//  * FileCache   - one shared store per process. Owns the bytes. Guarded by a
//                  mutex that is only taken on a miss, an insert or an eviction.
//  * LocalIndex  - one per worker thread, no locking. Maps a key to a shared_ptr
//                  of an entry living in the shared store, so hot lookups never
//                  touch a lock and memory is never duplicated.
//
// Entries are immutable after construction except for a few atomics. Eviction or
// invalidation sets `stale`; local indexes drop stale entries lazily. A worker that
// is in the middle of writing an entry keeps it alive through its shared_ptr, so
// eviction can never free a buffer that is being sent.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace agensio {

struct CacheEntry {
    std::vector<char> data;
    std::string file_path;      // filesystem path, for revalidation
    std::string headers;        // "Content-Type: ..\r\nContent-Length: ..\r\nLast-Modified: ..\r\nETag: ..\r\n"
    std::string etag;           // including the quotes
    std::string last_modified;  // IMF-fixdate
    std::int64_t mtime = 0;
    std::uint64_t size = 0;

    std::atomic<std::int64_t> last_access{0};     // seconds since epoch
    std::atomic<std::int64_t> last_validated{0};  // seconds since epoch
    std::atomic<bool> stale{false};
};

struct CacheKey {
    const void* site = nullptr;   // identifies the virtual host
    std::string path;             // normalised request path
};

struct CacheKeyView {
    const void* site = nullptr;
    std::string_view path;
};

struct CacheKeyHash {
    using is_transparent = void;
    std::size_t operator()(const CacheKeyView& k) const noexcept {
        std::size_t h = std::hash<std::string_view>{}(k.path);
        return h ^ (reinterpret_cast<std::size_t>(k.site) * 0x9E3779B97F4A7C15ull);
    }
    std::size_t operator()(const CacheKey& k) const noexcept { return (*this)(CacheKeyView{k.site, k.path}); }
};

struct CacheKeyEq {
    using is_transparent = void;
    bool operator()(const CacheKeyView& a, const CacheKeyView& b) const noexcept { return a.site == b.site && a.path == b.path; }
    bool operator()(const CacheKey& a, const CacheKeyView& b) const noexcept { return a.site == b.site && a.path == b.path; }
    bool operator()(const CacheKeyView& a, const CacheKey& b) const noexcept { return a.site == b.site && a.path == b.path; }
    bool operator()(const CacheKey& a, const CacheKey& b) const noexcept { return a.site == b.site && a.path == b.path; }
};

using EntryPtr = std::shared_ptr<CacheEntry>;
using CacheMap = std::unordered_map<CacheKey, EntryPtr, CacheKeyHash, CacheKeyEq>;

class FileCache {
public:
    FileCache(std::size_t max_file_size, std::size_t max_total_size, double evict_fraction);

    std::size_t max_file_size() const noexcept { return max_file_size_; }

    // Returns the entry or nullptr.
    EntryPtr find(const CacheKeyView& key);

    // Inserts entry unless an entry for the key already exists (then that one is
    // returned). Evicts least recently used entries first if needed. Returns the
    // canonical entry for the key, or nullptr if the entry does not fit at all.
    EntryPtr insert(const CacheKeyView& key, EntryPtr entry);

    // Removes the entry for key if it is still `expected`. Marks it stale.
    void erase(const CacheKeyView& key, const CacheEntry* expected);

    std::size_t total_bytes() const noexcept { return total_.load(std::memory_order_relaxed); }
    std::size_t entry_count();

private:
    void evict_locked(std::size_t needed);

    const std::size_t max_file_size_;
    const std::size_t max_total_size_;
    const double evict_fraction_;
    std::mutex mutex_;
    CacheMap map_;
    std::atomic<std::size_t> total_{0};
};

class LocalIndex {
public:
    explicit LocalIndex(std::size_t max_entries = 8192) : max_entries_(max_entries) {}

    // Returns a pointer to the stored shared_ptr (no refcount traffic) or nullptr.
    // The pointer is invalidated by the next insert/erase on this index.
    const EntryPtr* find(const CacheKeyView& key) noexcept {
        auto it = map_.find(key);
        return it == map_.end() ? nullptr : &it->second;
    }
    void insert(const CacheKeyView& key, EntryPtr entry) {
        if (map_.size() >= max_entries_) map_.clear();
        map_.insert_or_assign(CacheKey{key.site, std::string(key.path)}, std::move(entry));
    }
    void erase(const CacheKeyView& key) noexcept {
        auto it = map_.find(key);
        if (it != map_.end()) map_.erase(it);
    }

private:
    const std::size_t max_entries_;
    CacheMap map_;
};

}  // namespace agensio
