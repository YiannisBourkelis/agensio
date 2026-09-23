#include "cache.hpp"

#include <algorithm>

namespace agensio {

FileCache::FileCache(std::size_t max_file_size, std::size_t max_total_size, double evict_fraction,
                     std::size_t max_open_files)
    : max_file_size_(max_file_size),
      max_total_size_(max_total_size),
      evict_fraction_(evict_fraction),
      max_open_files_(max_open_files) {}

namespace {
inline std::size_t files_of(const CacheEntry& e) noexcept { return e.descriptor_only ? 1 : 0; }
}  // namespace

EntryPtr FileCache::find(const CacheKeyView& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(key);
    return it == map_.end() ? nullptr : it->second;
}

EntryPtr FileCache::insert(const CacheKeyView& key, EntryPtr entry) {
    const std::size_t bytes = bytes_of(*entry);
    const std::size_t files = files_of(*entry);
    if (entry->data.size() > max_file_size_ || bytes > max_total_size_ || files > max_open_files_) return nullptr;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it != map_.end()) return it->second;
    if (total_.load(std::memory_order_relaxed) + bytes > max_total_size_ ||
        open_.load(std::memory_order_relaxed) + files > max_open_files_)
        evict_locked(bytes, files);
    total_.fetch_add(bytes, std::memory_order_relaxed);
    open_.fetch_add(files, std::memory_order_relaxed);
    map_.emplace(CacheKey{key.scope, std::string(key.path)}, entry);
    return entry;
}

void FileCache::erase(const CacheKeyView& key, const CacheEntry* expected) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it == map_.end() || it->second.get() != expected) return;
    it->second->stale.store(true, std::memory_order_release);
    total_.fetch_sub(bytes_of(*it->second), std::memory_order_relaxed);
    open_.fetch_sub(files_of(*it->second), std::memory_order_relaxed);
    map_.erase(it);
}

std::size_t FileCache::entry_count() {
    std::lock_guard<std::mutex> lock(mutex_);
    return map_.size();
}

// Called with mutex_ held. Frees at least `needed_bytes` bytes and `needed_files`
// descriptors plus evict_fraction_ of each budget that is under pressure, oldest access
// first. An entry is only evicted if it contributes to a budget still being freed, so
// byte pressure never drops descriptor entries and vice versa.
void FileCache::evict_locked(std::size_t needed_bytes, std::size_t needed_files) {
    struct Candidate {
        CacheMap::iterator it;
        std::int64_t last_access;
    };
    std::vector<Candidate> candidates;
    candidates.reserve(map_.size());
    for (auto it = map_.begin(); it != map_.end(); ++it)
        candidates.push_back({it, it->second->last_access.load(std::memory_order_relaxed)});
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) { return a.last_access < b.last_access; });

    const bool want_bytes = needed_bytes > 0;
    const bool want_files = needed_files > 0;
    const std::size_t target_bytes = static_cast<std::size_t>(max_total_size_ * (1.0 - evict_fraction_));
    const std::size_t target_files = static_cast<std::size_t>(max_open_files_ * (1.0 - evict_fraction_));
    std::size_t total = total_.load(std::memory_order_relaxed);
    std::size_t open = open_.load(std::memory_order_relaxed);
    for (auto& c : candidates) {
        const bool bytes_ok = !want_bytes || (total + needed_bytes <= max_total_size_ && total <= target_bytes);
        const bool files_ok = !want_files || (open + needed_files <= max_open_files_ && open <= target_files);
        if (bytes_ok && files_ok) break;
        const std::size_t cb = bytes_of(*c.it->second);
        const std::size_t cf = files_of(*c.it->second);
        if (!((!bytes_ok && cb > 0) || (!files_ok && cf > 0))) continue;
        c.it->second->stale.store(true, std::memory_order_release);
        total -= cb;
        open -= cf;
        map_.erase(c.it);
    }
    total_.store(total, std::memory_order_relaxed);
    open_.store(open, std::memory_order_relaxed);
}

}  // namespace agensio
