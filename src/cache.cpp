#include "cache.hpp"

#include <algorithm>

namespace agensio {

FileCache::FileCache(std::size_t max_file_size, std::size_t max_total_size, double evict_fraction)
    : max_file_size_(max_file_size), max_total_size_(max_total_size), evict_fraction_(evict_fraction) {}

EntryPtr FileCache::find(const CacheKeyView& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(key);
    return it == map_.end() ? nullptr : it->second;
}

EntryPtr FileCache::insert(const CacheKeyView& key, EntryPtr entry) {
    const std::size_t bytes = entry->data.size();
    if (bytes > max_file_size_ || bytes > max_total_size_) return nullptr;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it != map_.end()) return it->second;
    if (total_.load(std::memory_order_relaxed) + bytes > max_total_size_) evict_locked(bytes);
    total_.fetch_add(bytes, std::memory_order_relaxed);
    map_.emplace(CacheKey{key.site, std::string(key.path)}, entry);
    return entry;
}

void FileCache::erase(const CacheKeyView& key, const CacheEntry* expected) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = map_.find(key);
    if (it == map_.end() || it->second.get() != expected) return;
    it->second->stale.store(true, std::memory_order_release);
    total_.fetch_sub(it->second->data.size(), std::memory_order_relaxed);
    map_.erase(it);
}

std::size_t FileCache::entry_count() {
    std::lock_guard<std::mutex> lock(mutex_);
    return map_.size();
}

// Called with mutex_ held. Frees at least `needed` bytes plus evict_fraction_ of
// the cache, oldest access first.
void FileCache::evict_locked(std::size_t needed) {
    struct Candidate { CacheMap::iterator it; std::int64_t last_access; };
    std::vector<Candidate> candidates;
    candidates.reserve(map_.size());
    for (auto it = map_.begin(); it != map_.end(); ++it)
        candidates.push_back({it, it->second->last_access.load(std::memory_order_relaxed)});
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) { return a.last_access < b.last_access; });

    const std::size_t target = static_cast<std::size_t>(max_total_size_ * (1.0 - evict_fraction_));
    std::size_t total = total_.load(std::memory_order_relaxed);
    for (auto& c : candidates) {
        if (total + needed <= max_total_size_ && total <= target) break;
        c.it->second->stale.store(true, std::memory_order_release);
        total -= c.it->second->data.size();
        map_.erase(c.it);
    }
    total_.store(total, std::memory_order_relaxed);
}

}  // namespace agensio
