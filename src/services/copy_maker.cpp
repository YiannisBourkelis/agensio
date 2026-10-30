#include "services/copy_maker.hpp"

#include <string_view>
#include <vector>

#include "compress.hpp"
#include "handlers/static.hpp"
#include "http2/hpack.hpp"
#include "http3/qpack.hpp"

namespace agensio {

CopyMaker::CopyMaker(FileCache& cache, std::size_t max_size, std::size_t queue_limit)
    : cache_(cache), max_size_(max_size), limit_(queue_limit), thread_([this] { run(); }) {}

CopyMaker::~CopyMaker() {
    {
        const std::lock_guard lock(mutex_);
        stopping_ = true;
    }
    wake_.notify_all();
    thread_.join();
}

bool CopyMaker::ask(EntryPtr entry) {
    if (!entry || entry->descriptor_only || entry->data.empty() || entry->data.size() > max_size_ || entry->has_variants()) return false;
    {
        const std::lock_guard lock(mutex_);
        if (stopping_) return false;
        if (queue_.size() >= limit_) {
            queue_full_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        queue_.push_back(std::move(entry));
    }
    wake_.notify_one();
    return true;
}

CopyMaker::Counts CopyMaker::counts() const noexcept {
    return {made_.load(std::memory_order_relaxed), bytes_.load(std::memory_order_relaxed), queue_full_.load(std::memory_order_relaxed),
            budget_refused_.load(std::memory_order_relaxed), failed_.load(std::memory_order_relaxed)};
}

void CopyMaker::run() {
    for (;;) {
        EntryPtr entry;
        {
            std::unique_lock lock(mutex_);
            wake_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
            if (stopping_) return;
            entry = std::move(queue_.front());
            queue_.pop_front();
        }
        make(entry);
    }
}

// One copy per coding the build has, brotli 11 and gzip 9 (the smallest output: paid once), each
// an entry of its own as a twin is, with the file's type and dates, its own strong ETag (the
// file's tag plus the coding, so a copy and a twin never share one), the coding's headers and
// Vary, no descriptor. Attached with a release store once complete: a worker that sees the
// pointer sees the entry whole (the hit path reads it with an acquire, as it reads the twins).
void CopyMaker::make(const EntryPtr& entry) {
    if (entry->stale.load(std::memory_order_acquire)) return;  // evicted since it was asked
    struct Copy {
        Encoding coding;
        int level;
    };
    static constexpr Copy kCopies[] = {{Encoding::br, 11}, {Encoding::gzip, 9}};
    std::vector<char> out;
    const std::string_view in(entry->data.data(), entry->data.size());
    for (const Copy& c : kCopies) {
        if (!coding_built(c.coding)) continue;
        if (!compress_whole(c.coding, c.level, in, out)) {
            failed_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        if (out.size() >= in.size()) continue;  // no gain: the file goes as it is (binary mislabelled as text)
        auto copy = std::make_shared<CacheEntry>();
        copy->data = std::move(out);
        copy->made = true;
        FileInfo fi;
        fi.mtime = entry->mtime;
        fi.size = static_cast<std::uint64_t>(copy->data.size());
        fi.is_regular = true;
        StaticHandler::fill_copy(*copy, *entry, fi, c.coding);
        const std::size_t n = copy->data.size();
        // Charged and attached under the cache's lock, the pointer released last: a worker's
        // acquire of it sees the copy complete, and the budget never disagrees with bytes_of.
        if (!cache_.attach(*entry, std::move(copy), c.coding == Encoding::br)) {
            budget_refused_.fetch_add(1, std::memory_order_relaxed);
            return;  // the budget, or the entry evicted meanwhile
        }
        made_.fetch_add(1, std::memory_order_relaxed);
        bytes_.fetch_add(n, std::memory_order_relaxed);
        out = std::vector<char>();
    }
}

}  // namespace agensio
