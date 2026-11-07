#include "compress.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <random>
#include <vector>

#ifdef AGENSIO_HAS_ZLIB
#include <zlib.h>
#endif
#ifdef AGENSIO_HAS_ZSTD
#include <zstd.h>
#endif
#ifdef AGENSIO_HAS_BROTLI
#include <brotli/encode.h>
#endif

namespace agensio {

bool coding_built(Encoding e) noexcept {
    switch (e) {
        case Encoding::gzip:
#ifdef AGENSIO_HAS_ZLIB
            return true;
#else
            return false;
#endif
        case Encoding::zstd:
#ifdef AGENSIO_HAS_ZSTD
            return true;
#else
            return false;
#endif
        case Encoding::br:
#ifdef AGENSIO_HAS_BROTLI
            return true;
#else
            return false;
#endif
        case Encoding::identity: break;
    }
    return true;
}

std::string_view coding_package(Encoding e) noexcept {
    switch (e) {
        case Encoding::gzip: return "zlib1g-dev";
        case Encoding::zstd: return "libzstd-dev";
        case Encoding::br: return "libbrotli-dev";
        case Encoding::identity: break;
    }
    return "";
}

bool compress_whole(Encoding e, int level, std::string_view in, std::vector<char>& out) {
    out.clear();
    switch (e) {
        case Encoding::gzip: {
#ifdef AGENSIO_HAS_ZLIB
            // gzip framing (RFC 1952) through deflateInit2's windowBits + 16; window 2^15, memLevel 8:
            // zlib's own, the output every browser decodes.
            z_stream z{};
            if (deflateInit2(&z, std::clamp(level, 1, 9), Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return false;
            const uLong bound = deflateBound(&z, static_cast<uLong>(in.size()));
            out.resize(static_cast<std::size_t>(bound));
            z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));  // NOLINT: zlib's API, not written to
            z.avail_in = static_cast<uInt>(in.size());
            z.next_out = reinterpret_cast<Bytef*>(out.data());
            z.avail_out = static_cast<uInt>(out.size());
            const int rc = deflate(&z, Z_FINISH);
            const std::size_t produced = static_cast<std::size_t>(z.total_out);
            deflateEnd(&z);
            if (rc != Z_STREAM_END) {
                out.clear();
                return false;
            }
            out.resize(produced);
            return true;
#else
            return false;
#endif
        }
        case Encoding::zstd: {
#ifdef AGENSIO_HAS_ZSTD
            out.resize(ZSTD_compressBound(in.size()));
            const std::size_t n = ZSTD_compress(out.data(), out.size(), in.data(), in.size(), std::clamp(level, 1, 19));
            if (ZSTD_isError(n)) {
                out.clear();
                return false;
            }
            out.resize(n);
            return true;
#else
            return false;
#endif
        }
        case Encoding::br: {
#ifdef AGENSIO_HAS_BROTLI
            // The window from the input's size (BrotliEncoderCompress picks lgwin for a one-shot input,
            // at most BROTLI_MAX_WINDOW_BITS); the whole input is in memory, so no per-stream cost.
            std::size_t n = BrotliEncoderMaxCompressedSize(in.size());
            if (n == 0) return false;
            out.resize(n);
            if (!BrotliEncoderCompress(std::clamp(level, 0, 11), BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC, in.size(),
                                       reinterpret_cast<const std::uint8_t*>(in.data()), &n, reinterpret_cast<std::uint8_t*>(out.data()))) {
                out.clear();
                return false;
            }
            out.resize(n);
            return true;
#else
            return false;
#endif
        }
        case Encoding::identity: break;
    }
    return false;
}

unsigned padding_length() noexcept {
    // xorshift64* per thread, seeded once from the system; the length only has to be unguessable
    // enough that an attacker averaging an answer's length pays for every sample (design 7).
    thread_local std::uint64_t state = [] {
        std::random_device rd;
        std::uint64_t s = (static_cast<std::uint64_t>(rd()) << 32) ^ rd();
        return s ? s : 0x9E3779B97F4A7C15ULL;
    }();
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return static_cast<unsigned>((state * 0x2545F4914F6CDD1DULL >> 32) % (kPaddingMax + 1));
}

#ifdef AGENSIO_HAS_ZLIB
namespace {
// The zlib stream with the header it writes: FEXTRA carries the padding as one subfield (RFC 1952
// 2.3.1.1: SI1, SI2, a little-endian length, the bytes), zero bytes of a length drawn per answer.
struct GzipState {
    z_stream z{};
    gz_header header{};
    unsigned char extra[4 + kPaddingMax] = {'a', 'g', 0, 0};
};
}  // namespace
#endif

GzipContext::GzipContext() = default;

GzipContext::~GzipContext() {
#ifdef AGENSIO_HAS_ZLIB
    if (z_) {
        auto* st = static_cast<GzipState*>(z_);
        deflateEnd(&st->z);
        delete st;
    }
#endif
}

bool GzipContext::compress(int level, unsigned padding, std::string_view in, std::string& out) {
    out.clear();
    if (in.size() > kCompressWholeMax) return false;  // one deflate call: zlib's counts are 32-bit
#ifdef AGENSIO_HAS_ZLIB
    level = std::clamp(level, 1, 9);
    auto* st = static_cast<GzipState*>(z_);
    if (!st) {
        st = new GzipState;
        // gzip framing (RFC 1952): windowBits 15 + 16, the 32 KB window deflate has at most; memLevel 8, zlib's own.
        if (deflateInit2(&st->z, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
            delete st;
            return false;
        }
        st->header.os = 3;  // unix, what zlib writes on its own
        z_ = st;
        level_ = level;
    } else {
        if (deflateReset(&st->z) != Z_OK) return false;  // the stream fresh for this answer
        if (level != level_) {
            if (deflateParams(&st->z, level, Z_DEFAULT_STRATEGY) != Z_OK) return false;
            level_ = level;
        }
    }
    // The header set for every answer (a reset keeps the pointer, the fields are read at the first
    // deflate): the padding's subfield or no extra field at all, the other fields zlib's defaults.
    padding = std::min(padding, kPaddingMax);
    st->extra[2] = static_cast<unsigned char>(padding);
    st->header.extra = padding ? st->extra : nullptr;
    st->header.extra_len = padding ? 4 + padding : 0;
    if (deflateSetHeader(&st->z, &st->header) != Z_OK) return false;
    z_stream* z = &st->z;
    out.resize(static_cast<std::size_t>(deflateBound(z, static_cast<uLong>(in.size()))) + 2 + st->header.extra_len);
    z->next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));  // NOLINT: zlib's API, not written to
    z->avail_in = static_cast<uInt>(in.size());
    z->next_out = reinterpret_cast<Bytef*>(out.data());
    z->avail_out = static_cast<uInt>(out.size());
    const int rc = deflate(z, Z_FINISH);
    if (rc != Z_STREAM_END) {
        out.clear();
        deflateReset(z);
        return false;
    }
    out.resize(static_cast<std::size_t>(z->total_out));
    return true;
#else
    (void)level;
    (void)padding;
    (void)in;
    return false;
#endif
}

GzipContext& gzip_context() {
    thread_local GzipContext ctx;
    return ctx;
}

ZstdContext::ZstdContext() = default;

ZstdContext::~ZstdContext() {
#ifdef AGENSIO_HAS_ZSTD
    if (cctx_) ZSTD_freeCCtx(static_cast<ZSTD_CCtx*>(cctx_));
#endif
}

bool ZstdContext::compress(int level, unsigned padding, std::string_view in, std::string& out) {
    out.clear();
    if (in.size() > kCompressWholeMax) return false;
#ifdef AGENSIO_HAS_ZSTD
    level = std::clamp(level, 1, 19);
    auto* cctx = static_cast<ZSTD_CCtx*>(cctx_);
    if (!cctx) {
        cctx = ZSTD_createCCtx();
        if (!cctx) return false;
        // The window capped (design 3; zstd takes the input's own size when that is smaller, as it
        // is for every whole answer); the frame carries the content size, no checksum: the transport
        // has its own, and the browsers do not check it.
        if (ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, kZstdWindowLog)) ||
            ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_contentSizeFlag, 1)) ||
            ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 0)) ||
            ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level))) {
            ZSTD_freeCCtx(cctx);
            return false;
        }
        cctx_ = cctx;
        level_ = level;
    } else if (level != level_) {
        if (ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level))) return false;
        level_ = level;
    }
    // A skippable frame first (RFC 8878 3.1.2: magic 0x184D2A50, a little-endian length, the bytes;
    // every decoder of the content coding skips it), then the data frame; ZSTD_compress2 resets the
    // session and keeps the parameters.
    padding = std::min(padding, kPaddingMax);
    const std::size_t prefix = padding ? 8 + padding : 0;
    out.resize(prefix + ZSTD_compressBound(in.size()));
    if (padding) {
        static constexpr unsigned char kMagic[4] = {0x50, 0x2A, 0x4D, 0x18};
        std::memcpy(out.data(), kMagic, 4);
        const unsigned char len[4] = {static_cast<unsigned char>(padding), 0, 0, 0};
        std::memcpy(out.data() + 4, len, 4);
        std::memset(out.data() + 8, 0, padding);
    }
    const std::size_t n = ZSTD_compress2(cctx, out.data() + prefix, out.size() - prefix, in.data(), in.size());
    if (ZSTD_isError(n)) {
        out.clear();
        return false;
    }
    out.resize(prefix + n);
    return true;
#else
    (void)level;
    (void)padding;
    (void)in;
    return false;
#endif
}

ZstdContext& zstd_context() {
    thread_local ZstdContext ctx;
    return ctx;
}

#ifdef AGENSIO_HAS_BROTLI
namespace {
// brotli for one answer: an encoder made and freed here (its state is sized by the window), the
// window the smallest that holds the answer up to the cap (design 3; a window is 2^bits - 16 bytes),
// the padding as a metadata meta-block the decoder skips (RFC 7932 9.2), then the data, finished.
bool brotli_buffered(int quality, unsigned padding, std::string_view in, std::string& out) {
    int lgwin = BROTLI_MIN_WINDOW_BITS;
    while (lgwin < kBrotliWindowBits && (static_cast<std::size_t>(1) << lgwin) - 16 < in.size()) ++lgwin;
    BrotliEncoderState* enc = BrotliEncoderCreateInstance(nullptr, nullptr, nullptr);
    if (!enc) return false;
    bool ok = BrotliEncoderSetParameter(enc, BROTLI_PARAM_QUALITY, static_cast<std::uint32_t>(std::clamp(quality, 0, 11))) &&
              BrotliEncoderSetParameter(enc, BROTLI_PARAM_LGWIN, static_cast<std::uint32_t>(lgwin)) &&
              BrotliEncoderSetParameter(enc, BROTLI_PARAM_SIZE_HINT, static_cast<std::uint32_t>(std::min<std::size_t>(in.size(), 1u << 30)));
    std::size_t bound = BrotliEncoderMaxCompressedSize(in.size());
    if (bound == 0) ok = false;
    if (ok) out.resize(bound + 16 + padding);
    std::size_t avail_out = out.size();
    auto* next_out = reinterpret_cast<std::uint8_t*>(out.data());
    const auto more_room = [&] {  // the bound is for one shot of quality 2 and up; a stream may want more
        const std::size_t used = out.size() - avail_out;
        out.resize(out.size() * 2);
        next_out = reinterpret_cast<std::uint8_t*>(out.data()) + used;
        avail_out = out.size() - used;
    };
    if (ok && padding) {
        static constexpr std::uint8_t kZeros[kPaddingMax] = {};
        std::size_t avail_in = std::min(padding, kPaddingMax);
        const std::uint8_t* next_in = kZeros;
        while (ok && (avail_in > 0 || BrotliEncoderHasMoreOutput(enc))) {
            if (avail_out == 0) more_room();
            ok = BrotliEncoderCompressStream(enc, BROTLI_OPERATION_EMIT_METADATA, &avail_in, &next_in, &avail_out, &next_out, nullptr) == BROTLI_TRUE;
        }
    }
    std::size_t avail_in = in.size();
    const auto* next_in = reinterpret_cast<const std::uint8_t*>(in.data());
    while (ok && !BrotliEncoderIsFinished(enc)) {
        if (avail_out == 0) more_room();
        ok = BrotliEncoderCompressStream(enc, BROTLI_OPERATION_FINISH, &avail_in, &next_in, &avail_out, &next_out, nullptr) == BROTLI_TRUE;
    }
    BrotliEncoderDestroyInstance(enc);
    if (!ok) {
        out.clear();
        return false;
    }
    out.resize(out.size() - avail_out);
    return true;
}
}  // namespace
#endif

// ---- answers compressed in pieces ----

namespace {
// The windows of the event-stream encoders (StreamEncoder::Kind::events): zstd 2^15 with its two
// tables at 2^14, brotli 2^16, gzip 2^13 with memLevel 6.
constexpr int kZstdEventsWindowLog = 15;
constexpr int kZstdEventsTableLog = 14;
constexpr int kBrotliEventsWindowBits = 16;
constexpr int kGzipEventsWindowBits = 13;
constexpr int kGzipEventsMemLevel = 6;
// Free encoders a worker keeps for the next answer: enough for the common case of a few at once;
// the rest are freed when their answer ends.
constexpr std::size_t kPoolKeep = 4;

std::atomic<std::uint64_t> g_active{0}, g_started{0}, g_over_budget{0};
}  // namespace

struct StreamEncoder::Slot {
    Encoding coding = Encoding::identity;
    Kind kind = Kind::answer;
    int level = -1;
    std::size_t charge = 0;
    std::unique_ptr<char[]> in;
    std::size_t in_cap = 0;
    // What goes out before the coding's own bytes: a zstd skippable frame carrying the padding.
    unsigned char prefix[8 + kPaddingMax] = {};
    std::size_t prefix_len = 0, prefix_pos = 0;
    // brotli's padding, a metadata meta-block emitted before the data: the zero bytes still to give,
    // and whether the meta-block is still being written.
    std::size_t meta_left = 0;
    bool meta_open = false;
#ifdef AGENSIO_HAS_ZLIB
    z_stream z{};
    gz_header header{};
    unsigned char extra[4 + kPaddingMax] = {'a', 'g', 0, 0};
    bool z_ready = false;
#endif
#ifdef AGENSIO_HAS_ZSTD
    ZSTD_CCtx* cctx = nullptr;
#endif
#ifdef AGENSIO_HAS_BROTLI
    BrotliEncoderState* br = nullptr;
    std::size_t br_bytes = 0;  // what brotli holds, counted by br_alloc and br_free
#endif
    ~Slot() {
#ifdef AGENSIO_HAS_ZLIB
        if (z_ready) deflateEnd(&z);
#endif
#ifdef AGENSIO_HAS_ZSTD
        if (cctx) ZSTD_freeCCtx(cctx);
#endif
#ifdef AGENSIO_HAS_BROTLI
        if (br) BrotliEncoderDestroyInstance(br);
#endif
    }
};

#ifdef AGENSIO_HAS_BROTLI
namespace {
// brotli's allocator hooks, so the bytes an encoder holds are known exactly (StreamEncoder::memory):
// each block carries its size in front of it.
constexpr std::size_t kBrHeader = alignof(std::max_align_t);
void* br_alloc(void* opaque, std::size_t n) {
    auto* p = static_cast<unsigned char*>(std::malloc(n + kBrHeader));
    if (!p) return nullptr;
    std::memcpy(p, &n, sizeof n);
    static_cast<StreamEncoder::Slot*>(opaque)->br_bytes += n;
    return p + kBrHeader;
}
void br_free(void* opaque, void* block) {
    if (!block) return;
    auto* p = static_cast<unsigned char*>(block) - kBrHeader;
    std::size_t n = 0;
    std::memcpy(&n, p, sizeof n);
    static_cast<StreamEncoder::Slot*>(opaque)->br_bytes -= n;
    std::free(p);
}
}  // namespace
#endif

namespace {
struct EncoderPool {
    std::vector<std::unique_ptr<StreamEncoder::Slot>> free;
    std::size_t charged = 0;  // the encoders of answers in progress
    bool taken = false;       // one taken since the last idle check
};
EncoderPool& encoder_pool() {
    thread_local EncoderPool p;
    return p;
}
}  // namespace

std::size_t stream_charge(Encoding e, StreamEncoder::Kind kind, int level) noexcept {
    // KB per level, the input buffer included: the peaks StreamEncoder::memory reported over a 2 MB
    // stream flushed every 128 KB, plus about 6 %. Index: the level the keys allow (zstd 1 to 9,
    // brotli 1 to 6, gzip 1 to 9; config.cpp), clamped.
    static constexpr std::uint16_t kZstdAnswer[10] = {1500, 1500, 1700, 2240, 3600, 4150, 4150, 6850, 6850, 12300};
    static constexpr std::uint16_t kZstdEvents[10] = {350, 350, 350, 410, 410, 410, 410, 410, 410, 410};
    static constexpr std::uint16_t kBrAnswer[7] = {160, 160, 1390, 1390, 2320, 2900, 3980};
    static constexpr std::uint16_t kBrEvents[7] = {110, 110, 930, 930, 1860, 1860, 1860};
    // Through a pointer and a plain index: GCC 14.2 at -O2 gave kZstdAnswer[1] for every level of
    // `(events ? kZstdEvents : kZstdAnswer)[std::clamp(level, 1, 9)]` (and the program crashed at -O0;
    // found by test_stream_encoder, 2026-11-07).
    const bool events = kind == StreamEncoder::Kind::events;
    std::size_t kb = 0;
    switch (e) {
        case Encoding::gzip: kb = events ? 96 : 350; break;
        case Encoding::zstd: {
            const std::uint16_t* t = events ? kZstdEvents : kZstdAnswer;
            const int i = level < 1 ? 1 : level > 9 ? 9 : level;
            kb = t[i];
            break;
        }
        case Encoding::br: {
            const std::uint16_t* t = events ? kBrEvents : kBrAnswer;
            const int i = level < 1 ? 1 : level > 6 ? 6 : level;
            kb = t[i];
            break;
        }
        case Encoding::identity: break;
    }
    return kb * 1024;
}

StreamEncoder::~StreamEncoder() {
    if (!slot_) return;
    EncoderPool& p = encoder_pool();
    p.charged -= std::min(p.charged, slot_->charge);
    g_active.fetch_sub(1, std::memory_order_relaxed);
#ifdef AGENSIO_HAS_BROTLI
    if (slot_->br) {  // no reset in brotli: made again for the next answer
        BrotliEncoderDestroyInstance(slot_->br);
        slot_->br = nullptr;
    }
#endif
    if (p.free.size() < kPoolKeep) p.free.emplace_back(slot_);
    else delete slot_;
    slot_ = nullptr;
}

StreamEncoder& StreamEncoder::operator=(StreamEncoder&& o) noexcept {
    if (this != &o) {
        this->~StreamEncoder();
        slot_ = o.slot_;
        o.slot_ = nullptr;
    }
    return *this;
}

// What an encoder holds now, as its library reports it, the input buffer included.
static std::size_t slot_memory(const StreamEncoder::Slot& s) noexcept {
    std::size_t n = s.in_cap;
    switch (s.coding) {
        case Encoding::gzip: {
            // zlib.h's own figure for deflate: (1 << (windowBits + 2)) + (1 << (memLevel + 9)), plus its state.
            const bool events = s.kind == StreamEncoder::Kind::events;
            const int bits = events ? kGzipEventsWindowBits : 15, mem = events ? kGzipEventsMemLevel : 8;
            n += (std::size_t{1} << (bits + 2)) + (std::size_t{1} << (mem + 9)) + 6 * 1024;
            break;
        }
        case Encoding::zstd:
#ifdef AGENSIO_HAS_ZSTD
            n += s.cctx ? ZSTD_sizeof_CCtx(s.cctx) : 0;
#endif
            break;
        case Encoding::br:
#ifdef AGENSIO_HAS_BROTLI
            n += s.br_bytes;
#endif
            break;
        case Encoding::identity: break;
    }
    return n;
}

bool StreamEncoder::begin(Encoding e, int level, Kind kind, unsigned padding, std::uint64_t size) {
    if (slot_ || e == Encoding::identity || !coding_built(e)) return false;
    level = e == Encoding::br ? std::clamp(level, 0, 11) : e == Encoding::zstd ? std::clamp(level, 1, 19) : std::clamp(level, 1, 9);
    EncoderPool& p = encoder_pool();
    std::size_t charge = stream_charge(e, kind, level);
    if (p.charged + charge > kStreamBudget) {
        g_over_budget.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    // A kept encoder of the same coding, kind and level: zstd keeps the workspace its level grew, so
    // one kept from level 9 would hold 11 MB for a level-3 answer.
    std::unique_ptr<Slot> s;
    for (auto it = p.free.begin(); it != p.free.end(); ++it)
        if ((*it)->coding == e && (*it)->kind == kind && (*it)->level == level) {
            s = std::move(*it);
            p.free.erase(it);
            break;
        }
    if (!s) {
        s = std::make_unique<Slot>();
        s->coding = e;
        s->kind = kind;
        s->in_cap = kind == Kind::events ? kPieceEvents : kPieceAnswer;
        s->in = std::make_unique<char[]>(s->in_cap);
    }
    padding = std::min(padding, kPaddingMax);
    s->prefix_len = s->prefix_pos = 0;
    s->meta_left = 0;
    s->meta_open = false;
    switch (e) {
        case Encoding::gzip: {
#ifdef AGENSIO_HAS_ZLIB
            level = std::clamp(level, 1, 9);
            if (!s->z_ready) {
                const int bits = kind == Kind::events ? kGzipEventsWindowBits : 15;
                const int mem = kind == Kind::events ? kGzipEventsMemLevel : 8;
                if (deflateInit2(&s->z, level, Z_DEFLATED, bits + 16, mem, Z_DEFAULT_STRATEGY) != Z_OK) return false;
                s->z_ready = true;
                s->level = level;
                s->header.os = 3;
            } else {
                if (deflateReset(&s->z) != Z_OK) return false;
                if (level != s->level) {
                    if (deflateParams(&s->z, level, Z_DEFAULT_STRATEGY) != Z_OK) return false;
                    s->level = level;
                }
            }
            s->extra[2] = static_cast<unsigned char>(padding);
            s->header.extra = padding ? s->extra : nullptr;
            s->header.extra_len = padding ? 4 + padding : 0;
            if (deflateSetHeader(&s->z, &s->header) != Z_OK) return false;
            break;
#else
            return false;
#endif
        }
        case Encoding::zstd: {
#ifdef AGENSIO_HAS_ZSTD
            level = std::clamp(level, 1, 19);
            if (!s->cctx) {
                s->cctx = ZSTD_createCCtx();
                if (!s->cctx) return false;
                const bool events = kind == Kind::events;
                if (ZSTD_isError(ZSTD_CCtx_setParameter(s->cctx, ZSTD_c_checksumFlag, 0)) ||
                    ZSTD_isError(ZSTD_CCtx_setParameter(s->cctx, ZSTD_c_compressionLevel, level)) ||
                    ZSTD_isError(ZSTD_CCtx_setParameter(s->cctx, ZSTD_c_windowLog, events ? kZstdEventsWindowLog : kZstdWindowLog)) ||
                    (events && (ZSTD_isError(ZSTD_CCtx_setParameter(s->cctx, ZSTD_c_hashLog, kZstdEventsTableLog)) ||
                                ZSTD_isError(ZSTD_CCtx_setParameter(s->cctx, ZSTD_c_chainLog, kZstdEventsTableLog)))))
                    return false;
                s->level = level;
            } else {
                if (ZSTD_isError(ZSTD_CCtx_reset(s->cctx, ZSTD_reset_session_only))) return false;
                if (level != s->level) {
                    if (ZSTD_isError(ZSTD_CCtx_setParameter(s->cctx, ZSTD_c_compressionLevel, level))) return false;
                    s->level = level;
                }
            }
            // A known size makes zstd size its tables to it and puts it in the frame (RFC 8878 3.1.1.1).
            if (size && ZSTD_isError(ZSTD_CCtx_setPledgedSrcSize(s->cctx, size))) return false;
            if (padding) {  // a skippable frame first (RFC 8878 3.1.2), as compress_buffered writes it
                static constexpr unsigned char kMagic[4] = {0x50, 0x2A, 0x4D, 0x18};
                std::memcpy(s->prefix, kMagic, 4);
                s->prefix[4] = static_cast<unsigned char>(padding);
                s->prefix[5] = s->prefix[6] = s->prefix[7] = 0;
                std::memset(s->prefix + 8, 0, padding);
                s->prefix_len = 8 + padding;
            }
            break;
#else
            return false;
#endif
        }
        case Encoding::br: {
#ifdef AGENSIO_HAS_BROTLI
            int lgwin = kind == Kind::events ? kBrotliEventsWindowBits : kBrotliWindowBits;
            if (size) {  // a known size: the smallest window that holds it
                int w = BROTLI_MIN_WINDOW_BITS;
                while (w < lgwin && (static_cast<std::uint64_t>(1) << w) - 16 < size) ++w;
                lgwin = w;
            }
            s->br = BrotliEncoderCreateInstance(br_alloc, br_free, s.get());
            if (!s->br) return false;
            if (!BrotliEncoderSetParameter(s->br, BROTLI_PARAM_QUALITY, static_cast<std::uint32_t>(std::clamp(level, 0, 11))) ||
                !BrotliEncoderSetParameter(s->br, BROTLI_PARAM_LGWIN, static_cast<std::uint32_t>(lgwin)) ||
                (size && !BrotliEncoderSetParameter(s->br, BROTLI_PARAM_SIZE_HINT, static_cast<std::uint32_t>(std::min<std::uint64_t>(size, 1u << 30))))) {
                BrotliEncoderDestroyInstance(s->br);
                s->br = nullptr;
                return false;
            }
            s->meta_left = padding;
            s->meta_open = padding > 0;
            s->level = level;
            break;
#else
            return false;
#endif
        }
        case Encoding::identity: return false;
    }
    // What the encoder already holds, if more (a kept one): the budget counts the larger.
    charge = std::max(charge, slot_memory(*s));
    s->charge = charge;
    p.charged += charge;
    p.taken = true;
    g_active.fetch_add(1, std::memory_order_relaxed);
    g_started.fetch_add(1, std::memory_order_relaxed);
    slot_ = s.release();
    return true;
}

bool StreamEncoder::run(Op op, const char*& in, std::size_t& in_len, char*& out, std::size_t& out_len, bool& done) {
    done = false;
    if (!slot_) return false;
    Slot& s = *slot_;
    // What goes before the data: the skippable frame of the padding (zstd).
    if (s.prefix_pos < s.prefix_len) {
        const std::size_t n = std::min(s.prefix_len - s.prefix_pos, out_len);
        std::memcpy(out, s.prefix + s.prefix_pos, n);
        s.prefix_pos += n;
        out += n;
        out_len -= n;
        if (s.prefix_pos < s.prefix_len) return true;  // no room yet
    }
    switch (s.coding) {
        case Encoding::gzip: {
#ifdef AGENSIO_HAS_ZLIB
            s.z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in));  // NOLINT: zlib's API, not written to
            s.z.avail_in = static_cast<uInt>(in_len);  // a piece, at most kPieceAnswer
            s.z.next_out = reinterpret_cast<Bytef*>(out);
            s.z.avail_out = static_cast<uInt>(std::min<std::size_t>(out_len, UINT32_MAX));
            const int flush = op == Op::process ? Z_NO_FLUSH : op == Op::flush ? Z_SYNC_FLUSH : Z_FINISH;
            const int rc = deflate(&s.z, flush);
            if (rc == Z_STREAM_ERROR) return false;  // Z_BUF_ERROR: no progress possible now, not an error
            const std::size_t used = in_len - s.z.avail_in, made = static_cast<std::size_t>(out_len - s.z.avail_out);
            in += used;
            in_len -= used;
            out += made;
            out_len -= made;
            // zlib: a flush is complete when it returns with room left (zlib.h, deflate()).
            if (op == Op::process) done = in_len == 0;
            else if (op == Op::flush) done = in_len == 0 && (s.z.avail_out != 0 || rc == Z_BUF_ERROR);
            else done = rc == Z_STREAM_END;
            return true;
#else
            return false;
#endif
        }
        case Encoding::zstd: {
#ifdef AGENSIO_HAS_ZSTD
            ZSTD_inBuffer ib{in, in_len, 0};
            ZSTD_outBuffer ob{out, out_len, 0};
            const ZSTD_EndDirective d = op == Op::process ? ZSTD_e_continue : op == Op::flush ? ZSTD_e_flush : ZSTD_e_end;
            const std::size_t rem = ZSTD_compressStream2(s.cctx, &ob, &ib, d);
            if (ZSTD_isError(rem)) return false;
            in += ib.pos;
            in_len -= ib.pos;
            out += ob.pos;
            out_len -= ob.pos;
            done = in_len == 0 && (op == Op::process || rem == 0);
            return true;
#else
            return false;
#endif
        }
        case Encoding::br: {
#ifdef AGENSIO_HAS_BROTLI
            std::size_t avail_out = out_len;
            auto* next_out = reinterpret_cast<std::uint8_t*>(out);
            // The padding first, as one metadata meta-block (RFC 7932 9.2), completed before any data:
            // brotli takes that operation's input whole and must be called with it until it is out.
            if (s.meta_open) {
                static constexpr std::uint8_t kZeros[kPaddingMax] = {};
                std::size_t avail_in = s.meta_left;
                const std::uint8_t* next_in = kZeros;
                if (!BrotliEncoderCompressStream(s.br, BROTLI_OPERATION_EMIT_METADATA, &avail_in, &next_in, &avail_out, &next_out, nullptr))
                    return false;
                s.meta_left = avail_in;
                s.meta_open = s.meta_left > 0 || BrotliEncoderHasMoreOutput(s.br);
                out = reinterpret_cast<char*>(next_out);
                out_len = avail_out;
                if (s.meta_open) return true;  // no room yet
            }
            std::size_t avail_in = in_len;
            const auto* next_in = reinterpret_cast<const std::uint8_t*>(in);
            const BrotliEncoderOperation bo =
                op == Op::process ? BROTLI_OPERATION_PROCESS : op == Op::flush ? BROTLI_OPERATION_FLUSH : BROTLI_OPERATION_FINISH;
            if (!BrotliEncoderCompressStream(s.br, bo, &avail_in, &next_in, &avail_out, &next_out, nullptr)) return false;
            in = reinterpret_cast<const char*>(next_in);
            in_len = avail_in;
            out = reinterpret_cast<char*>(next_out);
            out_len = avail_out;
            if (op == Op::process) done = in_len == 0;
            else if (op == Op::flush) done = in_len == 0 && !BrotliEncoderHasMoreOutput(s.br);
            else done = BrotliEncoderIsFinished(s.br) == BROTLI_TRUE;
            return true;
#else
            return false;
#endif
        }
        case Encoding::identity: break;
    }
    return false;
}

char* StreamEncoder::input() const noexcept { return slot_ ? slot_->in.get() : nullptr; }

std::size_t StreamEncoder::memory() const noexcept { return slot_ ? slot_memory(*slot_) : 0; }
std::size_t StreamEncoder::input_capacity() const noexcept { return slot_ ? slot_->in_cap : 0; }

StreamCounts stream_counts() noexcept {
    return {g_active.load(std::memory_order_relaxed), g_started.load(std::memory_order_relaxed),
            g_over_budget.load(std::memory_order_relaxed)};
}

bool release_idle_encoders() noexcept {
    EncoderPool& p = encoder_pool();
    if (p.taken) {
        p.taken = false;
        return false;
    }
    if (p.free.empty()) return false;
    p.free.clear();
    return true;
}

bool compress_buffered(Encoding e, int level, unsigned padding, std::string_view in, std::string& out) {
    out.clear();
    if (in.size() > kCompressWholeMax) return false;
    switch (e) {
        case Encoding::gzip: return gzip_context().compress(level, padding, in, out);
        case Encoding::zstd: return zstd_context().compress(level, padding, in, out);
        case Encoding::br:
#ifdef AGENSIO_HAS_BROTLI
            return brotli_buffered(level, padding, in, out);
#else
            return false;
#endif
        case Encoding::identity: break;
    }
    return false;
}

}  // namespace agensio
