// Compression behind response_compression (docs/design-compression.md): one-shot encoders for
// the copies of cached files made once at fill (brotli 11, gzip 9), and `coding_built` for what
// this binary offers. Each library optional at build time (CMakeLists.txt: AGENSIO_HAS_ZLIB,
// AGENSIO_HAS_ZSTD, AGENSIO_HAS_BROTLI); a coding the build lacks is refused where it is named.
// StreamEncoder for answers compressed in pieces (step 6). Levels and windows are set explicitly
// here, never left to a library's default, so a library upgrade never changes what agensio sends
// (the Traefik regression of 2026).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "handlers/encoding.hpp"

namespace agensio {

// The most one call compresses (the callers pass at most 64 KB, docs/design-compression.md 6).
inline constexpr std::size_t kCompressWholeMax = 256u * 1024 * 1024;

// Whether this binary can produce the coding.
bool coding_built(Encoding e) noexcept;
// The package that gives it, for a refusal ("libzstd-dev").
std::string_view coding_package(Encoding e) noexcept;

// `in` compressed whole with the coding at `level`, appended to `out` (cleared first). False
// when the build lacks the coding or the encoder fails; `out` is then empty. For the copies made
// once: brotli at `level` with the window the library picks for the input (at most 2^22 for a
// file of a few MB; the whole input is in memory, so the window costs nothing per stream), gzip
// at `level`. zstd is not made for files (every zstd browser takes br).
bool compress_whole(Encoding e, int level, std::string_view in, std::vector<char>& out);

// The windows of the encoders behind answers compressed per request, fixed (docs/design-compression.md
// 3): the memory a stream holds against under 1 % of output; a setting here is a way to run out of
// memory. zstd 2^19 (the content coding's decoders take up to 2^23, RFC 8878 7.1), brotli 2^18, gzip
// 2^15 (deflate's most). An answer smaller than the window gets a window of its own size.
inline constexpr int kZstdWindowLog = 19;
inline constexpr int kBrotliWindowBits = 18;

// The padding of every answer compressed per request (docs/design-compression.md 7): up to kPaddingMax
// bytes the coding carries where every decoder skips them (gzip's FEXTRA field, RFC 1952 2.3.1.1; a
// zstd skippable frame, RFC 8878 3.1.2; a brotli metadata meta-block, RFC 7932 9.2), so one answer's
// length differs from request to request and an attacker measuring it pays for every sample (the
// Heal the Breach mitigation; Rails' Thruster pads up to 32 bytes by default, Django up to 100).
// What protects is the spread of the random part, so the bound is the padding's own, 32, and the
// coding's framing (6 bytes for gzip, 8 for zstd, up to 4 for brotli) comes on top. A length of 0
// adds nothing; brotli sends 1 as 2 (brotli_padding in compress.cpp: libbrotli before 1.1.0 writes a
// one-byte metadata block without its length). padding_length() draws one from the calling thread's
// generator.
inline constexpr unsigned kPaddingMax = 32;
unsigned padding_length() noexcept;

// A gzip encoder kept by a worker for the answers it compresses per request (docs/design-compression.md
// 6): the zlib stream is set up once and reset per answer, so a buffered answer costs its deflate
// and nothing else, no allocation. One per thread; gzip_context() hands out the calling thread's.
class GzipContext {
public:
    GzipContext();
    ~GzipContext();
    GzipContext(const GzipContext&) = delete;
    GzipContext& operator=(const GzipContext&) = delete;
    // `in` compressed whole at `level` (1..9) into `out` (cleared first), `padding` bytes (at most
    // kPaddingMax) in the header's extra field; false on a failure or a build without zlib, `out`
    // then empty.
    bool compress(int level, unsigned padding, std::string_view in, std::string& out);

private:
    void* z_ = nullptr;  // the zlib stream and its header, kept behind the pointer so this header needs no zlib.h
    int level_ = 0;
};
GzipContext& gzip_context();

// The zstd encoder kept the same way: one ZSTD_CCtx per thread, its parameters set once (the level
// when it changes), the session reset by each answer's call. A skippable frame of `padding` bytes
// goes before the data frame.
class ZstdContext {
public:
    ZstdContext();
    ~ZstdContext();
    ZstdContext(const ZstdContext&) = delete;
    ZstdContext& operator=(const ZstdContext&) = delete;
    bool compress(int level, unsigned padding, std::string_view in, std::string& out);

private:
    void* cctx_ = nullptr;
    int level_ = 0;
};
ZstdContext& zstd_context();

// An answer compressed whole with the coding at `level` (docs/design-compression.md 6): gzip and
// zstd through the calling thread's context, brotli through an encoder made for the answer (its
// state is sized by the window, so one per answer costs less than one kept per thread), the window
// capped as above, `padding` bytes carried as the coding skips them. False when the build lacks the
// coding or the encoder fails, `out` then empty.
bool compress_buffered(Encoding e, int level, unsigned padding, std::string_view in, std::string& out);

// ---- answers compressed in pieces (docs/design-compression.md 6, step 6) ----

// What one worker's encoders for answers compressed in pieces may hold at once (design 12, decision
// 11): past it an answer goes out uncompressed, Vary kept, and is counted in status. No key: an
// answer is never refused for it, and the count says when a worker meets it.
inline constexpr std::size_t kStreamBudget = 32u * 1024 * 1024;
// The input piece an encoder takes from its source at a time: 64 KB for an answer (zstd 3 under
// 0.1 ms, gzip 5 about 0.5 ms, inside the writer's own pieces), 16 KB for an event stream, whose
// events are small.
inline constexpr std::size_t kPieceAnswer = 64 * 1024;
inline constexpr std::size_t kPieceEvents = 16 * 1024;

// The encoder of one answer compressed in pieces: taken from the calling thread's pool (zlib and
// zstd contexts are reset, never made per answer; brotli has no reset and is made per answer, its
// blocks under glibc's mmap threshold, tune_heap in server.cpp), set up with the coding's level, a
// window fixed here, and the answer's padding, and given back to the pool when it is destroyed.
// Every call runs on the thread that began it (a connection never leaves its worker).
class StreamEncoder {
public:
    // answer: the windows above (zstd 2^19, brotli 2^18 or the answer's size, gzip 2^15). events: a
    // text/event-stream held open for a long time, so small encoders (zstd 2^15, brotli 2^16, gzip
    // 2^13) that a thousand open streams can afford; an event is a few hundred bytes.
    enum class Kind : std::uint8_t { answer, events };
    // process: compress what is given, the coding keeping what it has not emitted; flush: everything
    // given so far emitted, decodable by the client as it stands (Z_SYNC_FLUSH, ZSTD_e_flush,
    // BROTLI_OPERATION_FLUSH); finish: the coding's end written.
    enum class Op : std::uint8_t { process, flush, finish };

    StreamEncoder() = default;
    ~StreamEncoder();
    StreamEncoder(StreamEncoder&& o) noexcept : slot_(o.slot_) { o.slot_ = nullptr; }
    StreamEncoder& operator=(StreamEncoder&& o) noexcept;
    StreamEncoder(const StreamEncoder&) = delete;
    StreamEncoder& operator=(const StreamEncoder&) = delete;

    // Set up for one answer of `size` bytes (0: not known): false when the build lacks the coding,
    // the worker's budget would be passed (counted), or the library fails. `padding` bytes (at most
    // kPaddingMax) go where every decoder skips them, before the data (design 7).
    bool begin(Encoding e, int level, Kind kind, unsigned padding, std::uint64_t size);
    // One step of `op`: input taken from `in`, output written to `out`, both advanced. False on a
    // failure of the library (the answer cannot go on: its head named the coding). `done`: process,
    // the input consumed; flush and finish, the op complete (else call again with more room, the
    // same op, no new input).
    bool run(Op op, const char*& in, std::size_t& in_len, char*& out, std::size_t& out_len, bool& done);
    // The input buffer the pool keeps with the encoder (kPieceAnswer or kPieceEvents bytes), for a
    // source that is not already in memory.
    char* input() const noexcept;
    std::size_t input_capacity() const noexcept;
    // The bytes the encoder holds now, as its library reports them (zlib's formula, ZSTD_sizeof_CCtx,
    // brotli's blocks counted through its allocator), the input buffer included: what stream_charge
    // must stay above.
    std::size_t memory() const noexcept;
    // What the worker's budget counts for this encoder: the admission estimate (stream_charge), grown
    // to what the library holds once it allocated.
    std::size_t charge() const noexcept;
    explicit operator bool() const noexcept { return slot_ != nullptr; }

    struct Slot;

private:
    Slot* slot_ = nullptr;
};

// The bytes an answer's encoder of the coding, kind and level is admitted on, its input buffer
// included: what the library held at most for a stream, measured per level on 2026-11-07 (Debian 13:
// zstd 1.5.7, brotli 1.1.0, zlib 1.3.1) with headroom. An estimate: once the library allocated, the
// budget counts what it holds (StreamEncoder::run), since the .deb links the host's own library and
// another version holds more (Ubuntu 22.04's libzstd 1.4.8: 5.6 MB at level 6 against 3.9 here;
// the release run of 0.1.0-alpha.137 failed on a test that held the table to it). The level decides
// it more than the coding:
// zstd 3 holds 2.1 MB for an answer, zstd 9 11.6 MB (its search tables grow whatever the window);
// an event stream 386 KB with zstd 3, 872 KB with brotli 3, 86 KB with gzip.
std::size_t stream_charge(Encoding e, StreamEncoder::Kind kind, int level) noexcept;

// For status: answers being compressed in pieces now, since the start, and sent uncompressed for
// the budget, over every worker.
struct StreamCounts {
    std::uint64_t active = 0;
    std::uint64_t started = 0;
    std::uint64_t over_budget = 0;
};
StreamCounts stream_counts() noexcept;
// The calling thread's pooled encoders freed when it took none since the last call (the worker's
// one-second tick); true when it freed any, so the worker trims its heap.
bool release_idle_encoders() noexcept;

}  // namespace agensio
