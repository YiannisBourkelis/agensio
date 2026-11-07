// libFuzzer target for an answer compressed in pieces (handlers/compressed_body.hpp, compress.cpp's
// StreamEncoder): the input scripts the source the writer pulls through CompressedBody. Its first
// bytes choose the coding, the kind (answer or event stream), the level, the writer's buffer size, a
// declared length and the padding; the rest are pieces, each a length and a flag saying whether the
// source holds it already (answered inside the read) or the application has not sent it yet (the
// read waits, then the piece arrives).
//
// The promises held:
// - every read the writer makes is answered: at once, or once the late piece arrives; never with 0
//   bytes before the coding's end;
// - when a read waits on the source, what was sent decodes to everything the source gave so far
//   (the flush rule: an application's flush and each event reach the client as they were sent);
// - at the end, the bytes sent decode whole, the coding's end reached, to what the source gave, held
//   to a declared length: never more, and a source that ends short fails the read.
// (What each encoder holds against the budget's charge is test_stream_encoder's, at every level.)
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "compress.hpp"
#include "handlers/compressed_body.hpp"
#include "../decode_stream.hpp"

using namespace agensio;

namespace {

class Source final : public StreamBody {
public:
    struct Piece {
        std::string bytes;
        bool ready;
    };
    std::vector<Piece> pieces;
    bool sized = false;
    std::uint64_t declared = 0;
    std::string given;
    bool length(std::uint64_t& out) const noexcept override {
        out = declared;
        return sized;
    }
    bool ready() const noexcept override { return next_ >= pieces.size() || pieces[next_].ready; }
    void async_read(char* buf, std::size_t len, ReadHandler h) override {
        assert(!waiting_);  // one read at a time
        if (next_ < pieces.size() && !pieces[next_].ready) {
            buf_ = buf;
            len_ = len;
            waiting_ = std::move(h);
            return;
        }
        give(buf, len, h);
    }
    bool waiting() const { return static_cast<bool>(waiting_); }
    void deliver() {
        pieces[next_].ready = true;
        ReadHandler h = std::move(waiting_);
        waiting_ = nullptr;
        give(buf_, len_, h);
    }

private:
    void give(char* buf, std::size_t len, ReadHandler& h) {
        if (next_ >= pieces.size()) {
            h({}, 0);
            return;
        }
        Piece& p = pieces[next_];
        const std::size_t n = std::min(len, p.bytes.size() - pos_);
        std::memcpy(buf, p.bytes.data() + pos_, n);
        given.append(p.bytes, pos_, n);
        pos_ += n;
        if (pos_ == p.bytes.size()) {
            ++next_;
            pos_ = 0;
        }
        h({}, n);
    }
    std::size_t next_ = 0, pos_ = 0;
    char* buf_ = nullptr;
    std::size_t len_ = 0;
    ReadHandler waiting_;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 6) return 0;
    static constexpr Encoding kCodings[3] = {Encoding::zstd, Encoding::br, Encoding::gzip};
    const Encoding e = kCodings[data[0] % 3];
    if (!coding_built(e)) return 0;
    const auto kind = (data[0] & 0x10) ? StreamEncoder::Kind::events : StreamEncoder::Kind::answer;
    const int level = 1 + data[1] % (e == Encoding::br ? 6 : 9);
    const std::size_t chunk = 64 + (static_cast<std::size_t>(data[2]) << 8 | data[3]) % 65472;  // the writer's buffer
    const unsigned padding = data[4] % (kPaddingMax + 1);
    const bool sized = data[5] & 1;
    data += 6;
    size -= 6;

    auto owned = std::make_unique<Source>();
    Source* src = owned.get();
    std::string all;
    while (size >= 2) {  // a piece: 2 bytes of length and flag, then its bytes (or a pattern when short)
        const std::size_t want = (static_cast<std::size_t>(data[0] & 0x7F) << 8 | data[1]) % 20000;
        const bool ready = !(data[0] & 0x80);
        data += 2;
        size -= 2;
        std::string bytes;
        const std::size_t take = std::min(want, size);
        bytes.assign(reinterpret_cast<const char*>(data), take);
        data += take;
        size -= take;
        for (std::size_t i = bytes.size(); i < want; ++i) bytes.push_back(static_cast<char>('a' + i % 7));  // compressible filler
        if (bytes.empty()) continue;  // a read of 0 bytes is a source's end: no piece is empty
        all += bytes;
        src->pieces.push_back({std::move(bytes), ready});
    }
    // A declared length: what the source sends, or a little less (the surplus is not the answer's),
    // or more (it ends short).
    std::uint64_t declared = all.size();
    if (sized) {
        if (!all.empty() && (all.size() & 3) == 1) declared = all.size() - 1;
        else if ((all.size() & 3) == 2) declared = all.size() + 1;
        src->sized = true;
        src->declared = declared;
    }

    StreamEncoder enc;
    if (!enc.begin(e, level, kind, padding, 0)) return 0;  // the budget is the worker's: one at a time here
    CompressedBody body(std::move(enc), std::move(owned));
    std::string sent;
    std::vector<char> buf(chunk);
    bool failed = false, ended = false;
    for (int reads = 0; reads < 1000000 && !failed && !ended; ++reads) {
        bool called = false;
        std::error_code ec;
        std::size_t got = 0;
        body.async_read(buf.data(), buf.size(), [&](std::error_code c, std::size_t n) {
            called = true;
            ec = c;
            got = n;
        });
        if (!called) {
            assert(src->waiting());  // a read that waits waits on the source, nothing else
            const test::Decoded d = test::decode_stream(e, sent);
            if (d.available) assert(d.ok && !d.ended && d.out == src->given);  // the flush rule
            src->deliver();
            assert(called);  // the late piece answers the writer's read
        }
        if (ec) {
            failed = true;
            break;
        }
        if (got == 0) ended = true;
        else sent.append(buf.data(), got);
    }
    const bool short_body = sized && declared > all.size();
    if (short_body) {
        assert(failed);
        return 0;
    }
    assert(!failed && ended);
    const test::Decoded d = test::decode_stream(e, sent);
    if (d.available) assert(d.ok && d.ended && d.out == all.substr(0, static_cast<std::size_t>(declared)));
    return 0;
}
