// Static file handler: turns a request into a Response served from the cache or a file.
// No socket I/O here; the protocol connection writes the Response. The dispatcher picks the
// site and the location; this handler applies the location's root, index, try_files and
// policies. An internal redirect from try_files re-enters the router with the new path.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "cache.hpp"
#include "config.hpp"
#include "core/router.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"
#include "file.hpp"
#include "handlers/encoding.hpp"

namespace agensio {

// The refused-endings rule: a path ends with one of `deny` when its last characters match
// case-insensitively, trailing dots ignored (`x.PHP`, `x.PhP`, `x.php.` are all `x.php`;
// Drupal's .htaccess spells the same rule). `x.php.jpg` is a .jpg and passes. Pure, so
// it is unit tested with the spellings a live report found served as source (2026-09-20).
inline bool refused_suffix(std::string_view path, const std::vector<std::string>& deny) noexcept {
    while (!path.empty() && path.back() == '.') path.remove_suffix(1);
    for (const std::string& d : deny) {
        if (d.size() > path.size()) continue;
        const std::string_view tail = path.substr(path.size() - d.size());
        bool same = true;
        for (std::size_t i = 0; i < d.size() && same; ++i) {
            const unsigned char a = static_cast<unsigned char>(tail[i]), b = static_cast<unsigned char>(d[i]);
            same = a == b || ((a | 0x20) == (b | 0x20) && ((a | 0x20) >= 'a' && (a | 0x20) <= 'z'));
        }
        if (same) return true;
    }
    return false;
}

// The protected-names rule (2026-09-20 live report: wp-config.php~, .bak, .save, .orig and
// .txt were served with the database password and the salts in them; the exact name was
// 404). A request in the directory of a name the site never serves is refused when, after
// an optional leading "." or "#" (vim's .name.swp, emacs's #name#), its basename is the
// name's stem followed by "." and anything (name.bak, name~ is below, stem.bak, stem.txt,
// the name itself in another case), or the whole name followed by "~", "#", "-" or "_"
// and anything (name~, name-old, name_bak). Case-insensitive, so a case-insensitive
// filesystem cannot serve WP-CONFIG.PHP either, and independent of hidden_files. The
// bare stem alone ("/readme", "/license") is not touched: a WordPress permalink. Pure,
// unit tested; the integration suite plants every spelling on both presets.
inline bool backup_of_protected(std::string_view path, const std::vector<ProtectedName>& names) noexcept {
    auto lower = [](char c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; };
    for (const ProtectedName& n : names) {
        if (path.size() <= n.dir_len) continue;
        std::size_t i = 0;
        while (i < n.dir_len && lower(path[i]) == n.dir_stem[i]) ++i;
        if (i < n.dir_len) continue;
        std::string_view base = path.substr(n.dir_len);
        if (base.find('/') != std::string_view::npos) continue;  // a deeper path, another directory
        const bool marked = base.front() == '.' || base.front() == '#';
        if (marked) base.remove_prefix(1);
        const std::string_view stem = std::string_view(n.dir_stem).substr(n.dir_len);
        if (base.size() < stem.size()) continue;
        std::size_t j = 0;
        while (j < stem.size() && lower(base[j]) == stem[j]) ++j;
        if (j < stem.size()) continue;
        const std::string_view rest = base.substr(stem.size());
        if (rest.empty()) {
            if (marked) return true;  // ".wp-config" or "#wp-config": nothing public is spelled so
            continue;
        }
        if (rest.front() == '.') return true;  // stem.anything: the name, its case variants and every suffix behind it
        if (rest.size() > n.ext.size()) {      // name followed by a marker: name~, name#, name-old, name_bak
            std::size_t k = 0;
            while (k < n.ext.size() && lower(rest[k]) == n.ext[k]) ++k;
            if (k == n.ext.size()) {
                const char c = rest[k];
                if (c == '~' || c == '#' || c == '-' || c == '_') return true;
            }
        }
    }
    return false;
}

class StaticHandler {
public:
    StaticHandler(const Config& cfg, FileCache& cache);

    enum class Outcome { done, redirect };  // redirect: ws.path holds the try_files target

    // Serves ws.path under `loc` (cache, file, try_files). ws.now must be set by the caller.
    Outcome serve_location(Stream& s, const LocationConfig& loc, WorkerState& ws);

    // Fills s.response with a canned error page. `allow` adds an Allow header (405).
    void error(Stream& s, int status, bool keep_alive, std::string_view allow = {});

    enum class RangeOutcome { whole, partial, done };
    // `extra`: the representation's Content-Encoding and Vary lines, if any (a pre-compressed twin).
    RangeOutcome apply_range(Stream& s, std::uint64_t size, std::string_view content_type, std::string_view etag,
                             std::string_view last_modified, std::uint64_t& first, std::uint64_t& length,
                             std::string_view extra = {});
    // 204 with an Allow header (OPTIONS).
    void no_content(Stream& s, std::string_view allow);

    static constexpr int kMaxInternalRedirects = 8;  // try_files fallbacks per request (nginx: 10)

private:
    enum class Lookup { found, responded, redirect };

    Lookup plain_lookup(Stream& s, const LocationConfig& loc, WorkerState& ws, File& f, FileInfo& fi);
    Lookup try_files_lookup(Stream& s, const LocationConfig& loc, WorkerState& ws, File& f, FileInfo& fi);
    Lookup index_lookup(const LocationConfig& loc, WorkerState& ws, File& f, FileInfo& fi);

    void serve_entry(Stream& s, EntryPtr e);  // takes ownership of the ref; picks a twin by Accept-Encoding
    static void add_headers(Stream& s, const LocationConfig& loc);
    // Metadata and prebuilt header blocks shared by memory, descriptor and twin entries:
    // `coding` names the twin's Content-Encoding, `vary` adds Vary: Accept-Encoding.
    void fill_entry(CacheEntry& e, const FileInfo& fi, std::string_view path, std::string_view content_type,
                    Encoding coding, bool vary, std::time_t now);
    void load_variants(CacheEntry& parent, const FileInfo& fi, const LocationConfig& loc, WorkerState& ws,
                       std::time_t now);
    bool twins_unchanged(const CacheEntry& e, WorkerState& ws);
    void serve_file(Stream& s, File&& f, const FileInfo& fi, WorkerState& ws);
    void redirect_slash(Stream& s, WorkerState& ws);
    static bool not_modified(const Request& req, std::string_view etag, std::string_view last_modified) noexcept;

    const Config& cfg_;
    FileCache& cache_;
};

// Helpers shared with tests and the other handlers.
void make_etag(std::int64_t mtime, std::uint64_t size, std::string& out);
// The filesystem path for ws.path under the location: root + path, or with `alias` the
// alias directory in place of the location prefix (nginx semantics). Result in ws.fs_path.
void fs_path_of(const LocationConfig& loc, WorkerState& ws);

}  // namespace agensio
