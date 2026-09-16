#include "mime.hpp"

#include <algorithm>
#include <array>
#include <cctype>

#include "core/strings.hpp"

namespace agensio {

namespace {

struct Entry {
    const char* ext;
    const char* type;
};

constexpr Entry kTable[] = {
    {"html", "text/html; charset=utf-8"},
    {"htm", "text/html; charset=utf-8"},
    {"shtml", "text/html; charset=utf-8"},
    {"css", "text/css; charset=utf-8"},
    {"xml", "text/xml; charset=utf-8"},
    {"txt", "text/plain; charset=utf-8"},
    {"md", "text/markdown; charset=utf-8"},
    {"csv", "text/csv; charset=utf-8"},
    {"vtt", "text/vtt; charset=utf-8"},
    {"js", "text/javascript; charset=utf-8"},
    {"mjs", "text/javascript; charset=utf-8"},
    {"json", "application/json; charset=utf-8"},
    {"map", "application/json; charset=utf-8"},
    {"webmanifest", "application/manifest+json; charset=utf-8"},
    {"xhtml", "application/xhtml+xml"},
    {"rss", "application/rss+xml"},
    {"atom", "application/atom+xml"},
    {"wasm", "application/wasm"},
    {"pdf", "application/pdf"},
    {"zip", "application/zip"},
    {"gz", "application/gzip"},
    {"tar", "application/x-tar"},
    {"7z", "application/x-7z-compressed"},
    {"rar", "application/vnd.rar"},
    {"bz2", "application/x-bzip2"},
    {"xz", "application/x-xz"},
    {"jar", "application/java-archive"},
    {"doc", "application/msword"},
    {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"xls", "application/vnd.ms-excel"},
    {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"ppt", "application/vnd.ms-powerpoint"},
    {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"rtf", "application/rtf"},
    {"bin", "application/octet-stream"},
    {"exe", "application/octet-stream"},
    {"dmg", "application/octet-stream"},
    {"iso", "application/octet-stream"},
    {"img", "application/octet-stream"},
    {"msi", "application/octet-stream"},
    {"deb", "application/octet-stream"},
    {"rpm", "application/octet-stream"},
    {"apk", "application/vnd.android.package-archive"},
    {"png", "image/png"},
    {"jpg", "image/jpeg"},
    {"jpeg", "image/jpeg"},
    {"gif", "image/gif"},
    {"webp", "image/webp"},
    {"avif", "image/avif"},
    {"svg", "image/svg+xml"},
    {"svgz", "image/svg+xml"},
    {"ico", "image/x-icon"},
    {"bmp", "image/bmp"},
    {"tif", "image/tiff"},
    {"tiff", "image/tiff"},
    {"heic", "image/heic"},
    {"woff", "font/woff"},
    {"woff2", "font/woff2"},
    {"ttf", "font/ttf"},
    {"otf", "font/otf"},
    {"eot", "application/vnd.ms-fontobject"},
    {"mp3", "audio/mpeg"},
    {"ogg", "audio/ogg"},
    {"oga", "audio/ogg"},
    {"m4a", "audio/mp4"},
    {"wav", "audio/wav"},
    {"flac", "audio/flac"},
    {"aac", "audio/aac"},
    {"opus", "audio/opus"},
    {"weba", "audio/webm"},
    {"mp4", "video/mp4"},
    {"m4v", "video/mp4"},
    {"webm", "video/webm"},
    {"ogv", "video/ogg"},
    {"mov", "video/quicktime"},
    {"avi", "video/x-msvideo"},
    {"mkv", "video/x-matroska"},
    {"ts", "video/mp2t"},
    {"m3u8", "application/vnd.apple.mpegurl"},
    {"3gp", "video/3gpp"},
    {"flv", "video/x-flv"},
    {"wmv", "video/x-ms-wmv"},
};

// Sorted at compile time so lookup is a binary search over a constant array: no heap,
// no static initialisation, genuinely noexcept.
struct MimeTable {
    std::array<Entry, sizeof(kTable) / sizeof(kTable[0])> entries{};
    constexpr MimeTable() {
        for (std::size_t i = 0; i < entries.size(); ++i)
            entries[i] = kTable[i];
        std::sort(entries.begin(), entries.end(),
                  [](const Entry& a, const Entry& b) { return std::string_view(a.ext) < std::string_view(b.ext); });
    }
};
constexpr MimeTable kSorted{};

}  // namespace

std::string_view mime_for_path(std::string_view path) noexcept {
    static constexpr std::string_view kDefault = "application/octet-stream";
    auto slash = path.rfind('/');
    std::string_view name = slash == std::string_view::npos ? path : slice(path, slash + 1);
    auto dot = name.rfind('.');
    if (dot == std::string_view::npos || dot + 1 >= name.size()) return kDefault;
    std::string_view ext = slice(name, dot + 1);
    if (ext.size() > 16) return kDefault;
    char lower[16];
    for (std::size_t i = 0; i < ext.size(); ++i)
        lower[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(ext[i])));
    const std::string_view key(lower, ext.size());
    auto it = std::lower_bound(kSorted.entries.begin(), kSorted.entries.end(), key,
                               [](const Entry& e, std::string_view k) { return std::string_view(e.ext) < k; });
    return (it != kSorted.entries.end() && std::string_view(it->ext) == key) ? std::string_view(it->type) : kDefault;
}

}  // namespace agensio
