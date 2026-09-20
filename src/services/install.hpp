// site-install (F9): puts an application's files into an empty site directory, as the
// account that owns that directory, from an https URL or an uploaded archive. `execute`
// is the whole job and runs wherever the caller can already be that account: in a child
// of the root provisioning helper after a privilege drop, or on a thread of a server that
// runs sites under its own account. Every rule the archive extractor and the downloader
// enforce applies; on any failure what was extracted is removed again, so the directory
// is either empty or complete. Pure helpers (`valid_upload_name`, `valid_sha256`) are
// unit tested; `tests/install.sh` runs the whole thing as real users.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "services/json.hpp"

namespace agensio::install {

struct Request {
    std::string site_root;    // the site's directory, owned by the executing account: the walk to the target starts here
    std::string target;       // site_root itself or a directory below it: must be empty, or missing with create_path
    bool create_path = false; // create the missing directories from site_root down to the target, as the executing account
    bool dry_run = false;     // run every check, create nothing, download nothing; report would_create
    std::vector<std::string> secrets;  // credential files relative to site_root (secret_paths): made 0600 after extraction, self-checked
    std::string url;          // https source, or ""
    int upload_fd = -1;       // an open descriptor of the uploaded archive, or -1
    std::string upload_name;  // for messages
    std::string sha256;       // expected digest (hex) or ""
    int strip = -1;           // -1 auto (unwrap a single top directory), 0 never, 1 always
    bool allow_private = false;
    std::uint64_t max_download = 1ull << 30;
    std::string ca_file;
};

// {"ok": bool, "error"?, "as", "files", "directories", "bytes", "downloaded", "sha256", "unwrapped"?,
//  "created": [{"path", "owner", "mode"}], "secured": [paths made 0600]} ; a dry run answers {"ok", "dry_run": true, "as", "would_create": [...]}.
// The walk from site_root to the target opens every component without following symlinks
// and requires each existing one to belong to the executing account; a refusal at any
// point removes what this call created.
json::Value execute(const Request& req);

// site-copy (F9b): one regular file of a site copied to another path of the same site, as
// the executing account. `from` and `to` are cleaned relative paths (archive::clean_path)
// below site_root; both are reached by the same walk as an install (no symlink on any
// component, every component the account's). The destination's parent must exist, the
// destination must not, unless `overwrite`; the new file gets the parent's pattern
// (a 2750 directory gives 0640, the execute bits when the source has them). Written to a
// temporary name and linked or renamed into place, so a failure leaves nothing.
struct CopyRequest {
    std::string site_root;
    std::string from, to;
    bool overwrite = false;
    bool dry_run = false;
    std::vector<std::string> secrets;  // as in Request: a destination among them is created 0600
    std::uint64_t max_bytes = 512ull << 20;
};

// {"ok", "error"?, "as", "from", "to", "bytes", "mode", "replaced"?: {"bytes", "mtime"}};
// a dry run answers {"ok", "dry_run": true, "as", "from", "to", "would_replace"?}.
json::Value copy_file(const CopyRequest& req);

// One path segment: letters, digits, ".", "_", "-", not starting with a dot, at most 128 bytes.
bool valid_upload_name(std::string_view name) noexcept;
// 64 hex digits (any case).
bool valid_sha256(std::string_view hex) noexcept;

}  // namespace agensio::install
