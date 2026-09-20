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

#include "services/json.hpp"

namespace agensio::install {

struct Request {
    std::string site_root;    // the site's directory, owned by the executing account: the walk to the target starts here
    std::string target;       // site_root itself or a directory below it: must be empty, or missing with create_path
    bool create_path = false; // create the missing directories from site_root down to the target, as the executing account
    bool dry_run = false;     // run every check, create nothing, download nothing; report would_create
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
//  "created": [{"path", "owner", "mode"}]} ; a dry run answers {"ok", "dry_run": true, "as", "would_create": [...]}.
// The walk from site_root to the target opens every component without following symlinks
// and requires each existing one to belong to the executing account; a refusal at any
// point removes what this call created.
json::Value execute(const Request& req);

// One path segment: letters, digits, ".", "_", "-", not starting with a dot, at most 128 bytes.
bool valid_upload_name(std::string_view name) noexcept;
// 64 hex digits (any case).
bool valid_sha256(std::string_view hex) noexcept;

}  // namespace agensio::install
