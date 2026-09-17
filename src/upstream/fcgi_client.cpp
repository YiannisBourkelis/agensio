#include "upstream/fcgi_client.hpp"

#include <string>

namespace agensio {

void FcgiRequest::encode_head(std::string& out) {
    out.reserve(64 + params_prefix_.size() + params_tail_.size() + body_.memory.size() + 32);
    fcgi::append_begin_request(out, 1, options_.keep_conn);
    // The PARAMS stream: the prebuilt block and the per-request tail as separate records.
    // Their boundary is a pair boundary, which is what matters: php-fpm cannot parse a
    // name/value pair that spans two records. Neither part can reach kMaxContent (the
    // request head is capped at 16 KB and the block is a few hundred bytes), so the
    // 65535-byte split inside append_stream never lands inside a pair.
    fcgi::append_stream(out, fcgi::RecordType::params, 1, params_prefix_, false);
    fcgi::append_stream(out, fcgi::RecordType::params, 1, params_tail_, true);
    params_prefix_ = params_tail_ = {};
}

void FcgiRequest::encode_body_chunk(std::string& out, std::string_view bytes, bool last) {
    if (!bytes.empty()) fcgi::append_stream(out, fcgi::RecordType::stdin_, 1, bytes, false);
    if (last) fcgi::append_record(out, fcgi::RecordType::stdin_, 1, {});
}

UpstreamRequest::HeadStatus FcgiRequest::parse_head(std::string_view in, int& status, Headers& headers,
                                                     std::size_t& length) {
    fcgi::CgiHead head;
    const auto hs = fcgi::parse_cgi_head(in, head);
    if (hs == fcgi::HeadStatus::incomplete) return HeadStatus::incomplete;
    if (hs == fcgi::HeadStatus::error) return HeadStatus::error;
    status = head.status;
    headers = head.headers;
    length = head.length;
    return HeadStatus::complete;
}

// The record loop over conn_->in: STDOUT feeds the head then the body, STDERR is kept
// for the log, END_REQUEST finishes. Records of other request ids are ignored.
bool FcgiRequest::decode() {
    std::size_t pos = 0;
    while (pos < conn_->in_len) {
        const std::string_view unread(conn_->in.data() + pos, conn_->in_len - pos);
        std::size_t used = 0;
        fcgi::RecordHeader h;
        std::string_view content;
        const auto st = fcgi::next_record(unread, used, h, content);
        if (st == fcgi::ReadStatus::error) {
            fail(UpstreamFailure::protocol_error, std::error_code());
            return false;
        }
        if (st == fcgi::ReadStatus::need_more) break;
        pos += used;
        if (h.request_id != 1 && h.type != static_cast<std::uint8_t>(fcgi::RecordType::get_values_result)) continue;
        switch (static_cast<fcgi::RecordType>(h.type)) {
            case fcgi::RecordType::stdout_:
                if (!on_stdout(content)) return false;  // failed
                break;
            case fcgi::RecordType::stderr_:
                if (result_.stderr_text.size() < kStderrCap)
                    result_.stderr_text.append(content.substr(0, kStderrCap - result_.stderr_text.size()));
                break;
            case fcgi::RecordType::end_request: {
                // Compact first: finishing hands the connection back to the pool (only when no
                // bytes are left over), and `content` is a view into the buffer being compacted.
                const std::string end(content);
                consume(pos);
                on_end_request(end);
                return false;
            }
            default:
                break;  // management records we did not ask for are ignored
        }
    }
    consume(pos);
    return true;
}

bool FcgiRequest::on_stdout(std::string_view content) {
    if (!head_done()) {
        std::size_t used = 0;
        const HeadStatus hs = feed_head(content, used);
        if (hs == HeadStatus::error) return false;
        if (hs == HeadStatus::incomplete) return true;
        return store_body(content.substr(used));
    }
    return store_body(content);
}

void FcgiRequest::on_end_request(std::string_view content) {
    fcgi::EndRequest er;
    if (!parse_end_request(content, er) || er.protocol_status != fcgi::ProtocolStatus::request_complete) {
        fail(UpstreamFailure::protocol_error, std::error_code());
        return;
    }
    if (!head_done()) {  // the child produced no head at all (a crash; "Primary script unknown" comes with one)
        fail(UpstreamFailure::closed_early, std::error_code());
        return;
    }
    if (result_.stderr_text.find("Primary script unknown") != std::string::npos)
        result_.failure = UpstreamFailure::primary_script_unknown;  // fpm's own 404 is still passed through
    finish();
}

}  // namespace agensio
