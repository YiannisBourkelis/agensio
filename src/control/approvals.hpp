// Changes that wait for a person's approval (docs/design-site-operations.md 27): what the gate
// holds back, the record of a waiting change, and the text a person reads before typing the code
// from their authenticator app. Pure, so the unit tests hold every rule; the control handler keeps
// the store and runs an approved change through its own code path.
#pragma once

#include <cstdint>
#include <ctime>
#include <list>
#include <string>
#include <string_view>
#include <vector>

#include "services/json.hpp"

namespace agensio::control {

// Bytes a terminal would act on written as \xHH: everything outside printable ASCII but newline
// and tab (a carriage return included), so no content of a preview can move the cursor, clear a
// line or change colours in front of the person reading it.
std::string escape_for_terminal(std::string_view text);

// 48 random bits as 12 hex digits ("" without random bytes): unique, not a secret (the code is).
std::string new_approval_id();

struct PendingChange {
    enum class State { waiting, running, done, failed, rejected };
    std::string id;
    std::string path;    // the control API path, /v1/sites/NAME/task
    std::string body;    // the request's JSON as it came
    long uid = -1, gid = -1;
    int role = 0;
    std::string client;  // what the requester said it is (X-Agensio-Client): shown, never trusted
    std::string reason;  // the requester's own words, shown last and marked as theirs
    std::time_t created = 0;
    std::vector<std::string> reasons;  // why it waits, in the server's words
    std::string preview;               // the change as the server describes it, escaped
    State state = State::waiting;
    std::string approver;
    std::time_t finished = 0;
    int status = 0;            // the answer's status once it ran
    json::Value result;        // the answer's body once it ran
    bool result_taken = false;  // a read's content is handed out once
};

const char* state_name(PendingChange::State s) noexcept;

// The waiting changes and what became of them. At most kMaxWaiting wait, each for kTtl; a result
// stays kTtl after it was made, then goes.
class ApprovalStore {
public:
    static constexpr std::size_t kMaxWaiting = 32;
    static constexpr std::time_t kTtl = 600;

    // Stores a change; false when kMaxWaiting already wait.
    bool add(PendingChange change, std::time_t now);
    PendingChange* find(std::string_view id, std::time_t now);
    std::vector<PendingChange*> waiting(std::time_t now);
    std::vector<PendingChange*> all(std::time_t now);
    bool reject(std::string_view id, std::time_t now);

private:
    void expire(std::time_t now);
    std::list<PendingChange> changes_;  // a list: a record's address holds while others come and go
};

// The change as JSON for approvals_list and agensio ctl approve: id, path, state, who and when,
// the reasons, the preview, and once it ran its status and result (`with_result`; a read's content
// is taken out by the caller).
json::Value pending_json(const PendingChange& c, std::time_t now, bool with_result);

// The person-facing text of one waiting change (ctl approve, the client's dialog): the reasons
// first, the preview, the requester's words last and marked as theirs; escaped.
std::string pending_text(const PendingChange& c, std::time_t now);

// Why a mutation waits for approval, in the server's words; empty when it does not
// (docs/design-site-operations.md 27.2). `action` is the part after /v1/sites/NAME/. A dry run gets
// the same reasons: the handler runs it as it is and says it would wait.
std::vector<std::string> approval_reasons(std::string_view path, std::string_view action, const json::Value& body);

}  // namespace agensio::control
