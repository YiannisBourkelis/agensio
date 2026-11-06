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

#include "control/sites.hpp"
#include "services/json.hpp"

namespace agensio::control {

// Bytes a terminal would act on written as \xHH: everything outside printable ASCII but newline
// and tab (a carriage return included), so no content of a preview can move the cursor, clear a
// line or change colours in front of the person reading it.
std::string escape_for_terminal(std::string_view text);
// The same with newline, tab and the backslash written as \x0a, \x09 and \x5c too: a line made of text from
// outside (a file name from a site's tree, a path the request gives) stays one line wherever it is shown, and
// two names never print alike.
std::string escape_line(std::string_view text);

// One PHP file a static site would serve as its source, by its served path ("/wp-config.php"), "" when the walk met
// none: the example of a PHP site made static (N1), never a claim that there is none. No gate depends on it: the
// reasons say what a change does whatever the walk found (2026-11-06, the owner's decision after the alpha.131 to
// alpha.135 reports, each of which found a layout an account of the tree missed). Breadth first, at most
// kPhpScanEntries entries, links to directories not followed, a directory that cannot be read passed over; a link
// named as a PHP file counts as one; every PHP spelling static serves as source (php_suffixes()), dot names skipped
// (static answers 404), a configuration file ("config" or "settings" in its name) before any other.
inline constexpr std::size_t kPhpScanEntries = 5000;
std::string php_example(const std::string& root);
// What a static or PHP site's site_create finds at its root: nothing there (no directory, or an empty one), entries
// (any, dot names too), or a directory the server cannot read, so not known to be empty. One directory read, no walk.
enum class RootState { empty, holds_files, unreadable };
RootState root_state(const std::string& root);

// 48 random bits as 12 hex digits ("" without random bytes): unique, not a secret (the code is).
std::string new_approval_id();

struct PendingChange {
    // skipped: approved in a batch, not run because a change before it in the same batch failed.
    enum class State { waiting, running, done, failed, rejected, skipped };
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
    // The result holds a secret (a credential file's content, a revealed variable, a generated
    // password): handed out once, by GET /v1/approvals/ID only, never in the list or the approval's answer.
    bool secret_result = false;
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
// `max_lines`: lines of the preview shown, the rest counted (agensio ctl approve --show prints them all).
std::string pending_text(const PendingChange& c, std::time_t now, std::size_t max_lines = 0);

// What the gate knows beyond the request (docs/design-site-operations.md 27.2): whether a file read
// is of a credential or database file (files::secret_path, judged by the handler against the site's
// credential files); the site's managed spec as it is now, so a site_update is judged by what it
// changes; the site's names, so a redirect to one of them is not "elsewhere"; and for a site_create
// whether the root is empty.
struct ApprovalContext {
    bool secret_read = false;
    const SiteSpec* current = nullptr;
    // The body's `rules` as check_rules stores them (prefix paths without their slash, addresses
    // canonical), so a site_update's rules compare with the spec's like with like; null when the
    // body has none or they do not check, in which case the handler refuses the change anyway.
    const json::Value* rules_after = nullptr;
    std::vector<std::string> site_names;
    // php_example of the root of a PHP site whose app becomes static (the alpha.131 addendum, N1, the owner's
    // decision: the administrator's to decide, said plainly to the person approving). An example only: "" changes no
    // reason's claim.
    std::string root_php;
    // root_state of a static or PHP site's site_create: entries there, or a directory the server cannot read, wait.
    RootState root = RootState::empty;
};
// Why a mutation waits for approval, in the server's words; empty when it does not. `action` is the
// part after /v1/sites/NAME/. A dry run gets the same reasons: the handler runs it as it is and says
// it would wait.
std::vector<std::string> approval_reasons(std::string_view path, std::string_view action, const json::Value& body, const ApprovalContext& ctx = {});
// Whether an upstream URL names a host that is not this one (unix: sockets and loopback are here).
bool upstream_off_host(std::string_view upstream);
// The host of an http(s) URL, lower-case, without the port; "" for anything else.
std::string url_host(std::string_view url);

// The change from `before` to `after` as a unified diff of lines (3 lines of context, hunks with
// @@ -l,s +l,s @@), at most `max_lines` lines of it with the count of the rest; a file replaced
// beyond a few thousand edits is shown as its new text instead.
std::string unified_diff(std::string_view before, std::string_view after, std::size_t max_lines);
// A credential file's diff as anyone may see it (the grabloop.app report, 2026-11-03: the context
// lines of a .env edit carried DB_PASSWORD to the agent): every line of the file, context included,
// shows no value. env_like: the names and the '=' stay, each value becomes "<N bytes>"; otherwise each
// line becomes "<N bytes>". A comment keeps a name only when it is one of `names` (env_names of the
// file before and after): any other is "#<N bytes>". The diff's own lines (@@ headers, "no change") are kept.
std::string mask_credential_diff(std::string_view diff, bool env_like, const std::vector<std::string>& names = {});
// The names `text` assigns, as phpdotenv reads them (services/dotenv), each once.
std::vector<std::string> env_names(std::string_view text);
// Every line blank, a comment, or NAME=value (optionally "export "): the syntax of .env files.
bool env_like_text(std::string_view text);

}  // namespace agensio::control
