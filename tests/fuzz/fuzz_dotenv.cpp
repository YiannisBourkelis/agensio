// libFuzzer target for a Laravel site's .env (services/dotenv) and for how a credential file's diff is
// masked (control::mask_credential_diff): the file is the application's own, written by the site's
// account before the first site_env_set and then read and changed by the provisioning helper as root,
// and its diff is what an approval shows. Input: the file's text, then a NUL, then a change, one per
// line: "S NAME=value" (set), "U NAME" (unset), "G NAME" (generate); the text's first line is also
// tried as an env_file setting.
//
// The promises held:
// - parse keeps every byte: its lines' text joined with '\n' is the input (one final '\n' aside), and
//   every assignment's name is one check_name accepts;
// - a value render_value accepts reads back the same from one line;
// - a change apply accepts reads back as given: a name set or generated once, with its value (a
//   generated APP_KEY in Laravel's form, a kept one unchanged), a name unset and not given again
//   gone, no quote left open, and every line of a name it did not touch kept, in order;
// - describe answers no value but those revealed;
// - the masked diff of the text shows, for each line, the line itself only when it is blank, else its
//   length, or for an env-like text the part before the '=' of an assignment phpdotenv reads on that
//   one line (a comment's only in capitals) and the value's length: never a byte of a value.
// - check_env_file accepts only a plain relative path of letters, digits, '.', '_', '-' and '/', no
//   '.', '..' or empty segment, none starting with '-', and no hidden directory.
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "control/approvals.hpp"
#include "services/dotenv.hpp"
#include "services/files.hpp"

using namespace agensio;

namespace {

std::vector<std::string_view> split(std::string_view text) {
    std::vector<std::string_view> out;
    for (std::size_t at = 0; at < text.size();) {
        const std::size_t end = std::min(text.find('\n', at), text.size());
        out.push_back(text.substr(at, end - at));
        at = end + 1;
    }
    return out;
}

bool blank(std::string_view s) { return s.find_first_not_of(" \t\r") == std::string_view::npos; }

std::string bytes(std::size_t n) { return "<" + std::to_string(n) + " bytes>"; }

// The name a masked line shows before its '=': past the blanks, a comment's '#' and "export ".
std::string_view shown_name(std::string_view head) {
    std::size_t i = head.find_first_not_of(" \t");
    if (i < head.size() && head[i] == '#') i = head.find_first_not_of(" \t", i + 1);
    if (head.substr(i).starts_with("export ")) i = head.find_first_not_of(" \t", i + 7);
    const std::size_t end = head.find_first_of(" \t=", i);
    return head.substr(i, end - i);
}

// The first assignment of a name and how many there are.
std::size_t find(const std::vector<dotenv::Line>& lines, const std::string& name, const dotenv::Line** first) {
    std::size_t n = 0;
    for (const auto& l : lines)
        if (l.assignment && l.name == name && n++ == 0) *first = &l;
    return n;
}

void check_parse(std::string_view text, const std::vector<dotenv::Line>& lines) {
    std::string joined;
    for (std::size_t i = 0; i < lines.size(); ++i) joined += (i ? "\n" : "") + lines[i].raw;
    std::string_view expect = text;
    if (expect.ends_with('\n')) expect.remove_suffix(1);
    assert(joined == expect);
    for (const auto& l : lines) {
        if (l.assignment) assert(dotenv::check_name(l.name).empty());
        else assert(l.name.empty() && !l.exported);
        if (l.unterminated) assert(!l.readable);
        if (l.readable) assert(l.raw.find('\n') == std::string::npos);
    }
}

void check_masking(std::string_view text, const std::vector<dotenv::Line>& lines) {
    const bool env = control::env_like_text(text);
    if (env)
        for (const auto& l : lines) assert(!l.assignment || l.readable);
    const std::vector<std::string_view> orig = split(text);
    const std::string masked = control::mask_credential_diff(control::unified_diff("", text, 0), env);
    std::size_t i = 0;
    for (std::string_view m : split(masked)) {
        if (m.empty() || m.front() != '+') {
            assert(m.find_first_not_of("0123456789@-+, ") == std::string_view::npos || m.starts_with("the file is replaced whole (") || m == "no change");
            continue;
        }
        assert(i < orig.size());
        const std::string_view o = orig[i++];
        m.remove_prefix(1);
        if (blank(o)) {
            assert(m == o);
            continue;
        }
        if (m == bytes(o.size())) continue;
        const std::size_t first = o.find_first_not_of(" \t");
        const bool comment = o[first] == '#';
        if (m == "#" + bytes(o.size())) {
            assert(env && comment);
            continue;
        }
        // An assignment: the text up to the first '=' after the name, then the rest's length.
        assert(env);
        const std::size_t eq = o.find('=');
        assert(eq != std::string_view::npos);
        const std::string_view head = o.substr(0, eq + 1);
        assert(m == std::string(head) + (o.size() > eq + 1 ? bytes(o.size() - eq - 1) : std::string()));
        const std::string_view name = shown_name(head);
        assert(!name.empty() && dotenv::check_name(name).empty());
        if (comment) {
            assert(std::none_of(name.begin(), name.end(), [](char c) { return c >= 'a' && c <= 'z'; }));
        } else {
            // phpdotenv's own reading: this line is an assignment of the name shown (an env-like text's
            // lines are its lines one for one).
            const std::size_t line_at = i - 1;
            assert(line_at < lines.size() && lines[line_at].assignment && lines[line_at].name == name);
        }
    }
    assert(i == orig.size());
}

void check_change(std::string_view text, const std::vector<dotenv::Line>& lines, std::string_view spec) {
    appenv::Change change;
    for (std::string_view l : split(spec)) {
        if (l.size() < 3 || l[1] != ' ') continue;
        const std::string_view rest = l.substr(2);
        if (l[0] == 'S') {
            const std::size_t eq = rest.find('=');
            if (eq == std::string_view::npos) continue;
            change.set.push_back({std::string(rest.substr(0, eq)), std::string(rest.substr(eq + 1))});
            std::string out;
            if (dotenv::render_value(change.set.back().value, out).empty()) {
                const auto back = dotenv::parse("X=" + out + "\n");
                assert(back.size() == 1 && back[0].assignment && back[0].readable && back[0].value == change.set.back().value);
            }
        } else if (l[0] == 'U') {
            change.unset.emplace_back(rest);
        } else if (l[0] == 'G') {
            change.generate.emplace_back(rest);
        }
        if (change.set.size() + change.unset.size() + change.generate.size() >= 16) break;
    }
    const dotenv::Result r = dotenv::apply(text, change);
    if (!r.error.empty()) return;
    const auto after = dotenv::parse(r.text);
    for (const auto& l : after) assert(!l.unterminated);
    // What the change touched, in apply's order: unset, then set, then generate (kept when present).
    std::map<std::string, std::string> value;  // name -> value expected ("" with generated: any)
    std::vector<std::string> gone, generated, touched;
    for (const auto& n : change.unset) gone.push_back(n), touched.push_back(n);
    for (const auto& v : change.set) {
        std::erase(gone, v.name);
        value[v.name] = v.value;
        touched.push_back(v.name);
    }
    for (const auto& n : r.generated) {
        generated.push_back(n);
        value.erase(n);
        std::erase(gone, n);
        touched.push_back(n);
    }
    for (const auto& n : r.kept) {
        const dotenv::Line* was = nullptr;
        const dotenv::Line* now = nullptr;
        assert(find(after, n, &now) >= 1 && now->readable && !now->value.empty());
        if (std::find(touched.begin(), touched.end(), n) == touched.end()) assert(find(lines, n, &was) >= 1 && was->value == now->value);
    }
    for (const auto& [n, v] : value) {
        const dotenv::Line* now = nullptr;
        assert(find(after, n, &now) == 1 && now->readable && now->value == v);
    }
    for (const auto& n : generated) {
        const dotenv::Line* now = nullptr;
        assert(find(after, n, &now) == 1 && now->readable && !now->value.empty());
        if (n == "APP_KEY") assert(now->value.size() == 51 && now->value.starts_with("base64:"));
    }
    for (const auto& n : gone) {
        const dotenv::Line* now = nullptr;
        assert(find(after, n, &now) == 0);
    }
    // Every line of a name the change did not touch, and every other line, kept in order.
    std::size_t j = 0;
    for (const auto& l : lines) {
        if (l.assignment && std::find(touched.begin(), touched.end(), l.name) != touched.end()) continue;
        while (j < after.size() && after[j].raw != l.raw) ++j;
        assert(j < after.size());
        ++j;
    }
}

void check_describe(std::string_view text, const std::vector<dotenv::Line>& lines) {
    const json::Value none = dotenv::describe(text, "k", {});
    for (const auto& v : none["variables"].items()) assert(v["value"].is_null());
    assert(none["revealed"].items().empty());
    std::string name;
    for (const auto& l : lines)
        if (l.assignment) {
            name = l.name;
            break;
        }
    if (name.empty()) return;
    const json::Value one = dotenv::describe(text, "k", {name});
    for (const auto& v : one["variables"].items())
        if (!v["value"].is_null()) assert(v.get("name") == name);
}

void check_env_file_path(std::string_view path) {
    if (!check_env_file(path).empty()) return;
    assert(!path.empty() && path.front() != '/' && path.back() != '/');
    const std::vector<std::string_view> parts = [&] {
        std::vector<std::string_view> out;
        for (std::size_t at = 0;;) {
            const std::size_t slash = path.find('/', at);
            out.push_back(path.substr(at, slash == std::string_view::npos ? std::string_view::npos : slash - at));
            if (slash == std::string_view::npos) return out;
            at = slash + 1;
        }
    }();
    assert(path.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/") == std::string_view::npos);
    for (std::size_t k = 0; k < parts.size(); ++k) {
        assert(!parts[k].empty() && parts[k] != "." && parts[k] != ".." && parts[k].front() != '-');
        if (k + 1 < parts.size()) assert(parts[k].front() != '.');
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view in(reinterpret_cast<const char*>(data), size);
    const std::size_t nul = in.find('\0');
    const std::string_view text = in.substr(0, nul);
    const std::string_view spec = nul == std::string_view::npos ? std::string_view() : in.substr(nul + 1);
    const auto lines = dotenv::parse(text);
    check_parse(text, lines);
    check_masking(text, lines);
    check_change(text, lines, spec);
    check_describe(text, lines);
    check_env_file_path(text.substr(0, text.find('\n')));
    if (files::private_key_head(text)) assert(text.starts_with("-----BEGIN ") || text.starts_with("PuTTY-User-Key-File-"));
    return 0;
}
