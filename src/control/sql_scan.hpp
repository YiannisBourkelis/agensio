// What a .sql file under a document root holds, for health's archives_in_root (control/commands.cpp):
// table definitions only, or statements that may carry the site's data or a credential. Header-only
// and free of the server, so tests/fuzz/fuzz_sql_scan.cpp runs it alone.
#pragma once

#include <cstddef>
#include <string_view>

namespace agensio::control::sql {

struct Scan {
    bool definitions_only = true;  // every statement defines tables, or is empty
    bool open = false;             // the text ends inside a quote or a block comment
};

// The text split into statements on `;` outside quotes and comments, each judged by its first two
// tokens (the alpha.96 report: a file of UPDATE statements holding a password hash and a key was
// taken for a schema by the keyword rule before it). A statement defines tables when it starts
// CREATE TABLE, CREATE INDEX, CREATE VIEW, CREATE UNIQUE | FULLTEXT | SPATIAL (INDEX), CREATE
// TEMPORARY (TABLE), ALTER TABLE, DROP TABLE, DROP INDEX or DROP VIEW, in any case; anything else may
// carry data or a secret (INSERT, UPDATE, REPLACE, COPY, SET, GRANT, CREATE USER ... IDENTIFIED BY,
// PRAGMA, a statement that starts with a symbol). Comments are `-- ...` and `# ...` to the end of the
// line and `/* ... */`, and are not read; MySQL's executable comments (`/*!40101 SET ... */`, which
// mysqldump writes) are code, so a dump counts even without its rows. Quotes are '...', "..." and
// `...`, a backslash escaping the next character and a doubled quote reading as two quotes. One pass,
// linear in the text, no allocation.
inline Scan scan(std::string_view t) {
    Scan r;
    enum class State { code, line_comment, block_comment, quote } st = State::code;
    char quote = 0;
    // The statement's first two tokens: a word, lowercased (a longer one than the buffer is kept cut,
    // which matches no keyword of the list), or a symbol, which is never one.
    char tok[2][12] = {};
    std::size_t tlen[2] = {0, 0};
    bool symbol[2] = {false, false};
    int ntok = 0;  // tokens seen in the statement, at most 2 kept
    int cur = -1;  // the word being read, when it is one of the two
    bool in_word = false;
    const auto is = [&](int i, std::string_view w) { return !symbol[i] && std::string_view(tok[i], tlen[i]) == w; };
    const auto defines_tables = [&] {
        if (ntok == 0) return true;  // an empty statement: `;;`, or comments alone
        if (ntok < 2) return false;
        if (is(0, "create"))
            return is(1, "table") || is(1, "index") || is(1, "view") || is(1, "unique") || is(1, "fulltext") || is(1, "spatial") ||
                   is(1, "temporary");
        if (is(0, "alter")) return is(1, "table");
        if (is(0, "drop")) return is(1, "table") || is(1, "index") || is(1, "view");
        return false;
    };
    const auto end_statement = [&] {
        if (!defines_tables()) r.definitions_only = false;
        ntok = 0;
        tlen[0] = tlen[1] = 0;
        symbol[0] = symbol[1] = false;
        cur = -1;
        in_word = false;
    };
    const auto add_symbol = [&] {
        in_word = false;
        if (ntok < 2) symbol[ntok++] = true;
    };
    for (std::size_t i = 0; i < t.size(); ++i) {
        const char c = t[i];
        const char next = i + 1 < t.size() ? t[i + 1] : '\0';
        if (st == State::line_comment) {
            if (c == '\n') st = State::code;
            continue;
        }
        if (st == State::block_comment) {
            if (c == '*' && next == '/') {
                st = State::code;
                ++i;
            }
            continue;
        }
        if (st == State::quote) {
            if (c == '\\') ++i;  // the next character escaped (past the end, the loop ends: open)
            else if (c == quote) st = State::code;
            continue;
        }
        const bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        if (letter || (c >= '0' && c <= '9') || c == '_') {
            if (!in_word) {
                in_word = true;
                cur = ntok < 2 ? ntok++ : -1;
            }
            if (cur >= 0 && tlen[cur] < sizeof tok[0]) tok[cur][tlen[cur]++] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
            continue;
        }
        in_word = false;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v') continue;
        if (c == '-' && next == '-') {
            st = State::line_comment;
            ++i;
        } else if (c == '#') {
            st = State::line_comment;
        } else if (c == '/' && next == '*' && !(i + 2 < t.size() && t[i + 2] == '!')) {
            st = State::block_comment;
            ++i;
        } else if (c == '\'' || c == '"' || c == '`') {
            quote = c;
            st = State::quote;
            add_symbol();
        } else if (c == ';') {
            end_statement();
        } else {
            add_symbol();
        }
    }
    r.open = st == State::quote || st == State::block_comment;
    end_statement();
    return r;
}

}  // namespace agensio::control::sql
