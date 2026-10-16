// libFuzzer target for the statement scanner of health's archives_in_root (control/sql_scan.hpp): the
// input is a .sql file's text. Beyond memory safety and a linear run (the run's timeout), three
// properties tie the verdict to the statements: a comment line appended changes nothing; a data
// statement after the text, when the text does not end inside a quote or a block comment, is always
// found, so no text can make the scanner miss the statement that follows it; and a table definition
// after a file of definitions keeps it one.
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>

#include "control/sql_scan.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace sql = agensio::control::sql;
    const std::string text(reinterpret_cast<const char*>(data), size);
    const sql::Scan r = sql::scan(text);
    assert(sql::scan(text + "\n-- a comment\n").definitions_only == r.definitions_only);
    if (!r.open) {
        assert(!sql::scan(text + "\n;INSERT INTO z VALUES (1);").definitions_only);
        if (r.definitions_only) assert(sql::scan(text + "\n;CREATE TABLE z (a int);").definitions_only);
    }
    return 0;
}
