// What a PHP application needs of its PHP (docs/design-php-versions.md 7): its preset's table,
// compiled from the application's own published requirements with the page and the date read, and
// what the installed release declares itself (composer.json's require, WordPress's
// $required_php_version), which wins where it says something. Pure: the callers read the files and
// run php-fpm -m; the unit tests and fuzz_php_constraint drive the readers directly.
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace agensio::php {

struct AppRequirements {
    std::string app;           // the preset
    std::string min;           // the oldest PHP the application runs on ("7.2.24")
    std::string recommended;   // the version it recommends ("8.3")
    std::string tested;        // the newest it says it supports ("8.4"): a newer one is a warning
    std::vector<std::string> required;     // extensions, as php -m names them, lower case
    std::vector<std::string> recommended_ext;
    std::string source;        // the page the values were read from
    std::string checked;       // when (YYYY-MM-DD)
};
// The table of the PHP presets that publish requirements; null for one that has none (php, static).
const std::vector<AppRequirements>& app_requirement_table();
const AppRequirements* app_requirements(std::string_view app);

// What an installed release declares of itself.
struct Declared {
    std::string php;               // a Composer version constraint ("^8.2", ">=7.2.24"); "" none
    std::vector<std::string> ext;  // the extensions it requires (composer.json's ext-*), lower case
    std::string from;              // the file it came from: "composer.json", "wp-includes/version.php"
};
// composer.json's require: "php" and every "ext-*". Nothing for text that is not such a file.
Declared parse_composer(std::string_view json_text);
// The version of `$required_php_version = '7.2.24';` in WordPress's wp-includes/version.php, "" none.
std::string parse_wp_required(std::string_view version_php);
// A release's declaration from its files' text: composer.json's require.php and ext-*, else
// WordPress's $required_php_version as a minimum; either text may be "".
Declared declared_from(std::string_view composer_json, std::string_view wp_version_php);

// Whether PHP `version` ("8.4", "8.4.24") satisfies a Composer constraint: exact, >= > <= < != ranges
// joined by spaces or commas (and) and || (or), a - b, the wildcard 8.2.*, ~8.2, ^8.2, a leading v and a
// stability flag dropped. `known` false when the constraint cannot be read (then the answer is true:
// nothing is refused on a constraint agensio does not understand).
bool constraint_allows(std::string_view constraint, std::string_view version, bool& known);
// -1, 0 or 1 for two versions of up to three numeric parts; a missing part is 0 ("8.4" == "8.4.0").
int compare_versions(std::string_view a, std::string_view b);

// One version and the extensions its php-fpm loads, judged against an application's table and its
// declaration. `outside`: the declaration's range excludes the version, or (without one) it is older
// than the table's minimum; `untested`: newer than the newest the application says it supports.
struct RequirementCheck {
    bool judged = false;   // a table or a declaration said something
    bool outside = false;
    bool untested = false;
    std::vector<std::string> missing;              // required extensions not loaded
    std::vector<std::string> missing_recommended;  // recommended extensions not loaded
    std::string range;     // what the version was judged by, for the messages
    bool blocks() const { return outside || !missing.empty(); }
};
// `modules` as php::parse_modules gives them; empty `modules_known` false skips the extensions.
RequirementCheck check_requirements(const AppRequirements* table, const Declared& declared, std::string_view version,
                                    const std::vector<std::string>& modules, bool modules_known = true);

}  // namespace agensio::php
