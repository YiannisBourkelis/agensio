# refuse matcher micro-benchmark, 2026-10-08

- machine: x86_64, AMD Ryzen 9 9900X 12-Core Processor, Linux 6.12.111+deb13-amd64, nothing else running
- commit: ce3276d + working tree (core/refuse.hpp as of this run)
- compiler: g++ (Debian 14.2.0-19) 14.2.0
- command: g++ -std=c++23 -O2 -DASIO_STANDALONE -I src -I third_party -isystem build/_deps/asio-src/asio/include refuse_bench.cpp -o refuse_bench && ./refuse_bench (three runs)
- what: refuse::match over TYPO3 13.4's 48 documented deny patterns (none of the paths is refused), 5M calls per path, ns per call

```
/                                                          2.3 ns  (hits 0)
/en/about-us                                              11.9 ns  (hits 0)
/fileadmin/user_upload/photo.jpg                          31.5 ns  (hits 0)
/typo3conf/ext/news/Resources/Public/Css/news.css         92.2 ns  (hits 0)
/_assets/abc/Css/x.css                                    24.5 ns  (hits 0)

/                                                          2.3 ns  (hits 0)
/en/about-us                                              11.9 ns  (hits 0)
/fileadmin/user_upload/photo.jpg                          31.4 ns  (hits 0)
/typo3conf/ext/news/Resources/Public/Css/news.css         93.4 ns  (hits 0)
/_assets/abc/Css/x.css                                    23.3 ns  (hits 0)

/                                                          2.3 ns  (hits 0)
/en/about-us                                              11.8 ns  (hits 0)
/fileadmin/user_upload/photo.jpg                          31.6 ns  (hits 0)
/typo3conf/ext/news/Resources/Public/Css/news.css         91.9 ns  (hits 0)
/_assets/abc/Css/x.css                                    23.4 ns  (hits 0)

```

Earlier forms of the matcher on the extension path: anchored patterns bucketed by first byte 205 ns; the path split once 143 ns; grouped by first segment 92-94 ns (above). A run while the sanitizer build compiled on the same cores gave 161 ns: measure on a quiet machine.

## refuse_bench.cpp

```cpp
#include <chrono>
#include <cstdio>
#include "core/refuse.hpp"
using namespace agensio;
int main() {
    const char* texts[] = {"composer.json", "composer.lock", "flexform*.xml", "locallang*.xml", "locallang*.xlf", "ext_conf_template.txt",
        "ext_typoscript_*.txt", "*.bak", "*.conf", "*.cnf", "*.cfg", "*.yaml", "*.yml", "*.ts", "*.typoscript", "*.tsconfig", "*.dist", "*.fla",
        "*.inc", "*.ini", "*.log", "*.sh", "*.sql", "*.sqlite", "_recycler_/", "_temp_/", "/fileadmin/templates/**/*.txt", "/vendor/",
        "/typo3_src/", "/typo3temp/var/", "/typo3conf/ext/*/Configuration/", "/typo3conf/ext/*/Resources/Private/", "/typo3conf/ext/*/Tests/",
        "/typo3conf/ext/*/Test/", "/typo3conf/ext/*/docs/", "/typo3conf/ext/*/doc/", "/typo3/sysext/*/Configuration/",
        "/typo3/sysext/*/Resources/Private/", "/typo3/sysext/*/Tests/", "/typo3/sysext/*/Test/", "/typo3/sysext/*/docs/", "/typo3/sysext/*/doc/",
        "/typo3/ext/*/Configuration/", "/typo3/ext/*/Resources/Private/", "/typo3/ext/*/Tests/", "/typo3/ext/*/Test/", "/typo3/ext/*/docs/", "/typo3/ext/*/doc/"};
    RefuseSet set;
    for (const char* t : texts) { RefusePattern p; refuse::compile(t, p); set.patterns.push_back(p); }
    refuse::index(set);
    const char* paths[] = {"/", "/en/about-us", "/fileadmin/user_upload/photo.jpg", "/typo3conf/ext/news/Resources/Public/Css/news.css", "/_assets/abc/Css/x.css"};
    for (const char* path : paths) {
        const int n = 5000000;
        int hits = 0;
        auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < n; ++i) hits += refuse::match(set, path) != nullptr;
        auto t1 = std::chrono::steady_clock::now();
        std::printf("%-55s %6.1f ns  (hits %d)\n", path, std::chrono::duration<double, std::nano>(t1 - t0).count() / n, hits);
    }
}
```
