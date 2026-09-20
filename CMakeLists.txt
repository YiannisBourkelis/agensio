cmake_minimum_required(VERSION 3.24)
project(agensio VERSION 0.1.0 LANGUAGES CXX)
set(AGENSIO_VERSION_STRING "0.1.0-alpha.10")  # what `agensio -v`, the status command and the release tag say

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(AGENSIO_TLS "Build TLS support (requires OpenSSL)" ON)
option(AGENSIO_TESTS "Build unit tests" ON)
option(AGENSIO_NATIVE "Compile for the build machine's CPU (-march=native)" OFF)
option(AGENSIO_HARDEN "Hardened build: stack protector, fortify, hardened std library, zero-init locals, RELRO/PIE" ON)
set(AGENSIO_SANITIZE "" CACHE STRING "Sanitizers for all targets, e.g. address,undefined")
option(AGENSIO_FUZZ "Build libFuzzer targets (needs clang with libFuzzer, e.g. brew llvm)" OFF)
option(AGENSIO_HARDEN_ZERO_INIT "Part of AGENSIO_HARDEN: zero-initialise automatic variables (-ftrivial-auto-var-init=zero)" ON)

# ---------------------------------------------------------------- asio (standalone, header-only)
find_path(ASIO_INCLUDE_DIR asio.hpp
  HINTS ${ASIO_ROOT} $ENV{ASIO_ROOT}
  PATHS /opt/homebrew/include /usr/local/include /usr/include)
if(NOT ASIO_INCLUDE_DIR)
  message(STATUS "asio not found on the system, fetching asio-1-38-2 from GitHub")
  include(FetchContent)
  FetchContent_Declare(asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG        asio-1-38-2
    GIT_SHALLOW    TRUE)
  FetchContent_MakeAvailable(asio)
  set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/asio/include)
endif()
message(STATUS "asio include dir: ${ASIO_INCLUDE_DIR}")

find_package(Threads REQUIRED)
add_library(asio INTERFACE)
target_include_directories(asio SYSTEM INTERFACE ${ASIO_INCLUDE_DIR})
target_compile_definitions(asio INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED
  $<$<PLATFORM_ID:Windows>:_WIN32_WINNT=0x0A00>)
target_link_libraries(asio INTERFACE Threads::Threads)

# ---------------------------------------------------------------- toml++ (vendored, header-only)
add_library(tomlplusplus INTERFACE)
target_include_directories(tomlplusplus SYSTEM INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/tomlplusplus)

# ---------------------------------------------------------------- OpenSSL (optional)
set(AGENSIO_HAS_TLS OFF)
if(AGENSIO_TLS)
  if(APPLE AND NOT OPENSSL_ROOT_DIR)
    execute_process(COMMAND brew --prefix openssl@3 OUTPUT_VARIABLE _brew_ssl
                    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(_brew_ssl)
      set(OPENSSL_ROOT_DIR ${_brew_ssl})
    endif()
  endif()
  find_package(OpenSSL)
  if(OpenSSL_FOUND)
    set(AGENSIO_HAS_TLS ON)
    message(STATUS "TLS enabled with OpenSSL ${OPENSSL_VERSION}")
  else()
    message(WARNING "OpenSSL not found; building without TLS")
  endif()
endif()

# ---------------------------------------------------------------- zlib (optional: site-install archives)
# gzip and deflate for the archive extractor behind `site-install` (.tar.gz and .zip);
# present on every Linux, macOS and BSD system. Without it plain .tar still works.
find_package(ZLIB)
set(AGENSIO_HAS_ZLIB ${ZLIB_FOUND})
if(NOT ZLIB_FOUND)
  message(WARNING "zlib not found; site-install handles only plain .tar archives")
endif()

# ---------------------------------------------------------------- core library
add_library(agensio_core STATIC
  src/config.cpp
  src/http_date.cpp
  src/mime.cpp
  src/file.cpp
  src/path.cpp
  src/http1/parser.cpp
  src/cache.cpp
  src/core/router.cpp
  src/services/log.cpp
  src/services/pools.cpp
  src/services/acme.cpp
  src/services/provision.cpp
  src/services/archive.cpp
  src/services/fetch.cpp
  src/services/install.cpp
  src/control/handler.cpp
  src/control/commands.cpp
  src/control/sites.cpp
  src/control/mcp.cpp
  src/control/client.cpp
  src/response.cpp
  src/handlers/static.cpp
  src/handlers/fastcgi.cpp
  src/handlers/proxy.cpp
  src/handlers/cgi.cpp
  src/handlers/upstream_common.cpp
  src/handlers/dispatch.cpp
  src/upstream/client.cpp
  src/upstream/fcgi_client.cpp
  src/upstream/http_client.cpp
  src/upstream/cgi_client.cpp
  src/server.cpp)
target_include_directories(agensio_core PUBLIC src)
target_link_libraries(agensio_core PUBLIC asio tomlplusplus)
target_compile_definitions(agensio_core PUBLIC
  AGENSIO_VERSION="${AGENSIO_VERSION_STRING}"
  $<$<BOOL:${AGENSIO_HAS_TLS}>:AGENSIO_HAS_TLS=1>
  $<$<BOOL:${AGENSIO_HAS_ZLIB}>:AGENSIO_HAS_ZLIB=1>)
if(AGENSIO_HAS_TLS)
  target_link_libraries(agensio_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()
if(AGENSIO_HAS_ZLIB)
  target_link_libraries(agensio_core PUBLIC ZLIB::ZLIB)
endif()
if(MSVC)
  target_compile_options(agensio_core PUBLIC /W4 /permissive- $<$<BOOL:${AGENSIO_HARDEN}>:/GS /guard:cf /sdl>)
else()
  target_compile_options(agensio_core PUBLIC -Wall -Wextra -Wpedantic
    $<$<BOOL:${AGENSIO_NATIVE}>:-march=native>)
  if(AGENSIO_HARDEN)
    # Measured cost of this set on the request path: see CLAUDE.md "Performance notes".
    target_compile_options(agensio_core PUBLIC -fstack-protector-strong
      $<$<BOOL:${AGENSIO_HARDEN_ZERO_INIT}>:-ftrivial-auto-var-init=zero>)
    target_compile_definitions(agensio_core PUBLIC
      $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>
      _LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST   # libc++: bounds checks on [] and iterators
      _GLIBCXX_ASSERTIONS)                                 # libstdc++: same
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      set_target_properties(agensio_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
      target_link_options(agensio_core PUBLIC -Wl,-z,relro,-z,now -pie)
    endif()
  endif()
  if(AGENSIO_SANITIZE)
    target_compile_options(agensio_core PUBLIC -fsanitize=${AGENSIO_SANITIZE} -fno-omit-frame-pointer -g)
    target_link_options(agensio_core PUBLIC -fsanitize=${AGENSIO_SANITIZE})
  endif()
endif()

add_executable(agensio src/main.cpp)
target_link_libraries(agensio PRIVATE agensio_core)

# ---------------------------------------------------------------- tests
if(AGENSIO_TESTS)
  enable_testing()
  add_executable(agensio_tests tests/tests.cpp)
  target_link_libraries(agensio_tests PRIVATE agensio_core)
  target_compile_definitions(agensio_tests PRIVATE AGENSIO_REGRESSIONS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/regressions")
  add_test(NAME unit COMMAND agensio_tests)
endif()

if(AGENSIO_TESTS AND NOT WIN32)
  add_test(NAME integration COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration.sh $<TARGET_FILE:agensio>)
endif()

add_executable(agensio_bench_header tests/bench_header.cpp)

# Benchmark upstream for the reverse proxy (roadmap D0): shares nothing with agensio_core.
add_executable(agensio_upstream bench/upstream/upstream.cpp)
target_link_libraries(agensio_upstream PRIVATE asio Threads::Threads)

# ---------------------------------------------------------------- fuzzers (parsers only, no asio)
if(AGENSIO_FUZZ)
  foreach(t parser path chunked fcgi http_head json archive)
    add_executable(fuzz_${t} tests/fuzz/fuzz_${t}.cpp src/http1/parser.cpp src/path.cpp src/services/archive.cpp)
    target_include_directories(fuzz_${t} PRIVATE src)
    target_compile_features(fuzz_${t} PRIVATE cxx_std_20)
    target_compile_definitions(fuzz_${t} PRIVATE $<$<BOOL:${AGENSIO_HAS_ZLIB}>:AGENSIO_HAS_ZLIB=1>)
    target_compile_options(fuzz_${t} PRIVATE -fsanitize=fuzzer,address,undefined -g -O1 -fno-omit-frame-pointer)
    target_link_options(fuzz_${t} PRIVATE -fsanitize=fuzzer,address,undefined)
    if(AGENSIO_HAS_ZLIB)
      target_link_libraries(fuzz_${t} PRIVATE ZLIB::ZLIB)
    endif()
  endforeach()
endif()

# ---------------------------------------------------------------- install and packages (H7)
include(GNUInstallDirs)
set(CMAKE_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(TARGETS agensio RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(FILES packaging/etc/agensio.toml DESTINATION /etc/agensio)
install(FILES packaging/etc/sites.d/default.toml DESTINATION /etc/agensio/sites.d)
install(FILES packaging/agensio.logrotate DESTINATION /etc/logrotate.d RENAME agensio)
install(FILES packaging/agensio.service DESTINATION /usr/lib/systemd/system)
install(FILES packaging/www/index.html DESTINATION ${CMAKE_INSTALL_DATADIR}/agensio/www)
install(FILES README.md CHANGELOG.md LICENSE docs/configuration.md docs/install.md docs/mcp.md
              docs/security-control-plane.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(DIRECTORY docs/examples DESTINATION ${CMAKE_INSTALL_DOCDIR})

set(CPACK_PACKAGE_NAME agensio)
set(CPACK_PACKAGE_VENDOR "Yiannis Bourkelis")
set(CPACK_PACKAGE_CONTACT "Yiannis Bourkelis <yiannis@grbytes.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Fast web server with PHP, reverse proxy, automatic TLS and an MCP control plane")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/YiannisBourkelis/agensio")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX /usr)
set(CPACK_STRIP_FILES ON)
set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE)
set(CPACK_GENERATOR "DEB;RPM")
# Debian: a pre-release sorts before the release with a tilde.
string(REPLACE "-" "~" AGENSIO_DEB_VERSION ${AGENSIO_VERSION_STRING})
set(CPACK_DEBIAN_PACKAGE_VERSION ${AGENSIO_DEB_VERSION})
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SECTION httpd)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "adduser")
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "php-fpm, logrotate")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    ${CMAKE_CURRENT_SOURCE_DIR}/packaging/deb/conffiles
    ${CMAKE_CURRENT_SOURCE_DIR}/packaging/deb/postinst
    ${CMAKE_CURRENT_SOURCE_DIR}/packaging/deb/prerm
    ${CMAKE_CURRENT_SOURCE_DIR}/packaging/deb/postrm)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)
# /etc files are conffiles (packaging/deb/conffiles): dpkg keeps the administrator's edits on upgrade.
# RPM: version without the pre-release part, release carries it.
set(CPACK_RPM_PACKAGE_VERSION ${PROJECT_VERSION})
string(REGEX REPLACE "^[0-9.]+-?" "" AGENSIO_PRERELEASE ${AGENSIO_VERSION_STRING})
if(AGENSIO_PRERELEASE)
  string(REPLACE "." "" AGENSIO_PRERELEASE_TAG ${AGENSIO_PRERELEASE})
  set(CPACK_RPM_PACKAGE_RELEASE "0.1.${AGENSIO_PRERELEASE_TAG}")
else()
  set(CPACK_RPM_PACKAGE_RELEASE 1)
endif()
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_RELOCATABLE OFF)  # a system package: /etc and /usr/lib are not relocatable
set(CPACK_RPM_PACKAGE_LICENSE MIT)
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Daemons")
set(CPACK_RPM_PACKAGE_REQUIRES "openssl-libs, zlib, shadow-utils")
set(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/packaging/rpm/pre)
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/packaging/rpm/post)
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/packaging/rpm/preun)
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/etc/agensio;/etc/logrotate.d;/usr/lib/systemd;/usr/lib/systemd/system;/var;/var/www")
set(CPACK_RPM_USER_FILELIST "%config(noreplace) %attr(0640,root,agensio) /etc/agensio/agensio.toml"
                            "%config(noreplace) /etc/agensio/sites.d/default.toml"
                            "%config(noreplace) /etc/logrotate.d/agensio")
include(CPack)

