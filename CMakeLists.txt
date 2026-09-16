cmake_minimum_required(VERSION 3.24)
project(agensio VERSION 0.1.0 LANGUAGES CXX)

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
  src/response.cpp
  src/handlers/static.cpp
  src/server.cpp)
target_include_directories(agensio_core PUBLIC src)
target_link_libraries(agensio_core PUBLIC asio tomlplusplus)
target_compile_definitions(agensio_core PUBLIC
  AGENSIO_VERSION="${PROJECT_VERSION}"
  $<$<BOOL:${AGENSIO_HAS_TLS}>:AGENSIO_HAS_TLS=1>)
if(AGENSIO_HAS_TLS)
  target_link_libraries(agensio_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
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

# ---------------------------------------------------------------- fuzzers (parsers only, no asio)
if(AGENSIO_FUZZ)
  foreach(t parser path chunked)
    add_executable(fuzz_${t} tests/fuzz/fuzz_${t}.cpp src/http1/parser.cpp src/path.cpp)
    target_include_directories(fuzz_${t} PRIVATE src)
    target_compile_features(fuzz_${t} PRIVATE cxx_std_20)
    target_compile_options(fuzz_${t} PRIVATE -fsanitize=fuzzer,address,undefined -g -O1 -fno-omit-frame-pointer)
    target_link_options(fuzz_${t} PRIVATE -fsanitize=fuzzer,address,undefined)
  endforeach()
endif()
