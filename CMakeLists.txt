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
  src/http_parser.cpp
  src/cache.cpp
  src/response.cpp
  src/handler.cpp
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
  target_compile_options(agensio_core PUBLIC /W4 /permissive-)
else()
  target_compile_options(agensio_core PUBLIC -Wall -Wextra -Wpedantic
    $<$<BOOL:${AGENSIO_NATIVE}>:-march=native>)
endif()

add_executable(agensio src/main.cpp)
target_link_libraries(agensio PRIVATE agensio_core)

# ---------------------------------------------------------------- tests
if(AGENSIO_TESTS)
  enable_testing()
  add_executable(agensio_tests tests/tests.cpp)
  target_link_libraries(agensio_tests PRIVATE agensio_core)
  add_test(NAME unit COMMAND agensio_tests)
endif()
