cmake_minimum_required(VERSION 3.28)

# zetta-tunnel is C++26, like zetta. When no compiler is chosen, pick one that builds C++26 before
# project(): Homebrew LLVM on macOS, the newest clang >= 17 on Linux. Opt out with
# -DZETTA_TUNNEL_USE_SYSTEM_COMPILER=ON or by passing -DCMAKE_CXX_COMPILER=...
if(NOT DEFINED CMAKE_CXX_COMPILER AND NOT ZETTA_TUNNEL_USE_SYSTEM_COMPILER)
  if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin" AND EXISTS "/opt/homebrew/opt/llvm/bin/clang++")
    set(CMAKE_C_COMPILER   "/opt/homebrew/opt/llvm/bin/clang"   CACHE FILEPATH "")
    set(CMAKE_CXX_COMPILER "/opt/homebrew/opt/llvm/bin/clang++" CACHE FILEPATH "")
    if(NOT CMAKE_OSX_SYSROOT)
      execute_process(COMMAND xcrun --show-sdk-path
                      OUTPUT_VARIABLE ZETTA_TUNNEL_SDKROOT OUTPUT_STRIP_TRAILING_WHITESPACE)
      set(CMAKE_OSX_SYSROOT "${ZETTA_TUNNEL_SDKROOT}" CACHE PATH "")
    endif()
  elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    foreach(ZETTA_TUNNEL_VER 21 20 19 18 17)
      find_program(ZETTA_TUNNEL_CLANGXX_${ZETTA_TUNNEL_VER} "clang++-${ZETTA_TUNNEL_VER}")
      if(ZETTA_TUNNEL_CLANGXX_${ZETTA_TUNNEL_VER})
        set(CMAKE_CXX_COMPILER "${ZETTA_TUNNEL_CLANGXX_${ZETTA_TUNNEL_VER}}" CACHE FILEPATH "")
        break()
      endif()
    endforeach()
  endif()
endif()

project(zetta-tunnel
  VERSION 0.0.1
  DESCRIPTION "Orama's own tunnels: developer access to services, apps and deployments"
  LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

configure_file(src/version.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/generated/zetta_tunnel/version.hpp @ONLY)

set(BOOST_CAPY_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(BOOST_CAPY_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BOOST_CAPY_BUILD_BENCH OFF CACHE BOOL "" FORCE)
add_subdirectory(modules/capy EXCLUDE_FROM_ALL)

if(APPLE)
  list(APPEND CMAKE_PREFIX_PATH /opt/homebrew/opt/openssl@3)
endif()
find_package(OpenSSL 3 REQUIRED)
set(BOOST_COROSIO_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(BOOST_COROSIO_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BOOST_COROSIO_BUILD_PERF OFF CACHE BOOL "" FORCE)
add_subdirectory(modules/corosio EXCLUDE_FROM_ALL)

add_library(zetta_tunnel_transport src/transport.cpp)
add_library(zetta-tunnel::transport ALIAS zetta_tunnel_transport)
if(NOT BUILD_SHARED_LIBS)
  target_compile_definitions(zetta_tunnel_transport PUBLIC ZETTA_TUNNEL_TRANSPORT_STATIC)
endif()
target_include_directories(zetta_tunnel_transport
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(zetta_tunnel_transport
  PRIVATE
    Boost::capy
    Boost::corosio
    Boost::corosio_openssl
)
target_compile_options(zetta_tunnel_transport PRIVATE -Wall -Wextra -Wpedantic -Werror)
set_target_properties(zetta_tunnel_transport PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN YES
)

add_executable(zetta-tunnel src/main.cpp)
target_include_directories(zetta-tunnel PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_compile_options(zetta-tunnel PRIVATE -Wall -Wextra -Wpedantic -Werror)

enable_testing()
add_test(NAME version_reports_project_version COMMAND zetta-tunnel --version)
set_tests_properties(version_reports_project_version PROPERTIES
  PASS_REGULAR_EXPRESSION "^zetta-tunnel ${PROJECT_VERSION}\n$")
add_test(NAME unknown_argument_fails COMMAND zetta-tunnel --no-such-flag)
set_tests_properties(unknown_argument_fails PROPERTIES WILL_FAIL TRUE)

add_executable(transport_test tests/transport_test.cpp)
target_link_libraries(transport_test
  PRIVATE
    zetta_tunnel_transport
    Boost::capy
    Boost::corosio
    Boost::corosio_openssl
    OpenSSL::Crypto
)
target_compile_options(transport_test PRIVATE -Wall -Wextra -Wpedantic -Werror)

foreach(ZETTA_TUNNEL_TRANSPORT_CASE
    exchange
    no_certificate
    other_ca
    expired_certificate
    wrong_identity)
  add_test(
    NAME transport_${ZETTA_TUNNEL_TRANSPORT_CASE}
    COMMAND transport_test ${ZETTA_TUNNEL_TRANSPORT_CASE}
  )
  set_tests_properties(transport_${ZETTA_TUNNEL_TRANSPORT_CASE} PROPERTIES TIMEOUT 20)
endforeach()
