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

add_executable(zetta-tunnel src/main.cpp)
target_include_directories(zetta-tunnel PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_compile_options(zetta-tunnel PRIVATE -Wall -Wextra -Wpedantic -Werror)

enable_testing()
add_test(NAME version_reports_project_version COMMAND zetta-tunnel --version)
set_tests_properties(version_reports_project_version PROPERTIES
  PASS_REGULAR_EXPRESSION "^zetta-tunnel ${PROJECT_VERSION}\n$")
add_test(NAME unknown_argument_fails COMMAND zetta-tunnel --no-such-flag)
set_tests_properties(unknown_argument_fails PROPERTIES WILL_FAIL TRUE)
