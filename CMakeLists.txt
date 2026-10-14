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
  DESCRIPTION "Orama's own tunnels, mesh and ingress network layer"
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
find_package(Threads REQUIRED)
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
find_package(nlohmann_json 3.12 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NGHTTP2 REQUIRED IMPORTED_TARGET libnghttp2>=1.61)
add_library(zetta_tunnel_roles STATIC
  src/egress.cpp
  src/egress_config.cpp
  src/ingress.cpp
  src/ingress_config.cpp
  src/ingress_h2.cpp
  src/ingress_http.cpp
  src/ingress_tls.cpp
  src/mesh_config.cpp
  src/mesh_diagnostics.cpp
  src/mesh_netlink.cpp
  src/peer.cpp
  src/peer_config.cpp
  src/tunnel.cpp
  src/tunnel_config.cpp
  src/tunnel_io.cpp
)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_sources(zetta_tunnel_roles PRIVATE src/mesh_linux.cpp)
else()
  target_sources(zetta_tunnel_roles PRIVATE src/mesh_stub.cpp)
endif()
target_link_libraries(zetta_tunnel_roles PUBLIC
  zetta_tunnel_transport
  Boost::capy
  Boost::corosio
  OpenSSL::SSL
  Threads::Threads
  nlohmann_json::nlohmann_json
  PkgConfig::NGHTTP2
)
target_include_directories(zetta_tunnel_roles PUBLIC src)
target_compile_options(zetta_tunnel_roles PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(zetta-tunnel PRIVATE zetta_tunnel_roles)
target_include_directories(zetta-tunnel PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_compile_options(zetta-tunnel PRIVATE -Wall -Wextra -Wpedantic -Werror)

enable_testing()
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME version_reports_project_version COMMAND zetta-tunnel --version)
set_tests_properties(version_reports_project_version PROPERTIES
  PASS_REGULAR_EXPRESSION "^zetta-tunnel ${PROJECT_VERSION}\n$")
add_test(NAME unknown_argument_fails COMMAND zetta-tunnel --no-such-flag)
set_tests_properties(unknown_argument_fails PROPERTIES WILL_FAIL TRUE)
add_test(NAME image_contract
  COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/image_contract.py
    $<TARGET_FILE:zetta-tunnel> ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_VERSION})

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

add_executable(tunnel_certificates tests/tunnel_certificates.cpp)
target_link_libraries(tunnel_certificates PRIVATE OpenSSL::Crypto)
target_compile_options(tunnel_certificates PRIVATE -Wall -Wextra -Wpedantic -Werror)
foreach(ZETTA_TUNNEL_CASE
    roundtrip revoke expiry expired_cert unknown_grant wrong_ca no_uri multiple_uri
    long_lived certificate_bound expired_grant endpoint_identity relay_identity
    server_identity target_isolation invalid_reload sighup capacity postgres
    tls_boundaries backpressure setup_timeout projected_reload removed_file grant_change
    audit_failure invalid_credentials)
  add_test(NAME tunnel_${ZETTA_TUNNEL_CASE}
    COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/tunnel_integration.py
      $<TARGET_FILE:zetta-tunnel> $<TARGET_FILE:tunnel_certificates> ${ZETTA_TUNNEL_CASE})
  set_tests_properties(tunnel_${ZETTA_TUNNEL_CASE} PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE)
endforeach()
set_tests_properties(tunnel_postgres PROPERTIES SKIP_RETURN_CODE 77)

add_executable(ingress_http_test tests/ingress_http_test.cpp)
target_link_libraries(ingress_http_test PRIVATE zetta_tunnel_roles)
target_compile_options(ingress_http_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME ingress_http_validation COMMAND ingress_http_test)
foreach(ZETTA_TUNNEL_INGRESS_CASE
    hosts routing tls body_limit streaming websocket http2 h2_streaming h2_reset upstream_tls
    reload certificate_reload config_validation capacity timeout headers keepalive audit_failure
    h2_limits h2_backpressure h2_upload_flow projected_reload early_response slow_headers upstream_framing)
  add_test(NAME ingress_${ZETTA_TUNNEL_INGRESS_CASE}
    COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/ingress_integration.py
      $<TARGET_FILE:zetta-tunnel> $<TARGET_FILE:tunnel_certificates> ${ZETTA_TUNNEL_INGRESS_CASE})
  set_tests_properties(ingress_${ZETTA_TUNNEL_INGRESS_CASE} PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)
endforeach()

add_executable(tunnel_config_test tests/tunnel_config_test.cpp)
target_link_libraries(tunnel_config_test PRIVATE zetta_tunnel_roles)
target_compile_options(tunnel_config_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME tunnel_config_validation COMMAND tunnel_config_test)

add_executable(egress_config_test tests/egress_config_test.cpp)
target_link_libraries(egress_config_test PRIVATE zetta_tunnel_roles)
target_compile_options(egress_config_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME egress_config_validation COMMAND egress_config_test)

add_executable(peer_config_test tests/peer_config_test.cpp)
target_link_libraries(peer_config_test PRIVATE zetta_tunnel_roles)
target_compile_options(peer_config_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME peer_config_validation COMMAND peer_config_test)

add_executable(mesh_config_test tests/mesh_config_test.cpp)
target_link_libraries(mesh_config_test PRIVATE zetta_tunnel_roles)
target_compile_options(mesh_config_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME mesh_config_validation COMMAND mesh_config_test)
add_executable(mesh_netlink_test tests/mesh_netlink_test.cpp)
target_link_libraries(mesh_netlink_test PRIVATE zetta_tunnel_roles)
target_compile_options(mesh_netlink_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME mesh_netlink_wire COMMAND mesh_netlink_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/mesh)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_test(NAME mesh_linux_fail_closed
    COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/mesh_linux_integration.py
      $<TARGET_FILE:zetta-tunnel> $<TARGET_FILE:tunnel_certificates>)
  set_tests_properties(mesh_linux_fail_closed PROPERTIES
    TIMEOUT 90
    RUN_SERIAL TRUE
    SKIP_RETURN_CODE 77)
endif()

foreach(ZETTA_TUNNEL_EGRESS_CASE
    allowed
    sni
    sni_denied
    denied
    ip_literal
    rebinding
    source_binding
    reload
    invalid_reload
    projected_reload
    setup_timeout
    capacity
    audit_failure)
  add_test(NAME egress_${ZETTA_TUNNEL_EGRESS_CASE}
    COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/egress_integration.py
      $<TARGET_FILE:zetta-tunnel> $<TARGET_FILE:tunnel_certificates>
      ${ZETTA_TUNNEL_EGRESS_CASE})
  set_tests_properties(egress_${ZETTA_TUNNEL_EGRESS_CASE} PROPERTIES TIMEOUT 45 RUN_SERIAL TRUE)
endforeach()

foreach(ZETTA_TUNNEL_PEER_CASE
    roundtrip
    named_only
    revoke
    mutual_tls
    reload
    invalid_reload
    setup_timeout
    capacity
    audit_failure)
  add_test(NAME peer_${ZETTA_TUNNEL_PEER_CASE}
    COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/peer_integration.py
      $<TARGET_FILE:zetta-tunnel> $<TARGET_FILE:tunnel_certificates>
      ${ZETTA_TUNNEL_PEER_CASE})
  set_tests_properties(peer_${ZETTA_TUNNEL_PEER_CASE} PROPERTIES TIMEOUT 45 RUN_SERIAL TRUE)
endforeach()
