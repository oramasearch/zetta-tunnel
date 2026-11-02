# Dependency licences

Only permissively licensed dependencies are linked.

| Dependency | Use | Licence | Source in this repository |
|---|---|---|---|
| Capy | Coroutine tasks, buffers and execution | Boost Software License 1.0 | `modules/capy/LICENSE` |
| Corosio | TCP, DNS and the OpenSSL TLS provider | Boost Software License 1.0 | `modules/corosio/LICENSE` |
| OpenSSL 3 | TLS 1.3 and test certificate generation | Apache License 2.0 | System package found by CMake; statically linked into the release image binary |
| nlohmann/json 3.12 | Strict grant/rule/peer/ingress/mesh JSON parsing and JSON-lines audit encoding (header-only) | MIT | Native system CMake package; image build downloads upstream `v3.12.0` with a pinned SHA-256; upstream `https://github.com/nlohmann/json/blob/v3.12.0/LICENSE.MIT` |
| nghttp2 >= 1.61 (native proof: 1.68.0) | Ingress HTTP/2 framing, HPACK, streams and windows | MIT | System pkg-config package `libnghttp2`; statically linked into the release image binary; upstream `https://github.com/nghttp2/nghttp2/blob/v1.68.0/COPYING` |
| musl libc | Linux C library in the static release binary | MIT | Alpine build package; upstream `https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT` |
| LLVM libc++ and libunwind | C++ runtime and stack unwinding in the static release binary | Apache License 2.0 with LLVM exceptions | Alpine build packages; upstream `https://github.com/llvm/llvm-project/blob/main/LICENSE.TXT` |
| LLVM compiler-rt | Compiler support routines in the static release binary | Apache License 2.0 with LLVM exceptions | Alpine `clang20-rtlib` build package; upstream `https://github.com/llvm/llvm-project/blob/main/LICENSE.TXT` |

The test runner uses Python 3's standard library (PSF License 2.0); it is not linked or shipped in
the binary. CMake finds the system interpreter. The optional database proof invokes the system
PostgreSQL `psql` client (PostgreSQL License); no database client library is linked or shipped.
The privileged mesh proof invokes the system `ip` command to create temporary Linux network
namespaces; it is test infrastructure and is not linked into the binary or included in the
production image. Mesh capture uses Linux kernel UAPI headers and the nftables netlink protocol
directly, with no added library or executable.

The egress integration fixture uses the platform's socket and dynamic-loader APIs, with no new
third-party package. It is loaded only into test gateway processes and is not linked into,
installed with or shipped in the application.

The production image is `scratch` plus the static binary, so it ships no Alpine packages, shell,
package manager or certificate bundle. The Dockerfile's separate `mesh-proof` target is test
infrastructure and includes Python 3 and `iproute2`; it is not a release target or runtime
dependency.

Capy and Corosio are pinned git submodules. They are configured without their tests, examples,
benchmarks or performance tools, so their development-only dependencies are not linked into
zetta-tunnel.
