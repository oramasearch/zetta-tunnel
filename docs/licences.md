# Dependency licences

Only permissively licensed dependencies are linked.

| Dependency | Use | Licence | Source in this repository |
|---|---|---|---|
| Capy | Coroutine tasks, buffers and execution | Boost Software License 1.0 | `modules/capy/LICENSE` |
| Corosio | TCP, DNS and the OpenSSL TLS provider | Boost Software License 1.0 | `modules/corosio/LICENSE` |
| OpenSSL 3 | TLS 1.3 and test certificate generation | Apache License 2.0 | System package found by CMake |
| nlohmann/json 3.12 | Strict grant/rule/peer JSON parsing and JSON-lines audit encoding (header-only) | MIT | System CMake package `nlohmann_json`; upstream `https://github.com/nlohmann/json/blob/v3.12.0/LICENSE.MIT` |

The test runner uses Python 3's standard library (PSF License 2.0); it is not linked or shipped in
the binary. CMake finds the system interpreter. The optional database proof invokes the system
PostgreSQL `psql` client (PostgreSQL License); no database client library is linked or shipped.

Capy and Corosio are pinned git submodules. They are configured without their tests, examples,
benchmarks or performance tools, so their development-only dependencies are not linked into
zetta-tunnel.
