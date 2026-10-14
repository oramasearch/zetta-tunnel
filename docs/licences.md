# Dependency licences

Only permissively licensed dependencies are linked.

| Dependency | Use | Licence | Source in this repository |
|---|---|---|---|
| Capy | Coroutine tasks, buffers and execution | Boost Software License 1.0 | `modules/capy/LICENSE` |
| Corosio | TCP, DNS and the OpenSSL TLS provider | Boost Software License 1.0 | `modules/corosio/LICENSE` |
| OpenSSL 3 | TLS 1.3 and test certificate generation | Apache License 2.0 | System package found by CMake |

Capy and Corosio are pinned git submodules. They are configured without their tests, examples,
benchmarks or performance tools, so their development-only dependencies are not linked into
zetta-tunnel.
