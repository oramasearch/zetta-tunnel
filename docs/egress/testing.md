# Egress gateway verification

The native suite starts the real `zetta-tunnel egress` process, independent TCP/TLS clients, plain
and TLS echo destinations, and isolated operator rule files. It verifies:

- exact allowed names over the `ZTEG1` preface and over a real fragmented-capable TLS ClientHello;
- forbidden explicit and SNI names without opening a destination connection;
- a forbidden alias even when the workload treats it as resolving to the allowed address;
- IP literals and source IPs absent from the projected rule;
- strict bounded rule/config parsing;
- live removal, invalid snapshots, readiness recovery, capacity and audit-before-forwarding;
- the existing transport and developer-tunnel suite for regressions.

Run the repository proof natively:

```sh
git submodule update --init --recursive
cmake -S . -B build -G Ninja
cmake --build build -j 6
ctest --test-dir build --output-on-failure
```

The tests use loopback DNS and sockets only. They do not require Docker, an external DNS service or
an internet destination.
