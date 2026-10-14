# Peer gateway verification

The native suite starts two real `zetta-tunnel peer` processes, a TCP destination, independent
clients and isolated operator projections. Both simulated sites project the exact same private
target address and port. Service names, rather than those colliding addresses, select the allowed
path. The cases verify:

- binary traffic in both directions through named imports and exports;
- matching allow records at the importing and exporting gateways;
- an unexported name refused before a target connection;
- mutual TLS with exact remote identities, including missing and wrong client identities;
- removal of the peer projection closing a live session and refusing later traffic;
- valid service removal and restoration, invalid projections and readiness recovery;
- strict bounded configuration parsing;
- TLS/request setup deadlines and combined import/export capacity;
- audit-before-forwarding and audit sink failure closing the path;
- health probes remaining responsive under stalled and full session sets;
- all transport, developer-tunnel and egress cases for regressions.

Run the repository proof natively:

```sh
git submodule update --init --recursive
cmake -S . -B build -G Ninja
cmake --build build -j 6
ctest --test-dir build --output-on-failure
```

The tests use loopback sockets and generated short-lived certificates only. They do not require
Docker, Kubernetes, external DNS or an internet destination.
