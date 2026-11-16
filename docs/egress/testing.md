# Egress gateway verification

The native suite starts the real `zetta-tunnel egress` process, independent TCP/TLS clients, plain
and TLS echo destinations, and isolated operator rule files. It verifies:

- exact allowed names over the `ZTEG1` preface and over a real fragmented-capable TLS ClientHello;
- forbidden explicit and SNI names without opening a destination connection;
- a forbidden alias even when the workload treats it as resolving to the allowed address;
- IP literals and source IPs absent from the projected rule;
- public IPv4/IPv6 acceptance and special-use address rejection, including IPv4-mapped forms;
- zero connect attempts for permitted names resolving to private, loopback, link-local, metadata,
  cluster, transition or mixed public/private destinations, over explicit routing and SNI;
- operator-projected public-numbered cluster exclusions, strict CIDR parsing and live exclusion reload;
- fresh address checks after DNS rebinding while existing connections keep their numeric endpoint;
- strict bounded rule/config parsing;
- live removal, projected-volume symlink replacement, invalid snapshots and readiness recovery;
- setup deadlines, capacity and audit-before-forwarding;
- the existing transport and developer-tunnel suite for regressions.

Run the repository proof natively:

```sh
git submodule update --init --recursive
cmake -S . -B build -G Ninja
cmake --build build -j 6
ctest --test-dir build --output-on-failure
```

The tests use local sockets only. On Linux/macOS, `egress_network_fixture` is loaded only into
the gateway child process: it gives `localhost` deterministic numeric DNS answers, records every
connect attempt, maps the public fixture address to the local echo server and refuses external
connections. On Linux it is loaded with `LD_PRELOAD` and reaches the real `getaddrinfo` and
`connect` through `dlsym(RTLD_NEXT, ...)`. On macOS it is loaded with `DYLD_INSERT_LIBRARIES`
and replaces them through `__interpose`; there it calls the originals by name, because dyld does
not interpose calls made from the interposing image. It supplies no policy override. Existing
forwarding, reload, admission and audit checks therefore still exercise the production executable through the new address policy.
The forbidden-destination checks require `destination_forbidden` and no connect attempts; the
mixed-answer check puts a usable public answer first to catch early-connect bypasses. The
classification unit test covers range endpoints, mapped encodings and projected IPv4/IPv6 CIDRs.
No external DNS service or internet destination is required. The socket fixture requires POSIX;
native Windows validation is pending.
