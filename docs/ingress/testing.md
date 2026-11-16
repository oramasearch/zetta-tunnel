# Ingress verification

Build prerequisites include C++26/Clang, CMake, Ninja, OpenSSL, nlohmann/json, pkg-config and
**libnghttp2 1.61 or newer**. On macOS add `brew install pkgconf libnghttp2`; Linux needs
pkg-config and libnghttp2 development headers/libraries. Tests and benchmarks use Python's
standard library. No containers, Kubernetes access or external backend are needed locally.

```sh
cmake -S . -B build -G Ninja
cmake --build build -j 6
ctest --test-dir build --output-on-failure
cmake -S . -B build-shared -G Ninja -DBUILD_SHARED_LIBS=ON
cmake --build build-shared -j 6
ctest --test-dir build-shared --output-on-failure
```

Submodules must match the checkout. With read-only git metadata inspect `git submodule status
--recursive`; initialization/update belongs to the coordinator. Run suites serially. The
inherited PostgreSQL proof uses the native server per [tunnel verification](../tunnel/testing.md).
Use the Linux proof helper when present; otherwise record `Linux proof deferred`.

`ingress_http_validation` checks conflicting header framing, invalid targets, path normalization,
prefix boundaries, Exact precedence, hop-by-hop filtering and CLI limits. Socket tests launch
the binary with local HTTP/HTTPS backends and distinct certificates for Lake, apps, Cloud v1
dashboard, engine and Zetta fixtures. The shared certificate generator includes subject/authority
key identifiers for strict clients, including Python 3.14.

| CTest suffix (`ingress_`) | Proof |
|---|---|
| `hosts` | Five host categories, verified distinct certificates, probes and counters |
| `routing` | SNI isolation, longest prefix, Exact tie-break, query preservation and 404 |
| `tls` | Unknown SNI, untrusted CA, TLS 1.2 and unsupported ALPN refused |
| `body_limit` | Fixed and chunked limits; known oversize rejected before backend connect |
| `streaming` | Response arrives before backend completes; upload arrives before client completes |
| `websocket` | Upgrade handshake and masked client frame echo |
| `http2` | ALPN, multiplexed requests, upload echo and response beyond initial window |
| `h2_streaming` | A streaming response does not block another stream |
| `h2_reset` | Reset cancels an upload and releases resources without breaking another stream |
| `h2_limits` | Streaming body limit and global concurrent-request cap |
| `h2_backpressure` | Withheld window credit, health responsiveness, reset and recovery |
| `h2_upload_flow` | Upload beyond the initial window advances with returned credit |
| `upstream_tls` | Valid HTTPS succeeds; wrong hostname and unrelated CA refused |
| `reload` | Invalid/missing routes revoke traffic/readiness; valid replacement recovers |
| `certificate_reload` | Rotation changes the certificate; expired replacement fails closed |
| `projected_reload` | Kubernetes `..data` rotation updates certs and closes old sessions |
| `config_validation` | Duplicate keys, invalid fields, missing HTTPS identity, key/SAN mismatch |
| `capacity` | Stalled TLS fills a slot, excess connection refused, probes and recovery work |
| `timeout`, `slow_headers` | Stalled backend/incomplete HTTP/1 headers expire |
| `headers` | Forwarding spoof prevention, secret-free audit, framing refusal |
| `keepalive` | Repeated HTTP/1 requests, HEAD and 100-continue |
| `early_response` | HTTP/1 and HTTP/2 backend rejection without consuming stalled uploads |
| `upstream_framing` | Conflicting upstream framing yields 502; close-delimited bodies complete; truncation fails |
| `audit_failure` | Broken audit output clears readiness before any backend request |

The independent HTTP/2 client constructs frames and literal HPACK headers and exchanges
SETTINGS, WINDOW_UPDATE and RST_STREAM. Assertions check byte equality and concurrent progress.
No mock replaces the gateway's data plane.

Local tests establish gateway behavior, not deployed application correctness. The coordinator
must verify actual hosts/cert-manager Secrets and preserve existing application access controls
when deploying through orama-operator#473, then record ingress-nginx comparison measurements.

## Sanitizer verification

The ingress suite also runs with address and undefined-behavior sanitizers. Both are configured
to stop on an error, so diagnostics cannot be hidden behind a successful test exit:

```sh
cmake -S . -B build-sanitize -G Ninja \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-sanitize -j 6
UBSAN_OPTIONS=halt_on_error=1 ASAN_OPTIONS=abort_on_error=1 \
  ctest --test-dir build-sanitize --output-on-failure -R '^ingress_'
```

## Recorded native verification

On a MacBook Pro (arm64, macOS 14.6.1), the static and shared builds each passed
all 85 tests with no failures or skips. Both included the inherited PostgreSQL integration test
against a fresh local database. The sanitizer build passed all 26 ingress tests with no failures.
The disposable database was removed after verification. Build parallelism was limited to six;
test suites ran serially. See [the benchmark](benchmark.md) for toolchain versions and measured
local throughput and latency.

The initialized submodule revisions matched the checkout; git metadata remained unchanged.
Linux proof deferred: the supplied Linux lane helper was not available on this host.
