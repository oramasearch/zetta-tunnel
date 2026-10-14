# Local ingress benchmark

`tools/bench-ingress.py` starts the actual gateway, generated CA-signed certificates and a local
HTTP backend. It measures completed requests per second and request latency p50/p99 for the
backend directly and through TLS ingress. It validates every response and fails the run on any
connection or response error; it does not discard failed samples.

```sh
cmake -S . -B build -G Ninja
cmake --build build -j 6
python3 tools/bench-ingress.py --requests 2000 --concurrency 8 \
  --output build/ingress-benchmark.json
```

Flags: `--binary` (default `build/zetta-tunnel`), `--certificates` (default
`build/tunnel_certificates`), `--requests` (default 2000), `--concurrency` (default 8), optional
`--output` JSON file. All listeners and traffic are on loopback. Temporary fixtures are created
under the binary's build directory and removed on exit. The tool imports the repository's
standard-library integration harness; no additional Python packages are required.

## Recorded native run

Host: **Steves-MacBook-Pro.local**, arm64, macOS 14.6.1. Clang 22.1.8, OpenSSL 3.6.3,
nghttp2 1.68.0, Python 3.14.6. Default CMake static build, without a Release optimization preset.
No container was used. No test suite or build was running concurrently within this work order.

Each target used 2,000 successful GET requests at concurrency 8, 20 separate warm-up requests,
HTTP/1.1 keep-alive, and an 18-byte response. Ingress used verified TLS 1.3 and JSON-lines audit
flushed to a local file for each request. The direct backend used plaintext HTTP. Requests through
ingress opened a new backend connection per request. The Python threaded backend and load driver
ran in the same process; the gateway ran as a separate process on the same host.

| Target | Requests | Errors | Requests/s | p50 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|---:|
| Direct local HTTP backend | 2,000 | 0 | 10,144.26 | 0.695 | 2.025 |
| zetta-tunnel TLS ingress | 2,000 | 0 | 4,687.95 | 1.558 | 8.567 |

Throughput includes measured worker setup/connection establishment; per-request latency begins
after client connection/TLS setup and includes the complete response body. Percentiles use the
nearest-rank method. This is a local functional throughput observation for this specific workload,
including Python scheduling and backend connection creation, not a production capacity result.
It does not measure HTTP/2, streaming/WebSocket throughput, CPU saturation or tail behavior under
cluster traffic. Those protocol behaviors have separate acceptance tests.

## Cluster comparison pending

**The ingress-nginx comparison is pending on the management cluster and belongs to the
coordinator**, as agreed for issue #6. No comparison number is inferred from the direct-backend
result. After deployment, measure both gateways against the same backend, certificates,
protocol mix, request/response payloads, concurrency, warm-up and sampling procedure. Record
versions, node resources, errors, throughput, p50/p99, and actual Lake/app/Cloud v1/Zetta host
verification before reviewing a cutover through orama-operator#473.
