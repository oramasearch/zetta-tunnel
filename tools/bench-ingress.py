#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

"""Benchmark a local ingress and backend; never sends traffic to a cluster."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import math
import platform
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from ingress_integration import Harness  # noqa: E402


def percentile(values, percent):
    return sorted(values)[max(0, math.ceil(len(values) * percent / 100) - 1)]


def measure(test, requests, concurrency, ingress):
    context = ssl.create_default_context(cafile=test.directory / "server-ca.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])

    def worker(count):
        port = test.port if ingress else test.backend.server_port
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        except OSError as error:
            raise RuntimeError(f"{'ingress' if ingress else 'backend'} connection setup failed") from error
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock = context.wrap_socket(raw, server_hostname="lake.test") if ingress else raw
        with sock:
            latencies = []
            for _ in range(count):
                start = time.perf_counter()
                sock.sendall(b"GET /benchmark HTTP/1.1\r\nHost: lake.test\r\n\r\n")
                response = http.client.HTTPResponse(sock)
                response.begin()
                body = response.read()
                if response.status != 200 or body != b"backend:/benchmark":
                    raise RuntimeError(f"{'ingress' if ingress else 'backend'} response validation failed: "
                                       f"status={response.status}, body={body[:100]!r}")
                latencies.append((time.perf_counter() - start) * 1000)
            return latencies

    # Warm TLS and code paths separately from the measured requests.
    worker(20)
    counts = [requests // concurrency + (index < requests % concurrency) for index in range(concurrency)]
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        values = [value for group in executor.map(worker, counts) for value in group]
    elapsed = time.perf_counter() - started
    return {"target": "zetta-tunnel ingress" if ingress else "direct HTTP backend",
            "requests": len(values), "concurrency": concurrency,
            "elapsed_seconds": round(elapsed, 6), "requests_per_second": round(len(values) / elapsed, 2),
            "p50_ms": round(percentile(values, 50), 3), "p99_ms": round(percentile(values, 99), 3),
            "errors": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("build/zetta-tunnel"))
    parser.add_argument("--certificates", type=Path, default=Path("build/tunnel_certificates"))
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    if not 1 <= options.concurrency <= 128 or not options.concurrency <= options.requests <= 50000:
        parser.error("concurrency must be 1..128 and requests concurrency..50000")
    if math.ceil(options.requests / options.concurrency) > 900:
        parser.error("use at most 900 requests per connection")
    with tempfile.TemporaryDirectory(prefix="bench-ingress-", dir=options.binary.resolve().parent) as directory:
        test = Harness(directory, options.binary, options.certificates)
        try:
            test.start()
            result = {"host": platform.node(), "platform": platform.platform(),
                      "machine": platform.machine(), "python": platform.python_version(),
                      "openssl": ssl.OPENSSL_VERSION,
                      "protocol": "HTTP/1.1 keep-alive, TLS 1.3 on ingress, 18-byte response",
                      "backend": "Python standard-library ThreadingHTTPServer on loopback",
                      "audit": "JSON-lines file, flush per request",
                      "comparison": "ingress-nginx pending on management cluster (coordinator)",
                      "results": [measure(test, options.requests, options.concurrency, target)
                                  for target in (False, True)]}
            text = json.dumps(result, indent=2)
            print(text)
            if options.output:
                options.output.write_text(text + "\n")
        finally:
            test.stop()


if __name__ == "__main__":
    main()
