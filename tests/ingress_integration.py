"""Real TLS/HTTP gateway proofs; Python standard library only."""

import base64
import contextlib
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time


HOSTS = ("lake", "apps", "dashboard", "engine", "zetta")


def eventually(check, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, ValueError, http.client.HTTPException):
            pass
        time.sleep(0.05)
    raise AssertionError("condition did not become true")


def receive(sock, size):
    result = b""
    while len(result) < size:
        block = sock.recv(size - len(result))
        if not block:
            raise EOFError("connection closed")
        result += block
    return result


def closed(sock):
    try:
        return sock.recv(1) == b""
    except (ConnectionError, ssl.SSLError):
        return True


class Backend(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, name="backend", context=None):
        super().__init__(("127.0.0.1", 0), Handler)
        self.name = name
        self.requests = []
        self.upload_started = threading.Event()
        self.release = threading.Event()
        self.bytes_read = 0
        if context:
            self.socket = context.wrap_socket(self.socket, server_side=True)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def handle_error(self, request, address):
        pass

    def close(self):
        self.release.set()
        self.shutdown()
        self.server_close()
        self.thread.join()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def read_body(self):
        body = b""
        if self.headers.get("Transfer-Encoding") == "chunked":
            while True:
                line = self.rfile.readline()
                if not line:
                    raise EOFError()
                size = int(line.split(b";", 1)[0], 16)
                if not size:
                    assert self.rfile.readline() == b"\r\n"
                    break
                block = self.rfile.read(size)
                assert len(block) == size
                assert self.rfile.read(2) == b"\r\n"
                body += block
                self.server.bytes_read += size
                self.server.upload_started.set()
        else:
            remaining = int(self.headers.get("Content-Length", "0"))
            while remaining:
                block = self.rfile.read(min(remaining, 4096))
                if not block:
                    raise EOFError()
                body += block
                remaining -= len(block)
                self.server.bytes_read += len(block)
                self.server.upload_started.set()
        return body

    def do_POST(self):
        self.server.requests.append((self.path, dict(self.headers)))
        if self.path == "/early":
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.close_connection = True
            return
        body = self.read_body()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self.server.requests.append((self.path, dict(self.headers)))
        if self.path == "/invalid-framing":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n")
            self.close_connection = True
            return
        if self.path == "/truncated":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
            self.close_connection = True
            return
        if self.path == "/eof-body":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\ncomplete")
            self.close_connection = True
            return
        if self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers["Sec-WebSocket-Key"]
            accept = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()
            first, second = self.rfile.read(2)
            assert first == 0x81 and second & 0x80
            length = second & 0x7F
            mask = self.rfile.read(4)
            data = self.rfile.read(length)
            plain = bytes(value ^ mask[i % 4] for i, value in enumerate(data))
            self.wfile.write(bytes([0x81, length]) + plain)
            self.wfile.flush()
            self.server.release.wait(8)
            self.close_connection = True
            return
        if self.path == "/hold":
            self.server.upload_started.set()
            self.server.release.wait(8)
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"5\r\nfirst\r\n")
            self.wfile.flush()
            self.server.release.wait(8)
            self.wfile.write(b"4\r\nlast\r\n0\r\n\r\n")
            self.wfile.flush()
            return
        body = (self.server.name + ":" + self.path).encode()
        if self.path == "/large":
            body = b"x" * (2 * 1024 * 1024)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class Harness:
    def __init__(self, directory, binary, certificates):
        self.directory = Path(directory)
        self.binary = str(Path(binary).resolve())
        subprocess.run([str(Path(certificates).resolve()), str(self.directory), "300"], check=True)
        self.backend = Backend()
        self.other = Backend("other")
        self.backends = [self.backend, self.other]
        self.reservations = []
        self.port = self.reserve()
        self.health_port = self.reserve()
        self.config = {"hosts": []}
        for host in HOSTS:
            self.config["hosts"].append({
                "name": host + ".test", "certificate": host + ".pem", "key": host + ".key",
                "routes": [self.route(host, "/", self.backend, 1024 * 1024)],
            })
        self.process = None
        self.log = open(self.directory / "ingress.log", "w+")
        self.project(self.config)

    def route(self, name, path, backend, maximum, path_type="Prefix"):
        return {"id": name, "path": path, "path_type": path_type,
                "target": f"http://127.0.0.1:{backend.server_port}", "max_body_bytes": maximum}

    def reserve(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.reservations.append(sock)
        return sock.getsockname()[1]

    def project(self, configuration):
        temporary = self.directory / "routes.next"
        temporary.write_text(json.dumps(configuration) if isinstance(configuration, dict) else configuration)
        temporary.replace(self.directory / "routes.json")

    def start(self, extra=(), audit_pipe=False, ready=True):
        for reservation in self.reservations:
            reservation.close()
        self.reservations.clear()
        self.process = subprocess.Popen([
            self.binary, "ingress", "--configuration", str(self.directory / "routes.json"),
            "--listen", f"127.0.0.1:{self.port}", "--health-listen", f"127.0.0.1:{self.health_port}",
            "--audit", "-" if audit_pipe else str(self.directory / "audit.jsonl"), *extra,
        ], stdout=subprocess.PIPE if audit_pipe else self.log, stderr=self.log)
        eventually(lambda: self.probe("/readyz")[0] == (200 if ready else 503))

    def probe(self, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.health_port, timeout=2)
        try:
            connection.request("GET", path, headers={"Host": "health.test"})
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()

    def connect(self, host="lake.test", protocols=("http/1.1",), ca="server-ca.pem", tls12=False, source="127.0.0.1"):
        context = ssl.create_default_context(cafile=self.directory / ca)
        context.minimum_version = ssl.TLSVersion.TLSv1_2 if tls12 else ssl.TLSVersion.TLSv1_3
        if tls12:
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(list(protocols))
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5, source_address=(source, 0))
        try:
            return context.wrap_socket(sock, server_hostname=host)
        except BaseException:
            sock.close()
            raise

    def request(self, path="/", host="lake.test", headers=None, method="GET", body=b""):
        with self.connect(host) as sock:
            fields = {"Host": host, "Content-Length": str(len(body)), "Connection": "close"}
            fields.update(headers or {})
            head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fields.items()) + "\r\n"
            sock.sendall(head.encode() + body)
            response = http.client.HTTPResponse(sock, method=method)
            response.begin()
            return response.status, response.read()

    def metric(self, name):
        text = self.probe("/metrics")[1]
        return int(next(line.split()[1] for line in text.splitlines()
                        if line.startswith("zetta_ingress_" + name + " ")))

    def stop(self):
        for backend in self.backends:
            backend.release.set()
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise AssertionError("ingress failed to shut down")
            assert self.process.returncode in (0, 1), self.process.returncode
        for backend in self.backends:
            backend.close()
        for reservation in self.reservations:
            reservation.close()
        self.log.close()


class H2:
    """Independent wire client with literal HPACK requests, no third-party test dependency."""

    def __init__(self, harness):
        self.sock = harness.connect(protocols=("h2",))
        assert self.sock.selected_alpn_protocol() == "h2"
        self.sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        self.send(4, 0, 0, b"")
        self.bodies = {}
        self.heads = {}
        self.ends = set()
        self.resets = set()

    def send(self, kind, flags, stream, payload):
        self.sock.sendall(len(payload).to_bytes(3, "big") + bytes([kind, flags]) + struct.pack("!I", stream) + payload)

    @staticmethod
    def string(value):
        data = value.encode()
        size = len(data)
        prefix = bytearray()
        if size < 127:
            prefix.append(size)
        else:
            prefix.append(127)
            size -= 127
            while size >= 128:
                prefix.append((size & 127) | 128)
                size >>= 7
            prefix.append(size)
        return bytes(prefix) + data

    def request(self, stream, path="/", method="GET", headers=(), end=True):
        fields = [(":method", method), (":scheme", "https"), (":authority", "lake.test"), (":path", path), *headers]
        payload = b"".join(b"\0" + self.string(name) + self.string(value) for name, value in fields)
        self.send(1, 4 | (1 if end else 0), stream, payload)

    def read(self, credit=True):
        header = receive(self.sock, 9)
        size = int.from_bytes(header[:3], "big")
        kind, flags = header[3:5]
        stream = struct.unpack("!I", header[5:])[0]
        payload = receive(self.sock, size)
        if kind == 4 and not flags & 1:
            self.send(4, 1, 0, b"")
        elif kind == 6 and not flags & 1:
            self.send(6, 1, 0, payload)
        elif kind == 1:
            self.heads[stream] = payload
        elif kind == 0:
            self.bodies[stream] = self.bodies.get(stream, b"") + payload
            if payload and credit:
                self.send(8, 0, 0, struct.pack("!I", len(payload)))
                if not flags & 1:
                    self.send(8, 0, stream, struct.pack("!I", len(payload)))
        elif kind == 3:
            self.resets.add(stream)
        elif kind == 7:
            raise AssertionError(f"unexpected GOAWAY {payload.hex()}")
        if kind in (0, 1) and flags & 1:
            self.ends.add(stream)
        return kind, stream, payload

    def complete(self, streams):
        while not set(streams).issubset(self.ends):
            self.read()
        for stream in streams:
            assert self.heads[stream][0] == 0x88, self.heads[stream].hex()  # static :status 200

    def close(self):
        self.sock.close()


def hosts(test):
    test.start()
    certificates = set()
    for name in HOSTS:
        with test.connect(name + ".test") as sock:
            certificates.add(sock.getpeercert(binary_form=True))
        assert test.request("/" + name, name + ".test") == (200, ("backend:/" + name).encode())
    assert len(certificates) == len(HOSTS)
    assert test.probe("/healthz")[0] == 200
    assert test.probe("/readyz")[0] == 200
    assert test.metric("requests_total") == len(HOSTS)
    assert test.metric("response_body_bytes_total") > 0


def routing(test):
    routes = test.config["hosts"][0]["routes"]
    routes.extend([test.route("prefix", "/api", test.other, 1000),
                   test.route("exact", "/api", test.backend, 1000, "Exact")])
    test.project(test.config)
    test.start()
    for path, backend in [("/api", "backend"), ("/api/users?q=yes", "other"),
                          ("/apiculture", "backend"), ("/%61pi/users", "other")]:
        assert test.request(path) == (200, (backend + ":" + path).encode())
    assert test.request("/", headers={"Host": "apps.test"})[0] == 421
    routes.pop(0)
    test.project(test.config)
    eventually(lambda: test.request("/missing")[0] == 404)


def tls(test):
    test.start()
    for options in ({"host": "unknown.test"}, {"ca": "other-ca.pem"}, {"tls12": True},
                    {"protocols": ("unsupported",)}):
        try:
            with test.connect(**options) as sock:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: lake.test\r\n\r\n")
                assert closed(sock)
        except (ssl.SSLError, ConnectionError):
            pass
        else:
            assert options.get("protocols"), "invalid TLS accepted"
    assert not test.backend.requests


def body_limit(test):
    test.config["hosts"][0]["routes"][0]["max_body_bytes"] = 8
    test.project(test.config)
    test.start()
    assert test.request(method="POST", body=b"12345678") == (200, b"12345678")
    before = len(test.backend.requests)
    assert test.request(method="POST", body=b"123456789")[0] == 413
    assert len(test.backend.requests) == before
    with test.connect() as sock:
        sock.sendall(b"POST / HTTP/1.1\r\nHost: lake.test\r\nTransfer-Encoding: chunked\r\n\r\n"
                     b"4\r\n1234\r\n5\r\n56789\r\n0\r\n\r\n")
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.status == 413
    assert test.backend.bytes_read <= 12


def streaming(test):
    test.start()
    with test.connect() as sock:
        sock.sendall(b"GET /stream HTTP/1.1\r\nHost: lake.test\r\nConnection: close\r\n\r\n")
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.read(5) == b"first"  # backend has not produced the rest yet
        test.backend.release.set()
        assert response.read() == b"last"
    with test.connect() as sock:
        sock.sendall(b"POST / HTTP/1.1\r\nHost: lake.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n")
        assert test.backend.upload_started.wait(5)
        sock.sendall(b"4\r\nlast\r\n0\r\n\r\n")
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.read() == b"firstlast"


def websocket(test):
    test.start()
    with test.connect() as sock:
        sock.sendall(b"GET /ws HTTP/1.1\r\nHost: lake.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                     b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.status == 101
        assert response.getheader("Sec-WebSocket-Accept") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        payload, mask = b"websocket", b"mask"
        sock.sendall(bytes([0x81, 0x80 | len(payload)]) + mask +
                     bytes(c ^ mask[i % 4] for i, c in enumerate(payload)))
        assert receive(sock, 2 + len(payload)) == bytes([0x81, len(payload)]) + payload
        test.backend.release.set()


def http2(test):
    test.start()
    with contextlib.closing(H2(test)) as client:
        for stream in (1, 3, 5):
            client.request(stream, "/" + str(stream))
        client.complete((1, 3, 5))
        for stream in (1, 3, 5):
            assert client.bodies[stream] == ("backend:/" + str(stream)).encode()
        client.request(7, "/", "POST", (("content-length", "60000"),), end=False)
        for offset in range(0, 60000, 15000):
            client.send(0, 1 if offset == 45000 else 0, 7, b"x" * 15000)
        client.complete((7,))
        assert client.bodies[7] == b"x" * 60000
        client.request(9, "/large")
        client.complete((9,))
        assert client.bodies[9] == b"x" * (2 * 1024 * 1024)


def h2_streaming(test):
    test.start()
    with contextlib.closing(H2(test)) as client:
        client.request(1, "/stream")
        while client.bodies.get(1) != b"first":
            client.read()
        client.request(3, "/independent")
        client.complete((3,))
        assert 1 not in client.ends
        test.backend.release.set()
        client.complete((1,))
        assert client.bodies[1] == b"firstlast"


def h2_reset(test):
    test.start()
    with contextlib.closing(H2(test)) as client:
        client.request(1, "/", "POST", end=False)
        client.send(0, 0, 1, b"first")
        assert test.backend.upload_started.wait(5)
        client.send(3, 0, 1, struct.pack("!I", 8))
        client.request(3, "/after-reset")
        client.complete((3,))
        assert client.bodies[3] == b"backend:/after-reset"
    eventually(lambda: test.metric("requests_active") == 0)


def h2_limits(test):
    test.config["hosts"][0]["routes"][0]["max_body_bytes"] = 8
    test.project(test.config)
    test.start(("--max-requests", "1"))
    with contextlib.closing(H2(test)) as client:
        client.request(1, "/", "POST", end=False)
        client.send(0, 1, 1, b"123456789")
        while 1 not in client.ends:
            client.read()
        assert client.heads[1][0] != 0x88
        assert test.backend.bytes_read == 0
        client.request(3, "/hold")
        assert test.backend.upload_started.wait(5)
        client.request(5, "/refused")
        while 5 not in client.ends:
            client.read()
        assert client.heads[5][0] != 0x88
        assert all(path != "/refused" for path, _ in test.backend.requests)
        test.backend.release.set()
        client.complete((3,))
        client.request(7, "/after")
        client.complete((7,))


def h2_backpressure(test):
    test.start()
    with contextlib.closing(H2(test)) as client:
        client.request(1, "/large")
        # Stop returning stream credit after a bounded receive window.
        while len(client.bodies.get(1, b"")) < 65535:
            client.read(credit=False)
        assert len(client.bodies[1]) == 65535
        assert test.probe("/healthz")[0] == 200
        client.send(3, 0, 1, struct.pack("!I", 8))
        client.send(8, 0, 0, struct.pack("!I", 65535))
        client.request(3, "/healthy")
        client.complete((3,))
        assert client.bodies[3] == b"backend:/healthy"
    eventually(lambda: test.metric("requests_active") == 0)


def h2_upload_flow(test):
    test.start()
    with contextlib.closing(H2(test)) as client:
        client.request(1, "/", "POST", (("content-length", "120000"),), end=False)
        for _ in range(4):
            client.send(0, 0, 1, b"x" * 15000)
        connection_credit = 5535
        stream_credit = 5535
        for index in range(4):
            while min(connection_credit, stream_credit) < 15000:
                kind, stream, payload = client.read()
                if kind == 8:
                    if stream == 0:
                        connection_credit += struct.unpack("!I", payload)[0]
                    elif stream == 1:
                        stream_credit += struct.unpack("!I", payload)[0]
            client.send(0, 1 if index == 3 else 0, 1, b"y" * 15000)
            connection_credit -= 15000
            stream_credit -= 15000
        client.complete((1,))
        assert client.bodies[1] == b"x" * 60000 + b"y" * 60000


def projected_reload(test):
    for name in ("generation-a", "generation-b"):
        directory = test.directory / name
        directory.mkdir()
        for host in HOSTS:
            for suffix in ("pem", "key"):
                source = "lake-rotated" if name == "generation-b" and host == "lake" else host
                (directory / f"{host}.{suffix}").write_bytes((test.directory / f"{source}.{suffix}").read_bytes())
        (directory / "routes.json").write_text(json.dumps(test.config))
    (test.directory / "..data").symlink_to("generation-a")
    for filename in ["routes.json", *(f"{host}.{suffix}" for host in HOSTS for suffix in ("pem", "key"))]:
        (test.directory / filename).unlink()
        (test.directory / filename).symlink_to("..data/" + filename)
    test.start()
    with test.connect() as old:
        certificate = old.getpeercert(binary_form=True)
        (test.directory / "..next").symlink_to("generation-b")
        (test.directory / "..next").replace(test.directory / "..data")
        def changed():
            with test.connect() as new:
                return new.getpeercert(binary_form=True) != certificate
        eventually(changed)
        assert closed(old)
    assert test.request()[0] == 200


def early_response(test):
    test.start()
    with test.connect() as sock:
        sock.sendall(b"POST /early HTTP/1.1\r\nHost: lake.test\r\nContent-Length: 10000\r\n\r\n")
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.status == 403 and response.read() == b""
    with contextlib.closing(H2(test)) as client:
        client.request(1, "/early", "POST", end=False)
        while 1 not in client.ends:
            client.read()
        assert client.heads[1][0] != 0x88
        client.request(3, "/after")
        client.complete((3,))


def upstream_framing(test):
    test.start()
    assert test.request("/invalid-framing")[0] == 502
    assert test.request("/eof-body") == (200, b"complete")
    try:
        test.request("/truncated")
    except (OSError, http.client.IncompleteRead):
        pass
    else:
        raise AssertionError("truncated backend response was reported complete")


def slow_headers(test):
    test.start(("--setup-timeout-seconds", "1"))
    with test.connect() as sock:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: lake.test\r\nX-Slow:")
        assert closed(sock)
    assert not test.backend.requests
    assert test.request()[0] == 200


def upstream_tls(test):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(test.directory / "backend.pem", test.directory / "backend.key")
    secure = Backend("secure", context)
    test.backends.append(secure)
    route = test.config["hosts"][0]["routes"][0]
    route.update(target=f"https://127.0.0.1:{secure.server_port}", ca="server-ca.pem", server_name="backend.test")
    test.project(test.config)
    test.start()
    assert test.request() == (200, b"secure:/")
    route["server_name"] = "wrong.test"
    test.project(test.config)
    eventually(lambda: test.request()[0] == 502)
    route["server_name"] = "backend.test"
    route["ca"] = "other-ca.pem"
    test.project(test.config)
    before = len(secure.requests)
    eventually(lambda: test.request()[0] == 502)
    time.sleep(2.1)
    assert test.request()[0] == 502
    assert len(secure.requests) == before


def reload(test):
    test.start()
    with test.connect() as idle:
        test.project('{"hosts":')
        eventually(lambda: test.probe("/readyz")[0] == 503)
        assert closed(idle)
    assert test.probe("/healthz")[0] == 200
    test.project(test.config)
    eventually(lambda: test.probe("/readyz")[0] == 200)
    assert test.request()[0] == 200
    (test.directory / "routes.json").unlink()
    eventually(lambda: test.probe("/readyz")[0] == 503)


def certificate_reload(test):
    test.start()
    with test.connect() as sock:
        old = sock.getpeercert(binary_form=True)
    for suffix in ("pem", "key"):
        (test.directory / f"lake.{suffix}").write_bytes((test.directory / f"lake-rotated.{suffix}").read_bytes())
    def rotated():
        with test.connect() as sock:
            return sock.getpeercert(binary_form=True) != old
    eventually(rotated)
    for suffix in ("pem", "key"):
        (test.directory / f"lake.{suffix}").write_bytes((test.directory / f"lake-expired.{suffix}").read_bytes())
    eventually(lambda: test.probe("/readyz")[0] == 503)


def config_validation(test):
    test.project('{"hosts":[],"hosts":[]}')
    test.start(ready=False)
    invalid = []
    for field, value in (("path_type", "Regex"), ("target", "https://127.0.0.1:443"),
                         ("max_body_bytes", -1), ("path", "/../")):
        document = json.loads(json.dumps(test.config))
        document["hosts"][0]["routes"][0][field] = value
        invalid.append(document)
    document = json.loads(json.dumps(test.config))
    document["hosts"][0]["key"] = "apps.key"
    invalid.append(document)
    document = json.loads(json.dumps(test.config))
    document["hosts"][0]["certificate"] = "apps.pem"
    document["hosts"][0]["key"] = "apps.key"
    invalid.append(document)
    for document in invalid:
        before = test.metric("reload_failures_total")
        test.project(document)
        test.process.send_signal(signal.SIGHUP)
        eventually(lambda: test.metric("reload_failures_total") > before)
        assert test.probe("/readyz")[0] == 503
    test.project(test.config)
    test.process.send_signal(signal.SIGHUP)
    eventually(lambda: test.probe("/readyz")[0] == 200)


def source_fairness(test):
    if sys.platform != "linux":
        sys.exit(77)  # Multiple 127/8 loopback sources are provided by the Linux runner.
    test.start(("--max-sessions", "8", "--max-pending-per-source", "2",
                "--max-sessions-per-source", "4", "--max-requests", "8",
                "--max-requests-per-source", "2"))
    with contextlib.ExitStack() as stack:
        pending = [stack.enter_context(socket.create_connection(("127.0.0.1", test.port), timeout=3))
                   for _ in range(2)]
        eventually(lambda: test.metric("connections_active") == 2)
        with socket.create_connection(("127.0.0.1", test.port), timeout=3) as excess:
            assert closed(excess)
        # A fresh source can still complete setup while the first source's quota is full.
        other = stack.enter_context(test.connect(source="127.0.0.2"))
        other.sendall(b"GET / HTTP/1.1\r\nHost: lake.test\r\nConnection: close\r\n\r\n")
        response = http.client.HTTPResponse(other)
        response.begin()
        assert response.status == 200
        response.read()
        for sock in pending:
            sock.close()
        eventually(lambda: test.metric("connections_active") == 0)
        # Incomplete uploads can consume only this source's request share, including H2 streams.
        sock = stack.enter_context(test.connect())
        sock.sendall(b"POST / HTTP/1.1\r\nHost: lake.test\r\nContent-Length: 100000\r\n\r\nx")
        h2 = stack.enter_context(contextlib.closing(H2(test)))
        h2.request(1, "/", "POST", end=False)
        h2.send(0, 0, 1, b"x")
        eventually(lambda: test.metric("requests_active") == 2)
        h2.request(3, "/refused")
        while 3 not in h2.ends:
            h2.read()
        assert h2.heads[3][0] != 0x88
        assert test.request()[0] == 503
        eventually(lambda: test.metric("connections_active") == 2)
        # TLS-only sessions also remain subject to the active source share.
        for _ in range(2):
            stack.enter_context(test.connect())
        eventually(lambda: test.metric("connections_active") == 4)
        with test.connect() as excess:
            assert closed(excess)
        with test.connect(source="127.0.0.2") as other:
            other.sendall(b"GET / HTTP/1.1\r\nHost: lake.test\r\nConnection: close\r\n\r\n")
            response = http.client.HTTPResponse(other)
            response.begin()
            assert response.status == 200
            response.read()


def pending_capacity(test):
    test.start(("--max-sessions", "1"))
    with contextlib.ExitStack() as stack:
        for _ in range(2):
            sock = stack.enter_context(socket.create_connection(("127.0.0.1", test.port), timeout=3))
            sock.sendall(b"\x16")
        eventually(lambda: test.metric("connections_active") == 2)
        assert test.request()[0] == 200
        assert test.probe("/readyz")[0] == 200


def capacity(test):
    test.start(("--max-sessions", "1", "--max-pending-sessions", "1",
                "--setup-timeout-seconds", "1"))
    with socket.create_connection(("127.0.0.1", test.port), timeout=4) as stalled:
        stalled.sendall(b"\x16")
        eventually(lambda: test.metric("connections_active") == 1)
        with socket.create_connection(("127.0.0.1", test.port), timeout=4) as rejected:
            assert closed(rejected)
        assert test.probe("/healthz")[0] == 200
        assert closed(stalled)
    eventually(lambda: test.metric("connections_active") == 0)
    assert test.request()[0] == 200
    assert test.metric("capacity_rejections_total") >= 1


def timeout(test):
    test.start(("--idle-timeout-seconds", "1", "--setup-timeout-seconds", "1"))
    with test.connect() as sock:
        sock.sendall(b"GET /hold HTTP/1.1\r\nHost: lake.test\r\n\r\n")
        assert test.backend.upload_started.wait(5)
        assert closed(sock)
    eventually(lambda: test.metric("requests_active") == 0)
    assert test.metric("timeouts_total") > 0


def headers(test):
    test.start()
    assert test.request(headers={"X-Forwarded-For": "attacker", "Forwarded": "for=attacker",
                                 "Connection": "close, secret", "Secret": "remove", "Authorization": "private"})[0] == 200
    forwarded = {k.lower(): v for k, v in test.backend.requests[-1][1].items()}
    assert forwarded["x-forwarded-for"] == "127.0.0.1"
    assert forwarded["x-forwarded-proto"] == "https"
    assert "forwarded" not in forwarded and "secret" not in forwarded
    assert forwarded["authorization"] == "private"
    text = (test.directory / "audit.jsonl").read_text()
    assert "private" not in text and "attacker" not in text
    with test.connect() as sock:
        sock.sendall(b"POST / HTTP/1.1\r\nHost: lake.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n")
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.status == 400


def keepalive(test):
    test.start()
    with test.connect() as sock:
        for path in (f"/request-{index}" for index in range(32)):
            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: lake.test\r\n\r\n".encode())
            response = http.client.HTTPResponse(sock)
            response.begin()
            assert response.status == 200
            assert response.read() == ("backend:" + path).encode()
    assert test.request(method="HEAD")[0] == 200
    with test.connect() as sock:
        sock.sendall(b"POST / HTTP/1.1\r\nHost: lake.test\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n")
        interim = b""
        while not interim.endswith(b"\r\n\r\n"):
            interim += receive(sock, 1)
        assert interim.startswith(b"HTTP/1.1 100")
        sock.sendall(b"body")
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.read() == b"body"


def audit_failure(test):
    test.start(audit_pipe=True)
    test.process.stdout.close()
    try:
        test.request()
    except (OSError, http.client.HTTPException):
        pass
    eventually(lambda: test.probe("/readyz")[0] == 503)
    assert not test.backend.requests


def main():
    binary, certificates, case = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="ingress-", dir=Path.cwd()) as directory:
        test = Harness(directory, binary, certificates)
        try:
            globals()[case](test)
            print(f"ingress {case} passed")
        except BaseException:
            test.log.flush()
            print((test.directory / "ingress.log").read_text())
            raise
        finally:
            test.stop()


if __name__ == "__main__":
    main()
