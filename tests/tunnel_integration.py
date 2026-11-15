"""Exercise the actual role processes with independent TLS clients and TCP targets."""

import concurrent.futures
import contextlib
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time


GRANT = "11111111-1111-4111-8111-111111111111"
BINARY, CERTIFICATES, CASE = sys.argv[1:4]


def eventually(check, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.03)
    raise AssertionError("condition did not become true")


def receive(connection, count):
    result = bytearray()
    while len(result) < count:
        data = connection.recv(count - len(result))
        assert data, f"connection closed after {len(result)} of {count} bytes"
        result.extend(data)
    return bytes(result)


def closed(connection):
    try:
        return connection.recv(1) == b""
    except (ConnectionError, ssl.SSLError):
        return True


class Echo(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self):
        self.accepted = 0
        self.payload = bytearray()
        self.stall = False
        self.resume = threading.Event()
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                owner.accepted += 1
                if owner.stall:
                    owner.resume.wait(timeout=15)
                    return
                try:
                    while data := self.request.recv(16384):
                        owner.payload.extend(data)
                        self.request.sendall(data)
                except OSError:
                    pass

        super().__init__(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.resume.set()
        self.shutdown()
        self.server_close()
        self.thread.join()


class Harness:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.processes = []
        self.logs = []
        self.reservations = []
        self.echo = Echo()
        self.other = Echo()
        self.endpoint = self.port()
        self.relay = self.port()
        self.local = self.port()
        self.endpoint_health = self.port()
        self.relay_health = self.port()
        lifetime = 6 if CASE == "expiry" else 300
        subprocess.run([CERTIFICATES, directory, str(lifetime)], check=True)
        # The relay trusts the union of every customer's CA, as the operator projects it.
        (self.directory / "customer-cas.pem").write_text(
            (self.directory / "tunnel-ca.pem").read_text() + (self.directory / "tenant-ca.pem").read_text())
        self.expiry = ssl.cert_time_to_seconds(ssl._ssl._test_decode_cert(str(self.directory / "developer.pem"))["notAfter"])
        self.grant = {"id": GRANT, "workspace": "workspace-test", "endpoint": self.address(self.endpoint),
                      "expires_at": datetime.datetime.fromtimestamp(self.expiry, datetime.timezone.utc).isoformat(),
                      "client_ca_sha256": [self.fingerprint("tunnel-ca")]}
        self.set_grants([self.grant])

    def fingerprint(self, name):
        der = ssl.PEM_cert_to_DER_cert((self.directory / f"{name}.pem").read_text())
        return hashlib.sha256(der).hexdigest()

    def port(self):
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        self.reservations.append(reservation)
        return reservation.getsockname()[1]

    @staticmethod
    def address(port):
        return f"127.0.0.1:{port}"

    def set_grants(self, grants):
        self.set_file(json.dumps({"grants": grants}))

    def set_file(self, value):
        temporary = self.directory / "grants.next"
        temporary.write_text(value)
        temporary.replace(self.directory / "grants.json")

    def start(self, role, stdout=None, **flags):
        for reservation in self.reservations[:]:
            if str(reservation.getsockname()[1]) in [value.rsplit(":", 1)[-1] for value in flags.values()]:
                reservation.close()
                self.reservations.remove(reservation)
        log = open(self.directory / f"{role}-{len(self.logs)}.log", "w+")
        self.logs.append(log)
        args = [BINARY, role]
        for name, value in flags.items():
            args.extend(["--" + name.replace("_", "-"), value])
        process = subprocess.Popen(args, stdout=log if stdout is None else stdout, stderr=log)
        self.processes.append(process)
        return process

    def tls_flags(self, name, ca):
        return {"cert": str(self.directory / f"{name}.pem"),
                "key": str(self.directory / f"{name}.key"), "ca": str(self.directory / f"{ca}.pem")}

    def start_stack(self, developer="developer", endpoint_cert="endpoint", relay_workload="relay-workload", target=None, max_sessions="128", server_name="relay.test", relay_audit=None, relay_stdout=None):
        self.start("endpoint", **self.tls_flags(endpoint_cert, "workload-ca"),
                   listen=self.address(self.endpoint), health_listen=self.address(self.endpoint_health),
                   peer_name="relay.workload", target=target or self.address(self.echo.server_address[1]),
                   audit=str(self.directory / "endpoint.jsonl"), max_sessions=max_sessions)
        self.relay_process = self.start("relay", stdout=relay_stdout, **self.tls_flags("relay", "customer-cas"),
                   listen=self.address(self.relay), health_listen=self.address(self.relay_health),
                   grants=str(self.directory / "grants.json"),
                   endpoint_cert=str(self.directory / f"{relay_workload}.pem"),
                   endpoint_key=str(self.directory / f"{relay_workload}.key"),
                   endpoint_ca=str(self.directory / "workload-ca.pem"),
                   audit=relay_audit or str(self.directory / "relay.jsonl"), max_sessions=max_sessions)
        self.start("client", **self.tls_flags(developer, "server-ca"), relay=self.address(self.relay),
                   server_name=server_name, listen=self.address(self.local))
        eventually(lambda: self.health(self.endpoint_health, "/readyz") == 200)
        eventually(lambda: self.health(self.relay_health, "/healthz") == 200)

    @staticmethod
    def health(port, path):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        try:
            connection.request("GET", path)
            return connection.getresponse().status
        finally:
            connection.close()

    def connection(self):
        connection = None
        def try_connect():
            nonlocal connection
            connection = socket.create_connection(("127.0.0.1", self.local), timeout=5)
            return True
        eventually(try_connect)
        connection.settimeout(5)
        return connection

    def records(self, event=None):
        path = self.directory / "relay.jsonl"
        records = [json.loads(line) for line in path.read_text().splitlines()]
        return [record for record in records if event is None or record["event"] == event]

    def roundtrip(self, data=b"hello\x00\xff"):
        with self.connection() as connection:
            connection.sendall(data)
            assert receive(connection, len(data)) == data

    def stop(self):
        for process in reversed(self.processes):
            process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("role failed to stop")
        for reservation in self.reservations:
            reservation.close()
        self.echo.close()
        self.other.close()

    def report(self):
        for log in self.logs:
            log.flush()
            log.seek(0)
            print(Path(log.name).name, log.read())
        for path in self.directory.glob("*.jsonl"):
            print(path.name, path.read_text())


def roundtrip(test):
    test.start_stack()
    payload = bytes(range(256)) * 1024
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(test.roundtrip, [payload] * 4))
    eventually(lambda: len(test.records("session_end")) == 4)
    for record in test.records("session_end"):
        assert record["bytes_up"] == len(payload) == record["bytes_down"]
        assert record["grant_id"] == GRANT and record["workspace"] == "workspace-test"
        assert record["peer"].startswith("127.0.0.1:") and record["started_at"] <= record["timestamp"]
    assert len({record["session_id"] for record in test.records("session_start")}) == 4
    assert test.health(test.relay_health, "/readyz") == 200
    assert test.health(test.endpoint_health, "/missing") == 404


def revoke(test):
    test.start_stack()
    with test.connection() as connection:
        connection.sendall(b"live")
        assert receive(connection, 4) == b"live"
        start = time.monotonic()
        test.set_grants([])
        assert closed(connection)
        assert time.monotonic() - start < 3
    eventually(lambda: any(record["reason"] == "grant_removed" for record in test.records("session_end")))
    with test.connection() as connection:
        connection.sendall(b"forbidden")
        assert closed(connection)
    assert test.echo.accepted == 1


def expiry(test):
    test.start_stack()
    with test.connection() as connection:
        connection.sendall(b"live")
        assert receive(connection, 4) == b"live"
        connection.settimeout(9)
        assert closed(connection)
    eventually(lambda: any(record["reason"] == "grant_expired" for record in test.records("session_end")))


def refusal(test):
    names = {"expired_cert": "expired", "unknown_grant": "unknown", "wrong_ca": "other", "no_uri": "no-uri", "multiple_uri": "multiple-uri", "long_lived": "long-lived", "other_customer_ca": "tenant"}
    if CASE == "certificate_bound":
        test.grant["expires_at"] = datetime.datetime.fromtimestamp(test.expiry - 30, datetime.timezone.utc).isoformat()
        test.set_grants([test.grant])
    if CASE == "expired_grant":
        test.grant["expires_at"] = "2000-01-01T00:00:00Z"
        test.set_grants([test.grant])
    test.start_stack(developer=names.get(CASE, "developer"),
                     endpoint_cert="wrong-endpoint" if CASE == "endpoint_identity" else "endpoint",
                     relay_workload="wrong-workload" if CASE == "relay_identity" else "relay-workload",
                     server_name="wrong.test" if CASE == "server_identity" else "relay.test")
    with test.connection() as connection:
        connection.sendall(b"must not reach target")
        assert closed(connection)
    eventually(lambda: bool(test.records("refusal")))
    assert test.echo.accepted == 0
    assert test.records("refusal")[0]["bytes_up"] == 0
    if CASE == "other_customer_ca":
        # A certificate from another trusted customer CA names this grant and its expiry, and is
        # still refused, because the grant is bound to its own customer's CA.
        assert test.records("refusal")[0]["reason"] == "grant_issuer", test.records("refusal")


def target_isolation(test):
    test.start_stack()
    second = test.address(test.other.server_address[1])
    for payload in [json.dumps({"target": second}).encode(), f"CONNECT {second} HTTP/1.1\r\n\r\n".encode(), b"\x05\x01\x00"]:
        test.roundtrip(payload)
    assert test.other.accepted == 0
    assert test.echo.accepted == 3


def invalid_reload(test):
    test.start_stack()
    with test.connection() as connection:
        connection.sendall(b"live")
        assert receive(connection, 4) == b"live"
        test.set_file('{"grants":[')
        assert closed(connection)
    eventually(lambda: test.health(test.relay_health, "/readyz") == 503)
    assert test.health(test.relay_health, "/healthz") == 200
    test.set_grants([test.grant])
    eventually(lambda: test.health(test.relay_health, "/readyz") == 200)
    test.roundtrip()


def sighup(test):
    if not hasattr(signal, "SIGHUP"):
        print("SIGHUP is POSIX-only; Windows uses the poll")
        return
    test.start_stack()
    with test.connection() as connection:
        connection.sendall(b"live")
        assert receive(connection, 4) == b"live"
        path = test.directory / "grants.json"
        original = path.stat()
        data = path.read_text().replace(GRANT, "33333333-3333-4333-8333-333333333333")
        path.write_text(data)
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
        test.relay_process.send_signal(signal.SIGHUP)
        assert closed(connection)


def credentials_reload(test):
    test.start_stack()
    test.roundtrip()
    path = test.directory / "relay.key"
    original = path.read_bytes()
    path.write_text("invalid fixture key")
    eventually(lambda: test.health(test.relay_health, "/readyz") == 503)
    path.write_bytes(original)
    eventually(lambda: test.health(test.relay_health, "/readyz") == 200)
    test.roundtrip(b"reloaded")


def pending_capacity(test):
    test.start_stack(max_sessions="2")
    with contextlib.ExitStack() as stack:
        # Stalled unauthenticated sockets must not take established slots.
        for port in (test.relay, test.endpoint):
            for _ in range(3):
                sock = stack.enter_context(socket.create_connection(("127.0.0.1", port), timeout=3))
                sock.sendall(b"\x16")
        for _ in range(2):
            live = stack.enter_context(test.connection())
            live.sendall(b"available")
            assert receive(live, 9) == b"available"
        assert test.health(test.relay_health, "/readyz") == 200


def capacity(test):
    test.start_stack(max_sessions="2")
    with contextlib.ExitStack() as stack:
        for _ in range(2):
            connection = stack.enter_context(test.connection())
            connection.sendall(b"live")
            assert receive(connection, 4) == b"live"
        with test.connection() as excess:
            excess.sendall(b"excess")
            assert closed(excess)
        assert test.health(test.relay_health, "/healthz") == 200
    eventually(lambda: any(record["reason"] == "capacity" for record in test.records()))


def tls_boundaries(test):
    test.start_stack()
    cases = [("server-ca", test.relay, "relay.test", None, ssl.TLSVersion.TLSv1_3),
             ("server-ca", test.relay, "relay.test", "developer", ssl.TLSVersion.TLSv1_2),
             ("workload-ca", test.endpoint, f"endpoint.{GRANT}", "developer", ssl.TLSVersion.TLSv1_3)]
    for ca, port, name, client, version in cases:
        context = ssl.create_default_context(cafile=str(test.directory / f"{ca}.pem"))
        context.minimum_version = version
        context.maximum_version = version
        if client:
            context.load_cert_chain(test.directory / f"{client}.pem", test.directory / f"{client}.key")
        with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
            try:
                with context.wrap_socket(connection, server_hostname=name) as secure:
                    secure.sendall(b"must not reach target")
                    assert closed(secure)
            except ssl.SSLError:
                pass
    assert test.echo.accepted == 0


def backpressure(test):
    test.echo.stall = True
    test.start_stack()
    with test.connection() as connection:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        def flood():
            try:
                for _ in range(64):
                    connection.sendall(b"x" * (1024 * 1024))
            except OSError:
                return
            raise AssertionError("stalled target did not backpressure sender")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            sender = pool.submit(flood)
            eventually(lambda: bool(test.records("session_start")))
            time.sleep(0.2)
            test.set_grants([])
            eventually(lambda: any(record["reason"] == "grant_removed" for record in test.records("session_end")), timeout=3)
            sender.result(timeout=4)
            assert closed(connection)
    assert test.health(test.relay_health, "/readyz") == 200


def setup_timeout(test):
    test.start_stack(max_sessions="1")
    with socket.create_connection(("127.0.0.1", test.relay), timeout=5) as stalled:
        stalled.settimeout(12)
        stalled.sendall(b"\x16")
        assert test.health(test.relay_health, "/healthz") == 200
        assert closed(stalled)
    eventually(lambda: any(record["reason"] == "setup_timeout" for record in test.records("refusal")))
    test.roundtrip()


def projected_reload(test):
    if os.name == "nt":
        print("projected volume symlink test requires POSIX")
        return
    original = test.directory / "snapshot1"
    original.write_text((test.directory / "grants.json").read_text())
    (test.directory / "grants.json").unlink()
    (test.directory / "grants.json").symlink_to(original.name)
    test.start_stack()
    with test.connection() as connection:
        connection.sendall(b"live")
        assert receive(connection, 4) == b"live"
        (test.directory / "snapshot2").write_text('{"grants":[]}')
        link = test.directory / "next-link"
        link.symlink_to("snapshot2")
        link.replace(test.directory / "grants.json")
        assert closed(connection)


def removed_file(test):
    test.start_stack()
    with test.connection() as connection:
        connection.sendall(b"live")
        assert receive(connection, 4) == b"live"
        (test.directory / "grants.json").unlink()
        assert closed(connection)
    eventually(lambda: test.health(test.relay_health, "/readyz") == 503)


def grant_change(test):
    test.start_stack()
    with test.connection() as connection:
        connection.sendall(b"live")
        assert receive(connection, 4) == b"live"
        test.grant["workspace"] = "workspace-reassigned"
        test.set_grants([test.grant])
        assert closed(connection)
    eventually(lambda: any(record["reason"] == "grant_changed" for record in test.records("session_end")))


def audit_failure(test):
    test.start_stack(relay_audit="-", relay_stdout=subprocess.PIPE)
    test.relay_process.stdout.close()
    with test.connection() as connection:
        connection.sendall(b"audit must precede forwarding")
        assert closed(connection)
    eventually(lambda: test.health(test.relay_health, "/readyz") == 503)
    assert not test.echo.payload


def invalid_credentials(test):
    flags = test.tls_flags("developer", "server-ca")
    flags["key"] = str(test.directory / "unknown.key")
    process = test.start("client", **flags, relay=test.address(test.relay), listen=test.address(test.local))
    assert process.wait(timeout=5) == 2
    assert test.echo.accepted == 0


def postgres(test):
    executable = os.environ.get("ZETTA_TUNNEL_PSQL")
    database = os.environ.get("ZETTA_TUNNEL_TEST_DATABASE")
    if not executable or not database:
        print("PostgreSQL proof requires ZETTA_TUNNEL_PSQL and ZETTA_TUNNEL_TEST_DATABASE")
        return 77
    test.start_stack(target="127.0.0.1:5432")
    connection = f"postgresql://stevesperandeo@127.0.0.1:{test.local}/{database}?connect_timeout=5"
    result = None
    def query():
        nonlocal result
        result = subprocess.run([executable, connection, "-XAt", "-v", "ON_ERROR_STOP=1", "-c", "select 'tunnel-postgres-ok', 42"], capture_output=True, text=True, timeout=15)
        return result.returncode == 0
    eventually(query)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "tunnel-postgres-ok|42", result.stdout
    process = subprocess.Popen([executable, connection, "-XAt", "-v", "ON_ERROR_STOP=1", "-c", "select pg_sleep(30)"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        eventually(lambda: len(test.records("session_start")) >= 2)
        test.set_grants([])
        _, error = process.communicate(timeout=5)
        assert process.returncode != 0 and error
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    print(result.stdout.strip())
    print("psql live query disconnected after grant removal")


CASES = {"roundtrip": roundtrip, "revoke": revoke, "expiry": expiry,
         "target_isolation": target_isolation, "invalid_reload": invalid_reload,
         "pending_capacity": pending_capacity, "credentials_reload": credentials_reload, "sighup": sighup, "capacity": capacity, "postgres": postgres,
         "tls_boundaries": tls_boundaries, "backpressure": backpressure,
         "setup_timeout": setup_timeout, "projected_reload": projected_reload,
         "removed_file": removed_file, "grant_change": grant_change,
         "audit_failure": audit_failure, "invalid_credentials": invalid_credentials}

with tempfile.TemporaryDirectory(prefix="tunnel-test-", dir=Path.cwd()) as directory:
    harness = Harness(directory)
    try:
        result = CASES.get(CASE, refusal)(harness)
        harness.stop()
        print(f"PASS {CASE}")
    except BaseException:
        harness.report()
        harness.stop()
        raise
    finally:
        for log in harness.logs:
            log.close()
    sys.exit(result or 0)
