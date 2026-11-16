# SPDX-License-Identifier: MIT

"""Exercise two peer gateways with real mutual TLS and overlapping service networks."""

import calendar
import contextlib
import http.client
import json
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time


BINARY, CERTIFICATES, CASE = sys.argv[1:4]
PEER_ID = "11111111-1111-4111-8111-111111111111"


def eventually(check, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, http.client.HTTPException, FileNotFoundError, json.JSONDecodeError):
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
    except (ConnectionError, ssl.SSLError, TimeoutError):
        return True


class Echo(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host, port):
        self.accepted = 0
        self.payload = bytearray()
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                owner.accepted += 1
                try:
                    while data := self.request.recv(16384):
                        owner.payload.extend(data)
                        self.request.sendall(data)
                except OSError:
                    pass

        super().__init__((host, port), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join()


class Harness:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.processes = []
        self.logs = []
        self.reservations = []
        subprocess.run([CERTIFICATES, directory, "300"], check=True)
        self.peer_a = self.port()
        self.peer_b = self.port()
        self.health_a = self.port()
        self.health_b = self.port()
        self.import_a = self.port()
        self.import_b = self.port()
        self.import_unknown = self.port()
        self.echo_a = Echo("127.0.0.1", 0)
        self.echo_b = self.echo_a
        service_port = self.echo_a.server_address[1]
        self.configuration_a = self.configuration(
            self.peer_b,
            [
                {"name": "service-b", "port": service_port, "listen": self.address(self.import_a)},
                {
                    "name": "not-exported",
                    "port": service_port,
                    "listen": self.address(self.import_unknown),
                },
            ],
            [{"name": "service-a", "port": service_port, "target": f"127.0.0.1:{service_port}"}],
        )
        self.configuration_b = self.configuration(
            self.peer_a,
            [{"name": "service-a", "port": service_port, "listen": self.address(self.import_b)}],
            [{"name": "service-b", "port": service_port, "target": f"127.0.0.1:{service_port}"}],
        )
        self.set_configuration("a", self.configuration_a)
        self.set_configuration("b", self.configuration_b)

    def port(self):
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        self.reservations.append(reservation)
        return reservation.getsockname()[1]

    @staticmethod
    def address(port):
        return f"127.0.0.1:{port}"

    @staticmethod
    def configuration(remote_port, imports, exports):
        return {
            "peer": {
                "id": PEER_ID,
                "workspace": "workspace-test",
                "remote": f"127.0.0.1:{remote_port}",
                "imports": imports,
                "exports": exports,
            }
        }

    def set_configuration(self, side, value):
        temporary = self.directory / f"peer-{side}.next"
        temporary.write_text(json.dumps(value))
        temporary.replace(self.directory / f"peer-{side}.json")

    def set_raw_configuration(self, side, value):
        temporary = self.directory / f"peer-{side}.next"
        temporary.write_text(value)
        temporary.replace(self.directory / f"peer-{side}.json")

    def start_side(self, side, max_sessions="128", audit_pipe=False):
        if side == "a":
            listen_port = self.peer_a
            health_port = self.health_a
            certificate = "peer-a"
            peer_name = "peer-b.test"
        else:
            listen_port = self.peer_b
            health_port = self.health_b
            certificate = "peer-b"
            peer_name = "peer-a.test"
        log = open(self.directory / f"peer-{side}.log", "w+")
        self.logs.append(log)
        args = [
            BINARY,
            "peer",
            "--listen",
            self.address(listen_port),
            "--health-listen",
            self.address(health_port),
            "--configuration",
            str(self.directory / f"peer-{side}.json"),
            "--cert",
            str(self.directory / f"{certificate}.pem"),
            "--key",
            str(self.directory / f"{certificate}.key"),
            "--ca",
            str(self.directory / "workload-ca.pem"),
            "--peer-name",
            peer_name,
            "--audit",
            "-" if audit_pipe else str(self.directory / f"peer-{side}.jsonl"),
            "--max-sessions",
            max_sessions,
        ]
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE if audit_pipe else log,
            stderr=log,
        )
        self.processes.append(process)
        eventually(lambda: self.health(side, "/readyz") == 200)
        return process

    def start(self, max_sessions="128", audit_b=False):
        for reservation in self.reservations:
            reservation.close()
        self.reservations.clear()
        self.start_side("b", max_sessions=max_sessions, audit_pipe=audit_b)
        self.start_side("a", max_sessions=max_sessions)

    def health(self, side, path):
        port = self.health_a if side == "a" else self.health_b
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        try:
            connection.request("GET", path)
            return connection.getresponse().status
        finally:
            connection.close()

    def imported(self, side):
        port = self.import_a if side == "a" else self.import_b
        connection = socket.create_connection(("127.0.0.1", port), timeout=5)
        connection.settimeout(12)
        return connection

    def records(self, side):
        path = self.directory / f"peer-{side}.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()]

    def direct_request(self, certificate, service="unknown", with_certificate=True):
        context = ssl.create_default_context(cafile=self.directory / "workload-ca.pem")
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        if with_certificate:
            context.load_cert_chain(
                self.directory / f"{certificate}.pem",
                self.directory / f"{certificate}.key",
            )
        connection = socket.create_connection(("127.0.0.1", self.peer_b), timeout=5)
        connection.settimeout(5)
        try:
            secure = context.wrap_socket(connection, server_hostname="peer-b.test")
            request = f"ZTPR1 {PEER_ID} {service} {self.echo_b.server_address[1]}\n".encode()
            secure.sendall(request)
            return closed(secure)
        except (ConnectionError, OSError, ssl.SSLError):
            return True
        finally:
            connection.close()

    def stop(self):
        for process in reversed(self.processes):
            process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("peer role failed to stop")
        for reservation in self.reservations:
            reservation.close()
        self.echo_a.close()

    def report(self):
        for log in self.logs:
            log.flush()
            log.seek(0)
            print(Path(log.name).name, log.read())
        for path in self.directory.glob("*.jsonl"):
            print(path.name, path.read_text())


def roundtrip(test):
    test.start()
    payload_a = bytes(range(256)) * 256
    with test.imported("a") as connection:
        connection.sendall(payload_a)
        assert receive(connection, len(payload_a)) == payload_a
    payload_b = b"cluster-b-to-cluster-a"
    with test.imported("b") as connection:
        connection.sendall(payload_b)
        assert receive(connection, len(payload_b)) == payload_b
    eventually(lambda: len(test.records("a")) == 2 and len(test.records("b")) == 2)
    assert test.echo_a.payload == payload_a + payload_b
    for record in test.records("a") + test.records("b"):
        assert record["decision"] == "allow"
        assert record["reason"] == "service_allowed"
        assert record["peer_id"] == PEER_ID
        assert record["workspace"] == "workspace-test"


def named_only(test):
    test.start()
    accepted = test.echo_b.accepted
    connection = socket.create_connection(("127.0.0.1", test.import_unknown), timeout=5)
    connection.settimeout(5)
    with connection:
        assert closed(connection)
    eventually(lambda: any(record["reason"] == "service_absent" for record in test.records("b")))
    assert test.echo_b.accepted == accepted


def revoke(test):
    test.start()
    connection = test.imported("a")
    with connection:
        connection.sendall(b"live")
        assert receive(connection, 4) == b"live"
        (test.directory / "peer-b.json").unlink()
        assert closed(connection)
    eventually(lambda: test.health("b", "/readyz") == 503)
    with test.imported("a") as refused:
        assert closed(refused)


def mutual_tls(test):
    test.start()
    accepted = test.echo_b.accepted
    assert test.direct_request("peer-a", with_certificate=False)
    assert test.direct_request("wrong-peer")
    assert test.echo_b.accepted == accepted
    eventually(lambda: sum(record["reason"] == "tls_authentication" for record in test.records("b")) >= 2)


def reload(test):
    test.start()
    changed = json.loads(json.dumps(test.configuration_b))
    changed["peer"]["exports"] = []
    test.set_configuration("b", changed)
    eventually(lambda: test.health("b", "/readyz") == 200)
    with test.imported("a") as refused:
        assert closed(refused)
    test.set_configuration("b", test.configuration_b)

    def restored():
        try:
            with test.imported("a") as connection:
                connection.sendall(b"restored")
                return receive(connection, 8) == b"restored"
        except (ConnectionError, OSError, TimeoutError):
            return False

    eventually(restored)


def invalid_reload(test):
    test.start()
    connection = test.imported("a")
    with connection:
        connection.sendall(b"live")
        assert receive(connection, 4) == b"live"
        test.set_raw_configuration("b", '{"peer":')
        assert closed(connection)
    eventually(lambda: test.health("b", "/readyz") == 503)
    assert test.health("b", "/healthz") == 200
    test.set_configuration("b", test.configuration_b)
    eventually(lambda: test.health("b", "/readyz") == 200)


def setup_timeout(test):
    test.start(max_sessions="1")
    stalled = socket.create_connection(("127.0.0.1", test.peer_b), timeout=5)
    stalled.settimeout(12)
    with stalled:
        stalled.sendall(b"\x16")
        assert test.health("b", "/healthz") == 200
        assert closed(stalled)
    eventually(lambda: any(record["reason"] == "setup_timeout" for record in test.records("b")))
    with test.imported("a") as connection:
        connection.sendall(b"after")
        assert receive(connection, 5) == b"after"


def pending_capacity(test):
    test.start(max_sessions="1")
    with contextlib.ExitStack() as stack:
        for port in (test.peer_a, test.peer_b):
            for _ in range(2):
                sock = stack.enter_context(socket.create_connection(("127.0.0.1", port), timeout=3))
                sock.sendall(b"\x16")
        # The shared import/export budget must remain available.
        with test.imported("a") as live:
            live.sendall(b"available")
            assert receive(live, 9) == b"available"
        assert test.health("b", "/readyz") == 200


def idle_listener(test):
    test.start()
    time.sleep(11)
    connected_at = int(time.time())
    context = ssl.create_default_context(cafile=test.directory / "workload-ca.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(test.directory / "peer-a.pem", test.directory / "peer-a.key")
    connection = socket.create_connection(("127.0.0.1", test.peer_b), timeout=5)
    connection.settimeout(5)
    with connection:
        # A distant peer: its handshake starts well after the 100 ms the old deadline left.
        time.sleep(0.5)
        secure = context.wrap_socket(connection, server_hostname="peer-b.test")
        port = test.echo_b.server_address[1]
        secure.sendall(f"ZTPR1 {PEER_ID} service-b {port}\n".encode())
        assert receive(secure, 6) == b"ZTPA1\n"
        secure.sendall(b"late")
        assert receive(secure, 4) == b"late"
    eventually(lambda: any(record["decision"] == "allow" for record in test.records("b")))
    allowed = next(record for record in test.records("b") if record["decision"] == "allow")
    started = calendar.timegm(time.strptime(allowed["started_at"][:19], "%Y-%m-%dT%H:%M:%S"))
    assert started >= connected_at - 1, allowed


def capacity(test):
    test.start(max_sessions="1")
    with contextlib.ExitStack() as stack:
        first = stack.enter_context(test.imported("a"))
        first.sendall(b"live")
        assert receive(first, 4) == b"live"
        second = stack.enter_context(test.imported("a"))
        assert closed(second)
        assert test.health("a", "/healthz") == 200
        assert test.health("b", "/healthz") == 200
    eventually(lambda: any(record["reason"] == "capacity" for record in test.records("a")))


def audit_failure(test):
    test.start(audit_b=True)
    process_b = test.processes[0]
    process_b.stdout.close()
    accepted = test.echo_b.accepted
    with test.imported("a") as connection:
        connection.sendall(b"must not pass")
        assert closed(connection)
    eventually(lambda: test.health("b", "/readyz") == 503)
    assert test.echo_b.accepted == accepted + 1
    assert not test.echo_b.payload


CASES = {
    "roundtrip": roundtrip,
    "named_only": named_only,
    "revoke": revoke,
    "mutual_tls": mutual_tls,
    "reload": reload,
    "invalid_reload": invalid_reload,
    "setup_timeout": setup_timeout,
    "idle_listener": idle_listener,
    "capacity": capacity,
    "pending_capacity": pending_capacity,
    "audit_failure": audit_failure,
}

with tempfile.TemporaryDirectory(prefix="peer-test-", dir=Path.cwd()) as directory:
    harness = Harness(directory)
    try:
        CASES[CASE](harness)
        harness.stop()
        print(f"PASS {CASE}")
    except BaseException:
        harness.report()
        harness.stop()
        raise
    finally:
        for log in harness.logs:
            log.close()
