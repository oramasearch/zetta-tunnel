"""Exercise egress authorization with real TCP and TLS clients."""

import contextlib
import http.client
import json
import os
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
NETWORK_FIXTURE = sys.argv[4] if len(sys.argv) > 4 else ""
if not NETWORK_FIXTURE:
    raise RuntimeError("egress integration tests require the POSIX network fixture")
RULE_ID = "11111111-1111-4111-8111-111111111111"


def eventually(check, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, http.client.HTTPException, FileNotFoundError):
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

    def __init__(self, tls_context=None):
        self.accepted = 0
        self.payload = bytearray()
        self.tls_context = tls_context
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                owner.accepted += 1
                connection = self.request
                try:
                    if owner.tls_context:
                        connection = owner.tls_context.wrap_socket(connection, server_side=True)
                    while data := connection.recv(16384):
                        owner.payload.extend(data)
                        connection.sendall(data)
                except (OSError, ssl.SSLError):
                    pass
                finally:
                    if connection is not self.request:
                        connection.close()

        super().__init__(("127.0.0.1", 0), Handler)
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
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.directory / "relay.pem", self.directory / "relay.key")
        self.echo = Echo()
        self.tls_echo = Echo(server_context)
        self.gateway = self.port()
        self.health_port = self.port()
        self.dns_answers = None
        self.dns_file = None
        self.rules = [self.rule()]
        self.set_rules(self.rules)

    def rule(self, source_ips=None):
        return {
            "id": RULE_ID,
            "workspace": "workspace-test",
            "source_ips": source_ips or ["127.0.0.1"],
            "dns_name": "localhost",
            "ports": [self.echo.server_address[1], self.tls_echo.server_address[1]],
        }

    def port(self):
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        self.reservations.append(reservation)
        return reservation.getsockname()[1]

    @staticmethod
    def address(port):
        return f"127.0.0.1:{port}"

    def set_rules(self, rules):
        self.set_file(json.dumps({"rules": rules}))

    def set_file(self, value):
        temporary = self.directory / "rules.next"
        temporary.write_text(value)
        temporary.replace(self.directory / "rules.json")

    def start(self, stdout=None, max_sessions="128"):
        for reservation in self.reservations:
            reservation.close()
        self.reservations.clear()
        log = open(self.directory / f"egress-{len(self.logs)}.log", "w+")
        self.logs.append(log)
        args = [
            BINARY,
            "egress",
            "--listen",
            self.address(self.gateway),
            "--health-listen",
            self.address(self.health_port),
            "--rules",
            str(self.directory / "rules.json"),
            "--audit",
            str(self.directory / "egress.jsonl") if stdout is None else "-",
            "--sni-port",
            str(self.tls_echo.server_address[1]),
            "--max-sessions",
            max_sessions,
        ]
        environment = os.environ.copy()
        loader = "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"
        environment[loader] = NETWORK_FIXTURE
        environment["EGRESS_TEST_CONNECT_LOG"] = str(self.directory / "connect.log")
        if self.dns_file is not None:
            environment["EGRESS_TEST_DNS_FILE"] = str(self.dns_file)
        if self.dns_answers is not None:
            environment["EGRESS_TEST_DNS"] = self.dns_answers
        process = subprocess.Popen(args, stdout=log if stdout is None else stdout, stderr=log,
                                   env=environment)
        self.processes.append(process)
        eventually(lambda: self.health("/healthz") == 200)
        return process

    def health(self, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.health_port, timeout=1)
        try:
            connection.request("GET", path)
            return connection.getresponse().status
        finally:
            connection.close()

    def connection(self):
        return socket.create_connection(("127.0.0.1", self.gateway), timeout=5)

    def explicit(self, name="localhost", port=None, payload=b"hello"):
        connection = self.connection()
        connection.settimeout(5)
        destination_port = port or self.echo.server_address[1]
        connection.sendall(f"ZTEG1 {name} {destination_port}\n".encode() + payload)
        return connection, payload

    def records(self):
        path = self.directory / "egress.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()]

    def stop(self):
        for process in reversed(self.processes):
            process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("egress role failed to stop")
        for reservation in self.reservations:
            reservation.close()
        self.echo.close()
        self.tls_echo.close()

    def report(self):
        for log in self.logs:
            log.flush()
            log.seek(0)
            print(Path(log.name).name, log.read())
        for path in self.directory.glob("*.jsonl"):
            print(path.name, path.read_text())


def explicit_roundtrip(test):
    test.start()
    connection, payload = test.explicit(payload=bytes(range(256)) * 256)
    with connection:
        assert receive(connection, len(payload)) == payload
    eventually(lambda: len(test.records()) == 1)
    record = test.records()[0]
    assert record["decision"] == "allow" and record["reason"] == "rule_allowed"
    assert record["rule_id"] == RULE_ID and record["workspace"] == "workspace-test"
    assert record["dns_name"] == "localhost" and record["protocol"] == "explicit"
    assert record["resolved_address"].rsplit(":", 1)[-1] == str(test.echo.server_address[1])


def sni(test):
    test.start()
    context = ssl._create_unverified_context()
    with test.connection() as connection:
        with context.wrap_socket(connection, server_hostname="localhost") as secure:
            secure.sendall(b"tls payload")
            assert receive(secure, 11) == b"tls payload"
    eventually(lambda: len(test.records()) == 1)
    record = test.records()[0]
    assert record["decision"] == "allow" and record["protocol"] == "https_sni"
    assert record["dns_name"] == "localhost"


def destination_forbidden(test, answers=None):
    # Every answer is fed to the real resolver-to-connect path. The fixture records connect
    # attempts and refuses external traffic even when the gateway under test is unfixed.
    test.dns_answers = answers or (sys.argv[5] if len(sys.argv) > 5 else "127.0.0.1")
    test.start()
    with test.explicit()[0] as connection:
        assert closed(connection)
    eventually(lambda: len(test.records()) == 1)
    assert test.records()[0]["reason"] == "destination_forbidden"
    assert not (test.directory / "connect.log").exists()
    assert test.echo.accepted == 0


def destination_sni_forbidden(test):
    test.dns_answers = "127.0.0.1"
    test.start()
    context = ssl._create_unverified_context()
    with test.connection() as connection:
        try:
            with context.wrap_socket(connection, server_hostname="LOCALHOST."):
                raise AssertionError("forbidden destination completed TLS")
        except (ConnectionError, ssl.SSLError):
            pass
    eventually(lambda: len(test.records()) == 1)
    assert test.records()[0]["reason"] == "destination_forbidden"
    assert not (test.directory / "connect.log").exists()
    assert test.tls_echo.accepted == 0


def destination_mixed(test):
    test.dns_answers = "93.184.216.34,::ffff:127.0.0.1"
    test.start()
    with test.explicit()[0] as connection:
        assert closed(connection)
    eventually(lambda: len(test.records()) == 1)
    assert test.records()[0]["reason"] == "destination_forbidden"
    assert not (test.directory / "connect.log").exists()
    assert test.echo.accepted == 0


def destination_cluster(test):
    rule = test.rule()
    rule["denied_cidrs"] = ["93.184.216.34/32"]
    test.set_rules([rule])
    destination_forbidden(test, "93.184.216.34")


def destination_rebinding(test):
    test.dns_file = test.directory / "dns.txt"
    test.dns_file.write_text("93.184.216.34")
    test.start()
    connection, payload = test.explicit()
    with connection:
        assert receive(connection, len(payload)) == payload
        test.dns_file.write_text("127.0.0.1")
        with test.explicit()[0] as refused:
            assert closed(refused)
        # Existing connections keep their checked numeric destination.
        connection.sendall(b"still public")
        assert receive(connection, 12) == b"still public"
    eventually(lambda: len(test.records()) == 2)
    assert test.records()[-1]["reason"] == "destination_forbidden"
    assert (test.directory / "connect.log").read_text().count("connect") == 1


def destination_reload(test):
    test.start()
    connection, payload = test.explicit()
    with connection:
        assert receive(connection, len(payload)) == payload
        rule = test.rule()
        rule["denied_cidrs"] = ["93.184.216.0/24"]
        test.set_rules([rule])
        assert closed(connection)
    with test.explicit()[0] as connection:
        assert closed(connection)
    eventually(lambda: len(test.records()) == 2)
    assert test.records()[-1]["reason"] == "destination_forbidden"
    assert (test.directory / "connect.log").read_text().count("connect") == 1


def sni_denied(test):
    test.start()
    context = ssl._create_unverified_context()
    with test.connection() as connection:
        try:
            with context.wrap_socket(connection, server_hostname="not-allowed.localhost"):
                raise AssertionError("unauthorized SNI completed TLS")
        except (ConnectionError, ssl.SSLError):
            pass
    eventually(lambda: len(test.records()) == 1)
    assert test.records()[0]["reason"] == "rule_absent"
    assert test.tls_echo.accepted == 0


def denied(test):
    test.start()
    with test.explicit(name="not-allowed.localhost")[0] as connection:
        assert closed(connection)
    eventually(lambda: len(test.records()) == 1)
    assert test.records()[0]["reason"] == "rule_absent"
    assert test.echo.accepted == 0


def ip_literal(test):
    test.start()
    with test.explicit(name="127.0.0.1")[0] as connection:
        assert closed(connection)
    eventually(lambda: len(test.records()) == 1)
    assert test.records()[0]["reason"] == "ip_literal"
    assert test.echo.accepted == 0


def rebinding(test):
    test.start()
    # The client connects to the gateway address, but cannot substitute another name that it
    # resolved to the allowed target address. Authorization happens before gateway DNS lookup.
    with test.explicit(name="rebound.localhost")[0] as connection:
        assert closed(connection)
    eventually(lambda: len(test.records()) == 1)
    assert test.records()[0]["reason"] == "rule_absent"
    assert test.echo.accepted == 0


def source_binding(test):
    test.set_rules([test.rule(source_ips=["192.0.2.10"])])
    test.start()
    with test.explicit()[0] as connection:
        assert closed(connection)
    eventually(lambda: len(test.records()) == 1)
    assert test.records()[0]["reason"] == "rule_absent"
    assert test.echo.accepted == 0


def reload(test):
    test.start()
    connection, payload = test.explicit(payload=b"live")
    with connection:
        assert receive(connection, len(payload)) == payload
        test.set_rules([])
        assert closed(connection)
    assert test.health("/readyz") == 200
    with test.explicit()[0] as refused:
        assert closed(refused)


def invalid_reload(test):
    test.start()
    connection, payload = test.explicit(payload=b"live")
    with connection:
        assert receive(connection, len(payload)) == payload
        test.set_file('{"rules":[')
        assert closed(connection)
    eventually(lambda: test.health("/readyz") == 503)
    assert test.health("/healthz") == 200
    test.set_rules(test.rules)
    eventually(lambda: test.health("/readyz") == 200)


def projected_reload(test):
    if os.name == "nt":
        print("projected volume symlink test requires POSIX")
        return
    original = test.directory / "snapshot1"
    original.write_text((test.directory / "rules.json").read_text())
    (test.directory / "rules.json").unlink()
    (test.directory / "rules.json").symlink_to(original.name)
    test.start()
    connection, payload = test.explicit(payload=b"live")
    with connection:
        assert receive(connection, len(payload)) == payload
        (test.directory / "snapshot2").write_text('{"rules":[]}')
        link = test.directory / "next-link"
        link.symlink_to("snapshot2")
        link.replace(test.directory / "rules.json")
        assert closed(connection)


def setup_timeout(test):
    test.start(max_sessions="1")
    with test.connection() as stalled:
        stalled.settimeout(12)
        stalled.sendall(b"\x16")
        assert test.health("/healthz") == 200
        assert closed(stalled)
    eventually(lambda: any(record["reason"] == "setup_timeout" for record in test.records()))
    connection, payload = test.explicit(payload=b"after timeout")
    with connection:
        assert receive(connection, len(payload)) == payload


def pending_capacity(test):
    test.start(max_sessions="1")
    with contextlib.ExitStack() as stack:
        for _ in range(2):
            stalled = stack.enter_context(test.connection())
            stalled.sendall(b"\x16")
        connection, payload = test.explicit(payload=b"available")
        with connection:
            assert receive(connection, len(payload)) == payload
        assert test.health("/readyz") == 200


def capacity(test):
    test.start(max_sessions="2")
    with contextlib.ExitStack() as stack:
        for _ in range(2):
            connection, payload = test.explicit(payload=b"live")
            connection = stack.enter_context(connection)
            assert receive(connection, len(payload)) == payload
        with test.explicit()[0] as excess:
            assert closed(excess)
    eventually(lambda: any(record["reason"] == "capacity" for record in test.records()))


def audit_failure(test):
    process = test.start(stdout=subprocess.PIPE)
    process.stdout.close()
    with test.explicit()[0] as connection:
        assert closed(connection)
    eventually(lambda: test.health("/readyz") == 503)
    assert not test.echo.payload


CASES = {
    "allowed": explicit_roundtrip,
    "destination_forbidden": destination_forbidden,
    "destination_sni_forbidden": destination_sni_forbidden,
    "destination_mixed": destination_mixed,
    "destination_cluster": destination_cluster,
    "destination_reload": destination_reload,
    "destination_rebinding": destination_rebinding,
    "sni": sni,
    "sni_denied": sni_denied,
    "denied": denied,
    "ip_literal": ip_literal,
    "rebinding": rebinding,
    "source_binding": source_binding,
    "reload": reload,
    "invalid_reload": invalid_reload,
    "projected_reload": projected_reload,
    "setup_timeout": setup_timeout,
    "capacity": capacity,
    "pending_capacity": pending_capacity,
    "audit_failure": audit_failure,
}

with tempfile.TemporaryDirectory(prefix="egress-test-", dir=Path.cwd()) as directory:
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
