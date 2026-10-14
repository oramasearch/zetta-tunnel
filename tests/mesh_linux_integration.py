"""Privileged Linux namespace proof for mesh capture and fail-closed behavior."""

import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


BINARY, CERTIFICATES = sys.argv[1:3]


if sys.platform != "linux" or os.geteuid() != 0 or os.environ.get("ZETTA_MESH_PRIVILEGED_TEST") != "1":
    print("SKIP: set ZETTA_MESH_PRIVILEGED_TEST=1 and run as root on a Linux node")
    raise SystemExit(77)

if not shutil.which("ip"):
    print("SKIP: the Linux node does not provide iproute2")
    raise SystemExit(77)


def command(*arguments, check=True):
    return subprocess.run(arguments, check=check, text=True, capture_output=True)


def eventually(check, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (ConnectionError, OSError, http.client.HTTPException):
            pass
        time.sleep(0.05)
    raise AssertionError("condition did not become true")


def reserve_port():
    reservation = socket.socket()
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    reservation.close()
    return port


class Harness:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.suffix = str(os.getpid())
        self.bridge = "ztb" + self.suffix[-8:]
        self.source = "zts" + self.suffix[-8:]
        self.destination = "ztd" + self.suffix[-8:]
        self.rogue = "ztr" + self.suffix[-8:]
        self.processes = []
        self.health_port = reserve_port()
        command(CERTIFICATES, directory, "300")
        self.create_network()
        self.write_configuration()

    def create_network(self):
        command("ip", "link", "add", self.bridge, "type", "bridge")
        command("ip", "addr", "add", "10.203.0.1/24", "dev", self.bridge)
        command("ip", "link", "set", self.bridge, "up")
        self.add_namespace(self.source, "10.203.0.2", "zsh" + self.suffix[-7:])
        self.add_namespace(self.destination, "10.203.0.3", "zdh" + self.suffix[-7:])
        self.add_namespace(self.rogue, "10.203.0.4", "zrh" + self.suffix[-7:])

    def add_namespace(self, name, address, host_link):
        command("ip", "netns", "add", name)
        command("ip", "link", "add", host_link, "type", "veth", "peer", "name", "eth0", "netns", name)
        command("ip", "link", "set", host_link, "master", self.bridge)
        command("ip", "link", "set", host_link, "up")
        command("ip", "-n", name, "link", "set", "lo", "up")
        command("ip", "-n", name, "link", "set", "eth0", "up")
        command("ip", "-n", name, "addr", "add", address + "/24", "dev", "eth0")

    def write_configuration(self):
        tls = lambda name: {
            "certificate": str(self.directory / f"{name}.pem"),
            "key": str(self.directory / f"{name}.key"),
            "ca": str(self.directory / "workload-ca.pem"),
        }
        self.configuration = {
            "mesh": {
                "node": "linux-proof-node",
                "workloads": [
                    {
                        "identity": "source.workspace.test",
                        "network_namespace": f"/var/run/netns/{self.source}",
                        "tls": tls("mesh-source"),
                        "routes": [
                            {
                                "destination": "10.203.0.3:8080",
                                "mesh": "10.203.0.3:15008",
                                "identity": "destination.workspace.test",
                            }
                        ],
                        "ports": [],
                    },
                    {
                        "identity": "destination.workspace.test",
                        "network_namespace": f"/var/run/netns/{self.destination}",
                        "tls": tls("mesh-destination"),
                        "routes": [],
                        "ports": [
                            {
                                "port": 8080,
                                "target": "127.0.0.1:8080",
                                "sources": ["source.workspace.test"],
                            }
                        ],
                    },
                ],
            }
        }
        temporary = self.directory / "mesh.next"
        temporary.write_text(json.dumps(self.configuration))
        temporary.replace(self.directory / "mesh.json")

    def write_raw_configuration(self, value):
        temporary = self.directory / "mesh.next"
        temporary.write_text(value)
        temporary.replace(self.directory / "mesh.json")

    def restore_configuration(self):
        self.write_raw_configuration(json.dumps(self.configuration))

    def start_agent(self):
        log = open(self.directory / f"agent-{len(self.processes)}.log", "w+")
        process = subprocess.Popen(
            [
                BINARY,
                "mesh",
                "--configuration",
                str(self.directory / "mesh.json"),
                "--health-listen",
                f"127.0.0.1:{self.health_port}",
                "--audit",
                str(self.directory / "audit.jsonl"),
                "--max-sessions",
                "8",
            ],
            stdout=log,
            stderr=log,
        )
        self.processes.append((process, log))
        eventually(lambda: self.probe("/readyz")[0] == 200)
        return process

    def start_echo(self):
        code = """
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 8080))
s.listen()
while True:
    c, _ = s.accept()
    with c:
        while True:
            data = c.recv(16384)
            if not data:
                break
            c.sendall(data)
"""
        process = subprocess.Popen(["ip", "netns", "exec", self.destination, sys.executable, "-c", code])
        self.processes.append((process, None))
        time.sleep(0.2)
        return process

    def probe(self, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.health_port, timeout=2)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()

    def request(self, namespace, expected=True):
        code = """
import socket
s = socket.create_connection(('10.203.0.3', 8080), timeout=3)
s.settimeout(3)
s.sendall(b'mesh-proof')
assert s.recv(10) == b'mesh-proof'
"""
        result = command("ip", "netns", "exec", namespace, sys.executable, "-c", code, check=False)
        if expected and result.returncode != 0:
            raise AssertionError(result.stderr)
        if not expected and result.returncode == 0:
            raise AssertionError("connection unexpectedly escaped mesh capture")

    def stop_process(self, process, crash=False):
        if process.poll() is not None:
            return
        process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
        process.wait(timeout=8)

    def cleanup(self):
        for process, log in reversed(self.processes):
            self.stop_process(process)
            if log:
                log.close()
        for namespace in (self.source, self.destination, self.rogue):
            command("ip", "netns", "del", namespace, check=False)
        command("ip", "link", "del", self.bridge, check=False)

    def report(self):
        for path in self.directory.glob("agent-*.log"):
            print(path.name, path.read_text())
        audit = self.directory / "audit.jsonl"
        if audit.exists():
            print(audit.read_text())


with tempfile.TemporaryDirectory(prefix="mesh-linux-", dir=Path.cwd()) as directory:
    test = Harness(directory)
    try:
        agent = test.start_agent()
        assert test.probe("/healthz")[0] == 200
        test.request(test.source, expected=False)
        echo = test.start_echo()
        test.request(test.source)
        test.request(test.rogue, expected=False)

        test.write_raw_configuration('{"mesh":')
        eventually(lambda: test.probe("/readyz")[0] == 503)
        test.request(test.source, expected=False)
        test.restore_configuration()
        eventually(lambda: test.probe("/readyz")[0] == 200)
        test.request(test.source)

        test.stop_process(agent, crash=True)
        test.request(test.source, expected=False)

        restarted = test.start_agent()
        test.request(test.source)
        metrics = test.probe("/metrics")[1]
        assert "zetta_mesh_allows_total" in metrics

        test.stop_process(echo)
        test.stop_process(restarted)
        test.request(test.source, expected=False)
        records = [json.loads(line) for line in (test.directory / "audit.jsonl").read_text().splitlines()]
        assert any(record["direction"] == "outbound" and record["decision"] == "allow" for record in records)
        assert any(record["direction"] == "inbound" and record["decision"] == "allow" for record in records)
        print("mesh Linux capture, identity, restart and crash proof passed")
    except BaseException:
        test.report()
        raise
    finally:
        test.cleanup()
