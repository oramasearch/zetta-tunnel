"""Portable checks for the release image contract and role entrypoints."""

from pathlib import Path
import subprocess
import sys


BINARY = Path(sys.argv[1])
SOURCE = Path(sys.argv[2])
VERSION = sys.argv[3]


def run(*arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=10)


assert run(BINARY, "--version").stdout == f"zetta-tunnel {VERSION}\n"

for role in ("client", "relay", "endpoint", "egress", "peer", "ingress", "mesh"):
    result = run(BINARY, role, "--help")
    assert role in result.stdout.lower(), role

dockerfile = (SOURCE / "Dockerfile").read_text(encoding="utf-8")
assert "FROM alpine:3.22@sha256:" in dockerfile
assert "FROM scratch AS runtime" in dockerfile
assert "FROM build AS mesh-proof" in dockerfile
assert "USER 65532:65532" in dockerfile
assert 'ENTRYPOINT ["/usr/local/bin/zetta-tunnel"]' in dockerfile
assert "readelf --program-headers /build/zetta-tunnel" in dockerfile
assert "--rtlib=compiler-rt" in dockerfile
assert dockerfile.rstrip().endswith('ENTRYPOINT ["/usr/local/bin/zetta-tunnel"]')

for script in ("tools/build-image.sh", "tools/prove-mesh-linux.sh"):
    path = SOURCE / script
    assert path.stat().st_mode & 0o111, script
    run("bash", "-n", path)

print("image contract and all role entrypoints passed")

