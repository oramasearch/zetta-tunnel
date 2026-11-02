"""Load TLS credentials once and reuse them after the source files disappear."""

from pathlib import Path
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="tls-cache-", dir=Path.cwd()) as directory:
    subprocess.run([sys.argv[2], directory, "300"], check=True, timeout=20)
    subprocess.run([sys.argv[1], directory], check=True, timeout=10)
