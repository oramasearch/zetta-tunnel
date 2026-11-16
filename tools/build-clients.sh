#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

# Builds the tunnel clients Lake hands to developers (lake#745) into one folder:
#   zetta-tunnel-<os>-<arch>, SHA256SUMS and VERSION.
#
#   tools/build-clients.sh [out-dir]
#
# - macOS: this machine's architecture, built with ZETTA_TUNNEL_PORTABLE=ON (OpenSSL and nghttp2
#   linked statically), and refused unless it loads only the system's own libraries.
# - Linux amd64: the image's fully static binary, when BUILDKIT_ADDR names a BuildKit
#   (kube-pod://<pod>?context=<ctx>&namespace=buildkit); its runtime stage is written out as files.
# - With CLIENTS_IMAGE=<registry>/<org>/zetta-tunnel-clients:<tag>, the folder is also pushed as
#   a scratch image holding /clients/*, which Lake's image build copies from.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/dist/clients}
version=$(sed -n 's/^  VERSION \(.*\)$/\1/p' "$root/CMakeLists.txt" | head -1)
mkdir -p "$out"
cd "$root"

if [ "$(uname -s)" = Darwin ]; then
  arch=$(uname -m)
  build=$root/build-portable-darwin-$arch
  cmake -S . -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DZETTA_TUNNEL_PORTABLE=ON >/dev/null
  cmake --build "$build" -j 6 --target zetta-tunnel >/dev/null
  foreign=$(otool -L "$build/zetta-tunnel" | tail -n +2 | awk '{print $1}' | grep -vE '^/usr/lib/|^/System/Library/' || true)
  if [ -n "$foreign" ]; then
    echo "darwin-$arch links libraries a developer's Mac may not have:" >&2
    echo "$foreign" >&2
    exit 1
  fi
  cp "$build/zetta-tunnel" "$out/zetta-tunnel-darwin-$arch"
  echo "darwin-$arch: $("$out/zetta-tunnel-darwin-$arch" --version)"
fi

if [ -n "${BUILDKIT_ADDR:-}" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  buildctl --addr "$BUILDKIT_ADDR" build --frontend dockerfile.v0 --local context=. --local dockerfile=. \
    --opt target=runtime --opt platform=linux/amd64 --opt build-arg:ZETTA_TUNNEL_VERSION="$version" \
    --output type=local,dest="$tmp" >/dev/null 2>"$tmp.log" || { tail -20 "$tmp.log" >&2; exit 1; }
  cp "$tmp/usr/local/bin/zetta-tunnel" "$out/zetta-tunnel-linux-amd64"
  chmod 0755 "$out/zetta-tunnel-linux-amd64"
  file "$out/zetta-tunnel-linux-amd64" | grep -q "statically linked" || { echo "linux-amd64 is not statically linked" >&2; exit 1; }
  echo "linux-amd64: static"
fi

echo "$version" > "$out/VERSION"
(cd "$out" && rm -f SHA256SUMS && shasum -a 256 zetta-tunnel-* > SHA256SUMS)
cat "$out/SHA256SUMS"

if [ -n "${CLIENTS_IMAGE:-}" ]; then
  : "${BUILDKIT_ADDR:?CLIENTS_IMAGE needs BUILDKIT_ADDR}"
  buildctl --addr "$BUILDKIT_ADDR" build --frontend dockerfile.v0 --local context="$out" \
    --local dockerfile="$root/tools" --opt filename=clients.Dockerfile --opt platform=linux/amd64 \
    --output type=image,name="$CLIENTS_IMAGE",push=true >/dev/null
  echo "pushed $CLIENTS_IMAGE"
fi
