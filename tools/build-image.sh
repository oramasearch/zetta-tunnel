#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: tools/build-image.sh vX.Y.Z" >&2
  exit 2
}

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RELEASE_TAG=${1:-}
KUBE_CONTEXT=${KCTX:-orama-production-cluster-01}
IMAGE_REPOSITORY=docker.io/oramasearch/zetta-tunnel
BUILD_LOG_DIR=${BUILD_LOG_DIR:-"$ROOT/build/image-logs"}

[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage

for command_name in buildctl curl git kubectl python3;
do
  command -v "$command_name" >/dev/null || {
    echo "missing required command: $command_name" >&2
    exit 2
  }
done

git -C "$ROOT" rev-parse --verify "refs/tags/$RELEASE_TAG^{commit}" >/dev/null 2>&1 || {
  echo "release tag does not exist: $RELEASE_TAG" >&2
  exit 2
}

HEAD_COMMIT=$(git -C "$ROOT" rev-parse HEAD)
TAG_COMMIT=$(git -C "$ROOT" rev-parse "refs/tags/$RELEASE_TAG^{commit}")
[[ "$HEAD_COMMIT" == "$TAG_COMMIT" ]] || {
  echo "check out $RELEASE_TAG before building the release image" >&2
  exit 2
}

[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || {
  echo "the tagged checkout and its submodules must be clean" >&2
  exit 2
}

[[ -z "$(git -C "$ROOT" submodule status --recursive | sed -n '/^[-+U]/p')" ]] || {
  echo "initialize every submodule at the commit recorded by the tag" >&2
  exit 2
}

PROJECT_VERSION=$(awk '$1 == "VERSION" { print $2; exit }' "$ROOT/CMakeLists.txt")
[[ "$RELEASE_TAG" == "v$PROJECT_VERSION" ]] || {
  echo "$RELEASE_TAG does not match CMake project version $PROJECT_VERSION" >&2
  exit 2
}

SHORT_COMMIT=$(git -C "$ROOT" rev-parse --short=7 HEAD)
IMAGE_TAG="main-$SHORT_COMMIT"
IMAGE="$IMAGE_REPOSITORY:$IMAGE_TAG"
BUILDKIT_POD=$(kubectl --context "$KUBE_CONTEXT" get pods -n buildkit \
  -o jsonpath='{.items[0].metadata.name}')
[[ -n "$BUILDKIT_POD" ]] || {
  echo "no BuildKit pod found in namespace buildkit" >&2
  exit 1
}

mkdir -p "$BUILD_LOG_DIR"
LOG_FILE="$BUILD_LOG_DIR/build-$IMAGE_TAG.log"
METADATA_FILE="$BUILD_LOG_DIR/build-$IMAGE_TAG.json"

if ! buildctl --addr "kube-pod://$BUILDKIT_POD?context=$KUBE_CONTEXT&namespace=buildkit" \
  build \
  --frontend dockerfile.v0 \
  --local context="$ROOT" \
  --local dockerfile="$ROOT" \
  --opt platform=linux/amd64 \
  --opt target=runtime \
  --opt "build-arg:ZETTA_TUNNEL_VERSION=$PROJECT_VERSION" \
  --output "type=image,name=$IMAGE,push=true" \
  --metadata-file "$METADATA_FILE" \
  --progress plain >"$LOG_FILE" 2>&1;
then
  echo "image build failed; log: $LOG_FILE" >&2
  tail -n 100 "$LOG_FILE" >&2
  exit 1
fi

HTTP_CODE=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  https://hub.docker.com/v2/repositories/oramasearch/zetta-tunnel/)
[[ "$HTTP_CODE" == 404 ]] || {
  echo "anonymous Docker Hub repository request returned $HTTP_CODE, expected 404" >&2
  exit 3
}

DIGEST=$(python3 - "$METADATA_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as metadata_file:
    metadata = json.load(metadata_file)

print(metadata["containerimage.digest"])
PY
)

echo "built $IMAGE@$DIGEST from $RELEASE_TAG"
echo "version proof: zetta-tunnel $PROJECT_VERSION (Dockerfile build check)"
echo "privacy proof: anonymous Docker Hub request returned 404"
echo "log: $LOG_FILE"

