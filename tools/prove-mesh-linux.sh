#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# Required: KCTX, the kubectl context of a cluster with a BuildKit pod and a Linux node that may run
# a privileged pod, and IMAGE_REPOSITORY, the repository the proof image is pushed to.
KUBE_CONTEXT=${KCTX:?set KCTX to the kubectl context of the cluster that runs BuildKit}
IMAGE_REPOSITORY=${IMAGE_REPOSITORY:?set IMAGE_REPOSITORY, for example docker.io/<org>/zetta-tunnel}
BUILDKIT_NAMESPACE=${BUILDKIT_NAMESPACE:-buildkit}
DOCKER_CONFIGURATION=${DOCKER_CONFIG:-"$HOME/.docker"}
SHORT_COMMIT=$(git -C "$ROOT" rev-parse --short=7 HEAD)
PROJECT_VERSION=$(awk '$1 == "VERSION" { print $2; exit }' "$ROOT/CMakeLists.txt")
PROOF_TAG=${1:-"mesh-proof-$SHORT_COMMIT"}
IMAGE="$IMAGE_REPOSITORY:$PROOF_TAG"
BUILD_LOG_DIR=${BUILD_LOG_DIR:-"$ROOT/build/image-logs"}
NAMESPACE="zetta-tunnel-proof-$SHORT_COMMIT"
PULL_SECRET=zetta-tunnel-proof-registry

[[ "$PROOF_TAG" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
  echo "invalid proof image tag: $PROOF_TAG" >&2
  exit 2
}

for command_name in buildctl git kubectl;
do
  command -v "$command_name" >/dev/null || {
    echo "missing required command: $command_name" >&2
    exit 2
  }
done

[[ -f "$DOCKER_CONFIGURATION/config.json" ]] || {
  echo "Docker registry credentials not found at $DOCKER_CONFIGURATION/config.json" >&2
  exit 2
}

[[ -z "$(git -C "$ROOT" submodule status --recursive | sed -n '/^[-+U]/p')" ]] || {
  echo "initialize every submodule before building the proof image" >&2
  exit 2
}

BUILDKIT_POD=$(kubectl --context "$KUBE_CONTEXT" get pods -n "$BUILDKIT_NAMESPACE" \
  -o jsonpath='{.items[0].metadata.name}')
[[ -n "$BUILDKIT_POD" ]] || {
  echo "no BuildKit pod found in namespace $BUILDKIT_NAMESPACE" >&2
  exit 1
}

mkdir -p "$BUILD_LOG_DIR"
LOG_FILE="$BUILD_LOG_DIR/build-$PROOF_TAG.log"

if ! buildctl --addr "kube-pod://$BUILDKIT_POD?context=$KUBE_CONTEXT&namespace=$BUILDKIT_NAMESPACE" \
  build \
  --frontend dockerfile.v0 \
  --local context="$ROOT" \
  --local dockerfile="$ROOT" \
  --opt platform=linux/amd64 \
  --opt target=mesh-proof \
  --opt "build-arg:ZETTA_TUNNEL_VERSION=$PROJECT_VERSION" \
  --output "type=image,name=$IMAGE,push=true" \
  --progress plain >"$LOG_FILE" 2>&1;
then
  echo "proof image build failed; log: $LOG_FILE" >&2
  tail -n 100 "$LOG_FILE" >&2
  exit 1
fi

if kubectl --context "$KUBE_CONTEXT" get namespace "$NAMESPACE" >/dev/null 2>&1;
then
  echo "proof namespace already exists: $NAMESPACE" >&2
  exit 1
fi

cleanup() {
  kubectl --context "$KUBE_CONTEXT" delete namespace "$NAMESPACE" \
    --ignore-not-found --wait=false >/dev/null
}
trap cleanup EXIT

kubectl --context "$KUBE_CONTEXT" create namespace "$NAMESPACE" >/dev/null
kubectl --context "$KUBE_CONTEXT" label namespace "$NAMESPACE" \
  pod-security.kubernetes.io/enforce=privileged >/dev/null
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" create secret generic "$PULL_SECRET" \
  --type=kubernetes.io/dockerconfigjson \
  --from-file=.dockerconfigjson="$DOCKER_CONFIGURATION/config.json" >/dev/null

OVERRIDES=$(printf '%s' \
  '{"apiVersion":"v1","spec":{"imagePullSecrets":[{"name":"'"$PULL_SECRET"'"}],"containers":[{"name":"mesh-proof","image":"'"$IMAGE"'","imagePullPolicy":"Always","securityContext":{"privileged":true,"runAsUser":0}}]}}')

kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" run mesh-proof \
  --image "$IMAGE" \
  --restart Never \
  --attach \
  --rm \
  --pod-running-timeout=2m \
  --overrides "$OVERRIDES"

