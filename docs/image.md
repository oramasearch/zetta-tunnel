# Image and releases

zetta-tunnel ships as one `linux/amd64` image:
`docker.io/oramasearch/zetta-tunnel`. Its entrypoint is the statically linked `zetta-tunnel`
binary. The production target is `scratch`, contains no shell or package manager, and runs as
numeric user and group `65532:65532` by default. It needs no service, licence check, update feed or
other control-plane call at runtime. A role makes only the connections in its projected
configuration; `egress` is the role explicitly allowed to reach declared outside destinations.

## Roles in the image

The same entrypoint serves every role. Configuration, environment, listeners, probes, metrics and
certificate expectations remain role contracts, not image defaults:

| Command | Contract | Default listeners |
|---|---|---|
| `zetta-tunnel client` | [Client](client.md) | Local application listener from configuration |
| `zetta-tunnel relay` | [Relay](relay.md) | Tunnel and private probe listeners from configuration |
| `zetta-tunnel endpoint` | [Endpoint](endpoint.md) | Tunnel and private probe listeners from configuration |
| `zetta-tunnel egress` | [Egress gateway](egress.md) | Proxy and private probe listeners from configuration |
| `zetta-tunnel peer` | [Peer gateway](peer.md) | Peer, import and private probe listeners from configuration |
| `zetta-tunnel ingress` | [Ingress gateway](ingress.md) | Public TLS and private probe listeners from configuration |
| `zetta-tunnel mesh` | [Mesh node agent](mesh.md) | Mesh and private probe listeners from configuration |

No `EXPOSE` declaration guesses which of these operator-projected listeners a deployment uses.
Client, relay, endpoint, egress, peer and ingress deployments keep the default non-root identity.
The mesh node agent is the exception: its documented namespace capture requires a privileged Linux
security context with uid 0. It is not suitable for a restricted workload pod.

## Cluster build

The release build never uses a local container engine. `tools/build-image.sh` requires:

- a clean checkout at an existing `vX.Y.Z` tag;
- initialized submodules at the commits recorded by that tag;
- the tag to match `project(VERSION)` in `CMakeLists.txt`;
- `buildctl`, `kubectl`, `curl`, Python 3 and registry credentials available to BuildKit;
- `KCTX`, the kubectl context of a cluster with a BuildKit pod in `BUILDKIT_NAMESPACE` (default
  `buildkit`);
- `IMAGE_REPOSITORY`, the repository to push to, for example `docker.io/<org>/zetta-tunnel`.
  `REQUIRE_PRIVATE_REPOSITORY=1` also checks that an anonymous Docker Hub lookup of it answers 404,
  for a repository that must stay private.

Run:

```sh
git checkout vX.Y.Z
git submodule update --init --recursive
KCTX=<context> IMAGE_REPOSITORY=docker.io/<org>/zetta-tunnel \
DOCKER_CONFIG=/path/to/docker-config tools/build-image.sh vX.Y.Z
```

The script sends this checkout to the cluster BuildKit pod with
`platform=linux/amd64`, pushes `$IMAGE_REPOSITORY:main-<sha>` and records its digest. The Dockerfile checks
`zetta-tunnel --version` against the tag's project version while executing on the amd64 builder.
The Alpine build image is pinned by digest, and the nlohmann/json source archive is pinned by
version and SHA-256. The final image contains only the static binary; build and proof dependencies
do not enter it.

## Linux mesh proof

`tools/prove-mesh-linux.sh [proof-tag]` builds the Dockerfile's `mesh-proof` target on the same
BuildKit lane, then runs `tests/mesh_linux_integration.py` as uid 0 in a privileged pod on a Linux
node. The script creates a dedicated namespace with privileged Pod Security admission, copies the
configured Docker registry credential into a short-lived pull Secret, prints the test output and
deletes the namespace. It does not build or run a container locally.

```sh
KCTX=<context> IMAGE_REPOSITORY=docker.io/<org>/zetta-tunnel DOCKER_CONFIG=/path/to/docker-config \
  tools/prove-mesh-linux.sh mesh-proof-<sha>
```

The proof image is test-only. It contains Python and `iproute2`; neither is present in the release
image. The assertions remain documented in [mesh verification](mesh/testing.md).

The first AKS mesh run failed at capture readiness; the
[netlink correction and startup diagnostics](mesh/netlink.md) followed. The proof now also checks operation-specific
failures for projection, namespace, key and listener errors before its existing traffic/restart
assertions. Native wire tests are not a substitute for this Linux run.

## Release contract

The maintainers name the version. A release then follows these steps:

1. On a branch from `dev`, set `project(VERSION)` and add `docs/releases/vX.Y.Z.md`. The page says
   what is included and excluded, known issues, the native and Linux proof results, and where the
   image has run. Add it to [the release index](releases/README.md).
2. Merge the release-document pull request into `dev`, promote `dev` to `main` by pull request, and
   merge `main` back into `dev`. Use merge commits.
3. Tag the promotion commit `vX.Y.Z`. Publish a GitHub release named `Release vX.Y.Z` from the
   release page, with its relative links made absolute at the tag.
4. Check out that tag and run `tools/build-image.sh vX.Y.Z`. Deploy the reported
   `<repository>:main-<sha>@sha256:<digest>` through the operator. Confirm every
   deployed role is ready and that the running image ID is the reported digest.
5. Add the Docker Hub tag `vX.Y.Z` to that exact deployed digest without rebuilding. Verify the
   Git tag, GitHub release and image tag exist, and `zetta-tunnel --version` reports `X.Y.Z`.

Do not publish `latest`. A release is incomplete until its Git tag, GitHub release, immutable image
tag and deployed digest all identify the same source.


## Tunnel clients for developers

Lake hands the `client` role to developers as a download (lake#745). `tools/build-clients.sh` builds
them into one folder, with `SHA256SUMS` and `VERSION`:

| File | Built | Depends on |
|---|---|---|
| `zetta-tunnel-darwin-arm64` | on a Mac, `-DZETTA_TUNNEL_PORTABLE=ON`: OpenSSL and nghttp2 linked statically | only `/usr/lib/libc++` and `libSystem`; the script refuses any other library |
| `zetta-tunnel-linux-amd64` | the image's `runtime` stage on the cluster BuildKit (`BUILDKIT_ADDR`), written out as a file | nothing: fully static |

```sh
BUILDKIT_ADDR="kube-pod://<buildkit pod>?context=<context>&namespace=buildkit" \
CLIENTS_IMAGE=docker.io/<org>/zetta-tunnel-clients:<version>-<sha> tools/build-clients.sh
```

With `CLIENTS_IMAGE` the folder is pushed as a scratch image holding `/clients/*`
(`tools/clients.Dockerfile`), which Lake's image build copies from. macOS on Intel (an x86_64 OpenSSL), Linux arm64 and Windows are
not built yet.
