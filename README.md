# zetta-tunnel

**zetta-tunnel is Orama's own network layer**, in C++26. It does three things:

- **Tunnels:** a developer, or another network, gets a narrow, authenticated path to one service,
  app or deployment inside an Orama workspace, without exposing it to the internet.
- **The mesh:** connections between workloads carry identity and mutual TLS.
- **The ingress:** traffic enters a cluster through it, replacing ingress-nginx.

The Orama operator manages each of these as an abstract kind with a provider behind it, the way a
`KubernetesCluster` is backed by an `AksCluster`. zetta-tunnel is the provider Orama owns: it runs
inside our clusters, inside a customer's own cluster, and with no internet access at all, and it is
open source under the MIT License. Third-party tunnel services can sit behind the same kind as
other providers, where their terms allow.

## Status

**The transport, developer tunnel, DNS-name egress, peer and ingress gateways, mesh node agent,
and amd64 image and release workflow are built.**
`zetta-tunnel client`, `relay`, and `endpoint` provide grant-certificate authentication,
one-target forwarding, live revocation/expiry and JSON-lines audit. `zetta-tunnel egress`
authorizes workload source IPs, exact DNS names and ports from operator-projected rules, with HTTPS
SNI and explicit other-TCP routing. It checks all resolved destinations for public unicast
addresses before connecting, with optional operator-projected cluster CIDR exclusions.
`zetta-tunnel peer` exchanges only projected named services over mutual TLS, including when the
two sites use identical private addresses.
`zetta-tunnel ingress` terminates mounted cert-manager TLS and routes hosts/paths to Services,
with body limits, unbuffered streaming, WebSockets, HTTP/2, reloads, probes and metrics.
Tunnel, egress, peer and ingress listeners separate pending setup capacity from established sessions,
bound pending sockets per source, and keep setup deadlines independent of progress. Relay and
peer streams share TLS contexts loaded outside accept handling; public ingress also bounds
established connections and requests per source.
`zetta-tunnel mesh` installs fail-closed Linux namespace capture and carries exact workload
identities over mutual TLS while Cilium remains the policy enforcer. Workload runtimes pin a
namespace descriptor after checking the projected pod UID and namespace inode; this projection
contract requires the paired operator projector update.
`zetta_tunnel_transport` provides mutual TLS 1.3 client/server connections, pinned peer identities,
binary frames and clean TLS shutdown. Workspace Zetta audit delivery is deferred to zetta#1281.
**Released as [v0.2.0](docs/releases/v0.2.0.md)** (2026-11-02): four security fixes and the peer
setup-deadline fix; the grants file and mesh projection change, so the operator must follow.
[v0.1.0](docs/releases/v0.1.0.md) (2026-10-15) was the first release, with the image and portable
tunnel clients for macOS arm64 and Linux amd64. The privileged Linux mesh proof passed on an AKS
node. Ingress cluster deployment and the ingress-nginx load comparison are pending. The design is
the Orama operator's secure-networking design
([`docs/infrastructure/secure-networking.md`](https://github.com/oramasearch/orama-operator/blob/dev/docs/infrastructure/secure-networking.md)).
How the roles fit together, and with Lake and the operator: [`docs/architecture.md`](docs/architecture.md).
See
[`docs/transport.md`](docs/transport.md), [`docs/tunnel.md`](docs/tunnel.md),
[`docs/egress.md`](docs/egress.md), [`docs/peer.md`](docs/peer.md),
[`docs/ingress.md`](docs/ingress.md), [`docs/mesh.md`](docs/mesh.md) and
[`docs/image.md`](docs/image.md).
MIT License; see [License](#license).

## Why it exists

Orama builds its own C++ components where it can, because that gives the most room for
customization, flexibility and observability. zetta-tunnel is that choice for the network layer.

The research behind it is in the operator repository,
[`docs/research/secure-networking/`](https://github.com/oramasearch/orama-operator/tree/dev/docs/research/secure-networking):

- **Hosted tunnel services cannot simply be resold.** Cloudflare's self-serve terms forbid selling
  access to its services or using them as a VPN or proxy service without written permission, and
  its Zero Trust terms forbid resale. Tailscale, ngrok and Twingate have similar terms.
- **Every Orama install must work air-gapped.** A tunnel that depends on an outside service cannot.
- **What a tunnel needs that no off-the-shelf piece gives us:** authorization tied to Lake's
  identities and grants, a narrow path to exactly one target, revocation, and an audit of who was
  connected.

## What it has to do

From the design:

- A developer authenticates as themselves and opens a tunnel to **one** service, app or deployment;
  nothing else in the workspace is reachable through it.
- Access is granted, expires, is revoked, and is audited per person. Lake issues and shows it.
- Traffic uses mutual TLS from the developer's machine to the trusted relay and from the relay to
  the endpoint. Application TLS may run inside it. The endpoint's path into the workspace is a
  declared, narrow network policy.
- It runs without any outside service, behind restricted Pod Security in the workspace.
- Possibly, later: service-addressed links between clusters or to a customer's network, whose
  addresses overlap the cluster's own (two AKS clusters commonly use the same pod range).

**As the mesh** (the design's decisions D7 and D8 are carried by zetta-tunnel too):
- Connections between workloads carry identity and mutual TLS, without changing the workloads,
  which stay under restricted Pod Security with no `NET_ADMIN`.
- It must fail closed: traffic that escapes capture escapes the policy. Istio ambient's CNI plugin
  and ztunnel are the benchmark.
- It runs beside AKS-managed Cilium, which stays the enforcer, as defence in depth.

**As the ingress:**
- Traffic enters a cluster through it. It terminates TLS with certificates cert-manager issues
  and routes each
  host to its Service, replacing ingress-nginx, which is retired upstream.

**Decided and implemented:** TLS 1.3 over Corosio, Lake-issued grant certificates,
operator-projected grant files and relay-enforced revocation, plus operator-projected DNS egress
rules enforced by source, exact name and port. See the [tunnel contract](docs/tunnel.md) and
[egress contract](docs/egress.md).

## Build and test

C++26, CMake 3.28 or newer, Clang 17 or newer, OpenSSL 3, nlohmann/json 3.12,
pkg-config, libnghttp2 >= 1.61 and Python 3 for tests.
See [build prerequisites and verification](docs/tunnel/testing.md).

```sh
cmake -S . -B build -G Ninja
cmake --build build -j 6
ctest --test-dir build --output-on-failure
./build/zetta-tunnel --version
```

Install the binary on your `PATH` (it is the only file installed; Capy and Corosio are linked in
statically and install nothing):

```sh
sudo cmake --install build            # /usr/local/bin/zetta-tunnel
cmake --install build --prefix ~/.local  # or ~/.local/bin/zetta-tunnel, without sudo
```

Build out of the source tree, as above. CMake refuses a build inside it, which would leave CMake's files
in the checkout and in the Capy and Corosio submodules.

Release images are built without a local container engine, on a BuildKit pod in a Kubernetes
cluster. See [Image and releases](docs/image.md).

The build produces the `zetta_tunnel_transport` library. Set `BUILD_SHARED_LIBS=ON` for a shared
library; the public header is [`include/zetta_tunnel/transport.hpp`](include/zetta_tunnel/transport.hpp).

## Where it sits

- [`oramasearch/orama-operator`](https://github.com/oramasearch/orama-operator) runs it, as the
  provider behind the tunnel kind.
- [`oramasearch/lake`](https://github.com/oramasearch/lake) grants and shows tunnels.
- Its image is `oramasearch/zetta-tunnel` on Docker Hub.

## License

MIT, see [LICENSE](LICENSE). Third-party components and their licenses are in
[THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES). Contributions are welcome under the
[Contributor License Agreement](CLA.md); see [CONTRIBUTING.md](CONTRIBUTING.md).
