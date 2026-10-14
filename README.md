# zetta-tunnel

**zetta-tunnel is Orama's own network layer**, in C++26. It does three things:

- **Tunnels:** a developer, or another network, gets a narrow, authenticated path to one service,
  app or deployment inside an Orama workspace, without exposing it to the internet.
- **The mesh:** connections between workloads carry identity and mutual TLS.
- **The ingress:** traffic enters a cluster through it, replacing ingress-nginx.

The Orama operator manages each of these as an abstract kind with a provider behind it, the way a
`KubernetesCluster` is backed by an `AksCluster`. zetta-tunnel is the provider Orama owns: it runs
inside our clusters, inside a customer's own cluster, and with no internet access at all, and it is
licensed so that Orama can sell it. Third-party tunnel services can sit behind the same kind as
other providers, where their terms allow.

## Status

**The transport, developer tunnel, DNS-name egress gateway and peer gateway are built.**
`zetta-tunnel client`, `relay`, and `endpoint` provide grant-certificate authentication,
one-target forwarding, live revocation/expiry and JSON-lines audit. `zetta-tunnel egress`
authorizes workload source IPs, exact DNS names and ports from operator-projected rules, with HTTPS
SNI and explicit other-TCP routing. `zetta-tunnel peer` exchanges only projected named services
over mutual TLS, including when the two sites use identical private addresses.
`zetta_tunnel_transport` provides mutual TLS 1.3 client/server connections, pinned peer identities,
binary frames and clean TLS shutdown. Workspace Zetta audit delivery is deferred to zetta#1281.
The mesh and ingress remain unbuilt. The decided design is in
the operator's secure-networking epic
([orama-operator#437](https://github.com/oramasearch/orama-operator/issues/437)) and Lake's
([lake#724](https://github.com/oramasearch/lake/issues/724)). See
[`docs/transport.md`](docs/transport.md), [`docs/tunnel.md`](docs/tunnel.md),
[`docs/egress.md`](docs/egress.md) and [`docs/peer.md`](docs/peer.md).
Private repository; proprietary to Orama.

## Why it exists

Steve, 2026-10-13: *"our instinct is to implement our own c++ components, so that's probably the
best path for customization, flexibility, observability"*, and 2026-10-14: *"let's just create a new
c++ project (private) ... let's call it zetta-tunnel"*.

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

From the epic and the decided design:

- A developer authenticates as themselves and opens a tunnel to **one** service, app or deployment;
  nothing else in the workspace is reachable through it.
- Access is granted, expires, is revoked, and is audited per person. Lake issues and shows it.
- Traffic uses mutual TLS from the developer's machine to the trusted relay and from the relay to
  the endpoint. Application TLS may run inside it. The endpoint's path into the workspace is a
  declared, narrow network policy.
- It runs without any outside service, behind restricted Pod Security in the workspace.
- Possibly, later: service-addressed links between clusters or to a customer's network, whose
  addresses overlap ours (every AKS cluster today uses `10.224.0.0/12`).

**As the mesh** (Steve, 2026-10-14: *"d7 and d8 are zetta-tunnel too"*):
- Connections between workloads carry identity and mutual TLS, without changing the workloads,
  which stay under restricted Pod Security with no `NET_ADMIN`.
- It must fail closed: traffic that escapes capture escapes the policy. Istio ambient's CNI plugin
  and ztunnel are the benchmark.
- It runs beside AKS-managed Cilium, which stays the enforcer, as defence in depth.

**As the ingress:**
- Traffic enters a cluster through it. It terminates TLS with certificates cert-manager issues
  ([orama-operator#457](https://github.com/oramasearch/orama-operator/issues/457)) and routes each
  host to its Service, replacing ingress-nginx, which is retired upstream.

**Decided and implemented:** TLS 1.3 over Corosio, Lake-issued grant certificates,
operator-projected grant files and relay-enforced revocation, plus operator-projected DNS egress
rules enforced by source, exact name and port. See the [tunnel contract](docs/tunnel.md) and
[egress contract](docs/egress.md).

## Build and test

C++26, CMake 3.28 or newer, Clang 17 or newer, OpenSSL 3, nlohmann/json 3.12 and Python 3 for tests.
See [build prerequisites and verification](docs/tunnel/testing.md).

```sh
cmake -S . -B build -G Ninja
cmake --build build -j 6
ctest --test-dir build --output-on-failure
./build/zetta-tunnel --version
```

The build produces the `zetta_tunnel_transport` library. Set `BUILD_SHARED_LIBS=ON` for a shared
library; the public header is [`include/zetta_tunnel/transport.hpp`](include/zetta_tunnel/transport.hpp).

## Where it sits

- [`oramasearch/zetta-bridge`](https://github.com/oramasearch/zetta-bridge) vendors it as
  `modules/zetta-tunnel`, beside Zetta.
- [`oramasearch/orama-operator`](https://github.com/oramasearch/orama-operator) runs it, as the
  provider behind the tunnel kind.
- [`oramasearch/lake`](https://github.com/oramasearch/lake) grants and shows tunnels.
- Its image is the private Docker Hub repository `oramasearch/zetta-tunnel`.
