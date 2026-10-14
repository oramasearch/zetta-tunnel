# zetta-tunnel

**zetta-tunnel is Orama's own tunnel**: a C++26 program that gives a developer, or another
network, a narrow, authenticated path to one service, app or deployment inside an Orama workspace,
without exposing it to the internet.

The Orama operator manages tunnels as an abstract kind with a provider behind it, the way a
`KubernetesCluster` is backed by an `AksCluster`. zetta-tunnel is the provider Orama owns: it runs
inside our clusters, inside a customer's own cluster, and with no internet access at all, and it is
licensed so that Orama can sell it. Third-party tunnel services can sit behind the same kind as
other providers, where their terms allow.

## Status

**Nothing is built yet.** The binary only reports its version. The design comes first, in the
operator's secure-networking epic
([orama-operator#437](https://github.com/oramasearch/orama-operator/issues/437)) and Lake's
([lake#724](https://github.com/oramasearch/lake/issues/724)). Private repository; proprietary to
Orama.

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

From the epic and the research, to be settled in the design:

- A developer authenticates as themselves and opens a tunnel to **one** service, app or deployment;
  nothing else in the workspace is reachable through it.
- Access is granted, expires, is revoked, and is audited per person. Lake issues and shows it.
- Traffic is encrypted end to end between the developer's machine and the tunnel's endpoint in the
  cluster, and the endpoint's path into the workspace is a declared, narrow network policy.
- It runs without any outside service, behind restricted Pod Security in the workspace.
- Possibly, later: service-addressed links between clusters or to a customer's network, whose
  addresses overlap ours (every AKS cluster today uses `10.224.0.0/12`).

**Open, for the design:** the transport (WireGuard through the OS kernel, QUIC, or TLS over
Corosio as Zetta's node-to-node links already use), the relay, the client a developer installs,
and how it authenticates.

## Build and test

C++26, CMake 3.28 or newer, and Clang 17 or newer (on macOS, Homebrew LLVM: `brew install llvm`).

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
./build/zetta-tunnel --version
```

## Where it sits

- [`oramasearch/zetta-bridge`](https://github.com/oramasearch/zetta-bridge) vendors it as
  `modules/zetta-tunnel`, beside Zetta.
- [`oramasearch/orama-operator`](https://github.com/oramasearch/orama-operator) runs it, as the
  provider behind the tunnel kind.
- [`oramasearch/lake`](https://github.com/oramasearch/lake) grants and shows tunnels.
- Its image is the private Docker Hub repository `oramasearch/zetta-tunnel`.
