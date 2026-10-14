# Documentation

- [Architecture](architecture.md): where zetta-tunnel sits under Lake and the operator, the one
  transport, how each role carries traffic, and what runs where on a cluster.
- [Developer tunnel contract](tunnel.md): Lake certificates, grant projection, revocation, audit,
  all role flags, health and readiness.
- [Client](client.md), [relay](relay.md), and [endpoint](endpoint.md): role deployment references.
- [Tunnel verification](tunnel/testing.md): real TLS acceptance tests and native PostgreSQL proof.
- [Egress gateway](egress.md): projected DNS rules, SNI and explicit TCP routing, probes and
  decision records.
- [Egress verification](egress/testing.md): exact-name, rebinding, reload and resource proofs.
- [Peer gateway](peer.md): mutual-TLS named services between networks, projection, revocation,
  probes and decision records.
- [Peer verification](peer/testing.md): overlapping-address, mutual-authentication, isolation,
  reload and resource proofs.
- [Ingress gateway](ingress.md): cert-manager TLS, host/path routing, HTTP/2, WebSockets,
  streaming, body limits, projected reload, probes and metrics.
- [Ingress verification](ingress/testing.md) and [benchmark](ingress/benchmark.md): native
  protocol/resource proofs and local throughput/latency; cluster comparison pending.
- [Mesh node agent](mesh.md): namespace capture, mutual-TLS workload identity, fail-closed
  lifecycle, probes, metrics and operator projection.
- [Mesh verification](mesh/testing.md): portable validation and the privileged Linux namespace
  acceptance command.
- [Mesh netlink and diagnostics](mesh/netlink.md): transaction wire fixtures, acknowledgement
  validation and safe startup failure details.
- [Image and releases](image.md): the private amd64 image, cluster BuildKit workflow, Linux image
  proof and digest-based release contract.
- [Releases](releases/README.md): release-page index and conventions.
- [Transport](transport.md): the mutual TLS 1.3 client/server interface, framed stream and security
  behavior.
- [Licences](licences.md): licences for every dependency linked by zetta-tunnel.

The secure-networking design and the Lake/operator desired-state contract live in the operator
repository's `docs/infrastructure/secure-networking.md`. This repository implements decisions D3
and D5-D8; developer tunnels implement issue #3, DNS-name egress implements issue #4, peer gateways
implement issue #5, the ingress data plane implements issue #6 and the mesh node agent implements
issue #7. The image and release workflow implement issue #8. Ingress and mesh cluster proofs are
coordinated through orama-operator#473 and #474.
Workspace Zetta audit delivery is deferred to zetta#1281.
