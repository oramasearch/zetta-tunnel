# Documentation

- [Developer tunnel contract](tunnel.md): Lake certificates, grant projection, revocation, audit,
  all role flags, health and readiness.
- [Client](client.md), [relay](relay.md), and [endpoint](endpoint.md): role deployment references.
- [Tunnel verification](tunnel/testing.md): real TLS acceptance tests and native PostgreSQL proof.
- [Transport](transport.md): the mutual TLS 1.3 client/server interface, framed stream and security
  behavior.
- [Licences](licences.md): licences for every dependency linked by zetta-tunnel.

The secure-networking design and the Lake/operator desired-state contract live in the operator
repository's `docs/infrastructure/secure-networking.md`. This repository implements decision D5;
developer tunnels implement the coordinator's issue #3 contract. Gateways, the mesh and ingress
are tracked separately; workspace Zetta audit delivery is deferred to zetta#1281.
