# Architecture

How zetta-tunnel fits into Orama's secure networking, and how its roles fit together. Each role's
own contract (flags, files, probes, certificates) is on its own page, listed in
[`README.md`](README.md). The system as a whole, from Lake's side, is Lake's
[`docs/architecture/secure-networking.md`](https://github.com/oramasearch/lake/blob/dev/docs/architecture/secure-networking.md).
The design and its decisions (D1–D8) are the operator's
[`docs/infrastructure/secure-networking.md`](https://github.com/oramasearch/orama-operator/blob/dev/docs/infrastructure/secure-networking.md).

## Where zetta-tunnel sits

Every workload Orama runs is a default-deny sandbox, and every path in or out is declared. Three
layers carry that out. zetta-tunnel is the data path, the bottom layer:

```text
  Lake            what a person declares     connections, egress rules, tunnel grants, peers
   │              (UI, REST, MCP)             -> Lake's Postgres control plane (desired state)
   ▼
  orama-operator  what each cluster enforces  NetworkSandbox, Connection, EgressRule, Tunnel,
   │              (identical on every          PeerConnection; Cilium policy; projected files
   │               cluster)                    and certificates for zetta-tunnel
   ▼
  zetta-tunnel    what carries the bytes       relay, endpoint, egress, peer, ingress, mesh
                  (this repository)            (one binary, one image, a role per process)
```

- **zetta-tunnel never calls Lake or the Kubernetes API.** Each role reads one configuration file
  and its certificates. The operator writes those as projections of Lake's desired state, and
  replaces them atomically. Each role reloads on a change of file (or SIGHUP). A change that
  withdraws an authorization closes the sessions it carried.
- **Cilium stays the enforcer.** The operator's policies allow a workload to reach only the
  zetta-tunnel listener its declaration names. zetta-tunnel then authorizes each connection
  again, by certificate identity, name and port. Neither layer trusts the other to be the only
  check.
- **Records go to the workspace Zetta.** Each role writes an allow or deny record for every
  connection as JSON lines. Delivering them to the workspace Zetta is zetta#1281.

## One transport

Every hop between two zetta-tunnel processes is **mutual TLS 1.3 over Corosio** (decision D5;
[`transport.md`](transport.md)), the same stack Zetta uses between its nodes (zetta#1283):
- both sides present a certificate;
- the chain is verified against a configured CA bundle;
- the expected identity must match a SAN;
- there is no plaintext fallback.

Application TLS (Postgres, HTTPS, Kafka) can run inside any hop unchanged.

Routing comes from the certificate and the projected configuration, never from bytes the
application sends. A tunnel grant's certificate names one grant, and the grant names one target.
A peer request names a service the remote side exports. The mesh uses the socket's original
destination. HTTP CONNECT, SOCKS or a forged header cannot redirect a connection.

## The roles

One statically linked binary in one image (`oramasearch/zetta-tunnel`, [`image.md`](image.md)).
The operator decides which role a process runs.

| Role | Operator kind | Runs | Carries | Contract |
|---|---|---|---|---|
| `client` | — | On a developer's machine | Loopback listener → relay | [`client.md`](client.md) |
| `relay` | `Tunnel` (`ZettaTunnel`) | One per cluster, LoadBalancer on 443 | Authenticates grant certificates, forwards to that grant's endpoint | [`relay.md`](relay.md) |
| `endpoint` | `Tunnel` | One per grant, in the workspace | Relay → one fixed target | [`endpoint.md`](endpoint.md) |
| `egress` | `EgressRule` (DNS names) | One per workspace with name rules | Workload → outside name and port, authorized before DNS | [`egress.md`](egress.md) |
| `peer` | `PeerConnection` | One per peer, at each end | Local import listener ⇄ remote named export | [`peer.md`](peer.md) |
| `ingress` | Ingress (operator#473) | Per cluster, replacing ingress-nginx | Public TLS (cert-manager) → Services by host and path | [`ingress.md`](ingress.md) |
| `mesh` | Mesh (operator#474) | DaemonSet, one per node, privileged system namespace | Pod → pod with workload identity, captured in each pod's namespace | [`mesh.md`](mesh.md) |

### Developer tunnel

```text
developer app -> client (loopback) -> mTLS -> relay (cluster, :443) -> mTLS -> endpoint (workspace) -> one target
```

1. The developer signs in to Lake. Lake creates a grant for one target, expiring at a set time.
2. The client makes a key and a CSR. Lake signs it with the grant's customer CA. The certificate
   carries `urn:orama:tunnel-grant:<uuid>` and lives at most 12 hours.
3. The operator projects the live grants into the relay's grants file:
   `{"grants":[{"id","workspace","endpoint","expires_at","client_ca_sha256"}]}`. The relay's
   client trust bundle is the union of the live grants' customer CAs, so each grant also names the
   SHA-256 fingerprints of its own customer's CAs.
4. The relay accepts the certificate only if its verified chain runs through one of the CAs its
   grant names: one customer's CA never authorizes another customer's grant. It maps the grant to its endpoint. The endpoint forwards to its one target,
   and the operator's `Connection` allows only that path.
5. Revoking or expiring a grant removes it from the projection. The relay closes that grant's live
   sessions.

The relay sees plaintext unless the application uses its own TLS. Lake records grants and sessions;
the relay and endpoint record each connection.

### Egress by DNS name

```text
workload -> egress gateway -> (resolves the allowed name itself) -> destination
```

Cilium blocks a workload's direct path out, except CIDR `EgressRule`s, which Cilium enforces
itself. A name rule routes through the gateway:
- the gateway checks the workload's source address, the exact name and the port **before** DNS;
- it resolves the name itself and connects to one returned address;
- HTTPS is routed by its SNI and forwarded unchanged;
- other TCP sends a one-line `ZTEG1 <name> <port>` preface.

The gateway never accepts an address from the workload, and it refuses an unauthorized name even
when that name resolves to the same address as an allowed one. A connected socket stays bound to
the address it was first resolved to.

### Peer connection

```text
local workload -> import listener -> mTLS -> remote peer gateway -> named export
```

Two sites can use the same private addresses (the clusters' VNets overlap). So nothing routes by
address:
- an importing gateway asks for `ZTPR1 <peer-id> <service> <port>`;
- the exporting gateway answers only for the exact service and port it exports to that peer.

Zetta-to-Zetta links between clusters run through this role with Zetta's own mTLS end to end
inside it (zetta#1282). The first user is Orama Cloud v1's US readers of the EU writer
(orama-operator#396).

### Ingress

```text
internet -> LoadBalancer :443 -> ingress (TLS from cert-manager) -> Service by host and path
```

The ingress replaces ingress-nginx (decision D8). It does:
- HTTP/1.1, HTTP/2 and WebSockets;
- streaming without buffering;
- body limits;
- reloading its routes and certificates.

It needs no privileges. ingress-nginx stays on each cluster until that cluster is cut over
(orama-operator#473), after a load comparison of the two on the cluster.

### Mesh

```text
workload -> 127.0.0.1:15001 (captured) -> mTLS -> destination pod :15008 -> application port
```

The node agent:
- enters each enrolled pod's network namespace;
- installs nftables capture through netlink;
- carries the connection with the source workload's certificate.

The destination agent authorizes that identity for the port. The workload needs no capability and
no injected proxy, and stays under restricted Pod Security. Cilium allows only port 15008 between
enrolled pods, so traffic that escapes capture is refused, not passed in the clear: **the mesh
fails closed**. Enrolment keeps application containers stopped until capture is ready
([`mesh.md`](mesh.md)). The agent is the one privileged role, in its own system namespace.

## Deployment on a cluster

| Where | What | Who installs it |
|---|---|---|
| Platform layer, every cluster | ingress, mesh agent | `helmfile.yaml` on the management cluster and `ClusterHelmRelease` on each leaf, identical (operator#473, #474) |
| One per cluster | relay | the operator, from `Tunnel` resources |
| Per workspace | endpoints, egress gateway, peer gateways | the operator, from Lake's desired rows |

The same image and roles run on every cluster, and on-prem with no internet access. Nothing in a
role depends on a hosted service. A customer's own Cloudflare account can back a `Tunnel` as
another provider, but zetta-tunnel does not need it.

## What is not here

- **Policy decisions.** Who may reach what is Lake's (declared by a person) and the operator's
  (enforced by Cilium). zetta-tunnel enforces only what its projected file says.
- **Credentials for datastores.** A scoped Postgres role for an app's connection is the
  operator's (orama-operator#469); Zetta's scoped app credentials are zetta#1280.
- **Certificate issuance.** Lake signs tunnel certificates and cert-manager issues ingress
  certificates (orama-operator#457). The mesh agent's workload certificates and CA are projected
  to it by the operator (orama-operator#474).
