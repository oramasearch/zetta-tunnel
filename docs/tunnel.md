# Developer tunnel contract

`zetta-tunnel client`, `zetta-tunnel relay`, and `zetta-tunnel endpoint` are roles of one C++26
binary for macOS, Linux and Windows. This page records the coordinator's 2026-10-14 decisions
for issue #3 and is the contract for Lake (#730) and the operator (#471).

```text
developer application -> loopback client -> TLS 1.3 relay -> TLS 1.3 endpoint -> fixed TCP target
```

Each accepted local TCP connection gets its own relay and endpoint connections. Both network hops
require mutual TLS. The relay is trusted with plaintext; application TLS (for example PostgreSQL
TLS) can also run inside the tunnel. There is no destination supplied in application traffic:
the certificate selects one grant, the grant selects one endpoint, and that endpoint's startup
configuration selects one target. HTTP CONNECT, SOCKS and JSON sent by a client are ordinary target
bytes, never routing instructions. The operator must also enforce the narrow endpoint-to-target
`Connection` and NetworkPolicy. The endpoint cannot prevent an application protocol at its target
from providing additional services of its own.

## Authentication and certificates

The developer signs into Lake using Lake's existing sign-in. Lake issues a separate client
certificate for each tunnel grant, signed by that grant's customer CA. Its URI SAN is exactly
`urn:orama:tunnel-grant:<grant-uuid>`, where UUIDs use lowercase canonical `8-4-4-4-12` notation.
There must be exactly one URI SAN; DNS SANs do not provide grant identity. Certificate lifetime
(`notAfter - notBefore`) must be at most 12 hours, and `notAfter` must not exceed the grant's
`expires_at`. The relay rejects certificates that violate either bound. An expired certificate
cannot authenticate, and live sessions also end when the certificate expires.

The client never calls Clerk or Lake. The relay and endpoint never call Lake. They trust only
explicit CA files; system CA fallback, verification bypass flags, TLS below 1.3, and session
resumption are disabled. Peer chains, validity and intended certificate use are verified before
forwarding. DNS identities require an exact SAN match (no wildcard or common-name fallback); an IP
identity requires an IP SAN. Private keys must match their leaf certificates. Certificate files may
include intermediate chains; keys and CA bundles are PEM.

| Connection | Presenting credentials | Verifier's trust and identity |
|---|---|---|
| Developer to relay | Lake grant certificate and key | Relay `--ca`: union of customer CAs; verified URI SAN supplies grant ID; the verified chain must include a CA the grant names |
| Relay to developer | Relay server certificate and key | Client `--ca`: relay server CA; `--server-name` or relay hostname/IP SAN |
| Relay to endpoint | Operator workload certificate and key | Endpoint `--ca`: operator workload CA; exact `--peer-name` SAN |
| Endpoint to relay | Operator endpoint certificate and key | Relay `--endpoint-ca`; exact DNS SAN `endpoint.<grant-uuid>` |

Keep the developer and workload trust domains distinct. In particular, a developer certificate
must not authorize a connection directly to an endpoint. An ingress in front of the relay must
pass TCP/TLS through so the relay receives the developer's certificate; terminating that TLS at
an ingress without forwarding the authenticated stream does not satisfy this protocol.

TLS uses Corosio TCP and OpenSSL. The streaming adapter uses Corosio's cancellable socket readiness
operations so a reader and writer can progress concurrently on one event-loop thread. The existing
framed transport API remains available for other consumers. On the relay-to-endpoint hop, the
endpoint sends the five ASCII bytes `ZTUN1` after verifying the relay, connecting the target and
recording its session start. The relay consumes this acknowledgement before recording its own
start or forwarding application bytes. This handles TLS 1.3's client-side handshake completion
before server-side client-certificate verification. After that prefix, both hops carry raw bytes.
EOF or any I/O error closes the complete session and cancels the other direction; TCP half-close
is not exposed. The original framed API retains its explicit graceful TLS shutdown operation.

## Grant file and revocation

The operator projects the live set into a mounted ConfigMap or Secret file:

```json
{
  "grants": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "workspace": "workspace-example",
      "endpoint": "endpoint-service.workspace-example.svc:7444",
      "expires_at": "2026-10-14T20:00:00Z",
      "client_ca_sha256": ["3f1c...64 lowercase hex characters..."]
    }
  ]
}
```

`workspace` is a Kubernetes namespace label, `endpoint` is `host:port` (bracket IPv6), and
`expires_at` is RFC3339 with an explicit zone. Fractional seconds and numeric UTC offsets are
accepted. `client_ca_sha256` lists one to 16 distinct SHA-256 fingerprints, in lowercase hex, of the
DER encoding of each customer CA certificate allowed to sign this grant's developer certificates
(the certificates in the ZettaTunnel's `clientCAPEM`).

### Binding a grant to its customer CA

The relay's `--ca` is the union of every live grant's customer CA, so TLS alone only proves that some
customer signed the certificate. Authorization then requires that one certificate in the verified
chain above the leaf (an intermediate or the trust anchor) has a fingerprint the selected grant
lists. Otherwise the connection is refused with reason `grant_issuer`, before any endpoint is
contacted. A customer that holds its own CA key (for example after recovering it) and knows another
customer's grant ID and expiry therefore still cannot open that grant's tunnel (LSR-074,
[#28](https://github.com/oramasearch/zetta-tunnel/issues/28)). A grant without `client_ca_sha256`
is a malformed snapshot, so a relay never falls back to trusting any CA in its bundle. Changing a
grant's fingerprints is a grant change and ends its live sessions. Unknown/missing fields, duplicate JSON keys, duplicate grant IDs, invalid UUIDs,
invalid namespaces and malformed addresses or dates reject the entire snapshot. Limits are
1 MiB per file, 10,000 grants and eight JSON nesting levels. Publish complete files using atomic
replacement; Kubernetes projected-volume symlink changes are followed.

The relay checks file modification time and length every two seconds and at each authorization.
SIGHUP forces a reload on POSIX, including when the timestamp and length are unchanged. Windows
uses the same periodic reload without SIGHUP. Every new connection must have a verified grant ID
present in the current valid snapshot, with an unexpired grant and a bounded certificate.

Missing, unreadable or malformed files clear the allow set, make readiness fail and terminate
existing sessions. They never preserve an old allow set. Valid snapshots restore readiness.
When a grant disappears, expires or changes, its sessions close within the next poll; idle and
backpressured sessions are included. Expiry and session cancellation are checked on a 100 ms
event-loop tick, without waiting for application traffic. Changes to workspace, endpoint or
expiry also terminate existing sessions instead of retargeting them. An empty valid grant set
is ready but authorizes nobody. Certificates, keys and CA bundles are loaded at startup and
refreshed every two seconds or on SIGHUP, outside connection handling. Streams share each immutable TLS context snapshot. An invalid
refresh refuses new traffic and fails readiness until valid files return. Existing streams retain
their snapshot; restart after a CA rotation when existing TLS sessions must also be replaced.

## Command-line configuration

There are no role-specific environment variables or implicit configuration files. Unknown,
duplicate, missing-value and other-role flags fail startup. `--help` and `<role> --help` show the
flag summary; `--version` reads the CMake project version. Addresses require explicit nonzero ports.
Listeners use numeric IPv4 or bracketed IPv6 addresses. Outbound hosts may use DNS.

| Flag | Roles | Meaning/default |
|---|---|---|
| `--cert FILE` | all | Required identity certificate/chain |
| `--key FILE` | all | Required matching private key |
| `--ca FILE` | all | Required peer CA bundle, as in the trust table |
| `--listen IP:PORT` | client | `127.0.0.1:5433`; only loopback IPs allowed |
| `--listen IP:PORT` | relay | `0.0.0.0:7443` |
| `--listen IP:PORT` | endpoint | `0.0.0.0:7444` |
| `--max-sessions N` | all | 128; authenticated sessions, range 1–4096 |
| `--max-pending-sessions N` | all | 128; separate setup budget, range 1–4096 |
| `--max-pending-per-source N` | all | 32; concurrent setup sockets per source IP, range 1–4096 |
| `--relay HOST:PORT` | client | Required outbound relay address |
| `--server-name DNS_OR_IP` | client | Relay certificate identity; defaults to `--relay` host |
| `--grants FILE` | relay | Required operator-projected grant snapshot |
| `--endpoint-cert FILE` | relay | Required operator-issued relay workload certificate |
| `--endpoint-key FILE` | relay | Required matching workload private key |
| `--endpoint-ca FILE` | relay | Required CA for endpoint certificates |
| `--peer-name DNS_OR_IP` | endpoint | Required expected relay workload certificate SAN |
| `--target HOST:PORT` | endpoint | Required single TCP destination, fixed for process lifetime |
| `--health-listen IP:PORT` | relay, endpoint | Separate plain HTTP listener, `127.0.0.1:8080` |
| `--audit FILE` | relay, endpoint | Append JSON lines to file; `-` (default) writes stdout |

Each direction has a 16 KiB copy buffer; there is no unbounded data queue. Connection setup,
including DNS, connect, TLS and endpoint acknowledgement, has a ten-second deadline. Capacity
overflow is refused. Relay sessions enter the authenticated budget only after TLS and grant
authorization; endpoints do so after verifying the relay identity. Pending sockets cannot consume
that budget. The loopback client uses the same admission accounting before outbound setup.
Source limits use the socket address without its port, with IPv4-mapped IPv6 normalized to IPv4;
forwarding headers never select a quota. A proxy that shares one source address shares its quota,
so configure limits for that topology. SIGINT/SIGTERM cancel accepts and sessions and write
session-end records.
Local peers on the developer's machine can use its loopback listener, so protect that machine's
accounts and private-key files. No privileged ports, `NET_ADMIN`, packet capture, or internet API
access are required. DNS resolution is local to each role; the endpoint resolves only its configured
target. Restrict egress with the operator's generated policy.

## Health, readiness and metrics

Relay and endpoint expose `GET /healthz` (200 while the event loop responds), `GET /readyz`
(200 after startup configuration validation while audit is usable; otherwise 503), and 404 for other paths. Relay
readiness also requires a readable, valid grant snapshot. Readiness is not a probe of every
upstream target. These unauthenticated paths belong on a separate, private probe port; do not
route them through the developer-facing ingress. There are at most 16 probe connections,
a five-second probe deadline, and a 4 KiB request-header limit. The client has no HTTP port.
Metrics are not implemented; audit records supply per-session byte counts.

## AuditSink and JSON lines

`AuditSink::write(const AuditRecord&)` is the tunnel writer interface in `src/tunnel.hpp`; the
overload for egress decisions uses the same sink.
The current `JsonLinesSink` appends one JSON object per line and flushes each record. The relay
is authoritative for grant/workspace identity. The endpoint also records transport sessions,
with empty grant/workspace fields because it authenticates the relay's workload identity. The
client emits no audit records. A TLS refusal leaves `grant_id` empty unless a verified certificate's
identity was successfully extracted. The session's target is never taken from an unauthenticated
request. Application payloads, certificate contents, credentials and private keys are never logged.

| Field | Type and meaning |
|---|---|
| `schema` | Integer `1` |
| `event` | `session_start`, `session_end`, or `refusal` |
| `role` | `relay` or `endpoint` |
| `session_id` | Random 128-bit identifier encoded as 32 hexadecimal characters; pairs start/end |
| `timestamp` | Event UTC RFC3339 timestamp |
| `started_at` | TCP acceptance UTC RFC3339 timestamp, also present for refusals |
| `grant_id` | Verified Lake grant UUID; Lake maps it to the person |
| `workspace` | Grant's namespace |
| `peer` | Numeric TCP peer address and port (the ingress address if it proxies TCP) |
| `endpoint` | Relay's selected endpoint, or endpoint's configured target |
| `reason` | Empty for start; fixed reason code for end/refusal |
| `bytes_up` | Plaintext bytes successfully written toward the target |
| `bytes_down` | Plaintext bytes successfully written toward the developer |

Byte counts exclude the `ZTUN1` preface and are cumulative through the event, not end-to-end
delivery acknowledgements. Reasons include `grant_absent`, `grant_expired`, `grant_removed`,
`grant_changed`, `grant_issuer`, `certificate_identity`, `certificate_lifetime`, `certificate_exceeds_grant`,
`tls_peer_refused`, `upstream_tls_refused`, `tls_configuration`, `upstream_connect`, `capacity`,
`setup_timeout`, `peer_closed`, `shutdown`, `unavailable`, `audit_unavailable`, `credentials_changed`,
`credentials_unavailable`, and `session_error`.

**A rotated or withdrawn credential ends the sessions authorized under it** (zetta-tunnel#37). On every
refresh the gateway fingerprints the certificate, key and CA files' contents (and, on a relay, the
endpoint credentials), read through any symlink, so a projected-volume swap counts. When the
fingerprint changes, every session closes with `credentials_changed` before the new context is used;
when a file is missing, unreadable or invalid, every session closes with `credentials_unavailable`
and new traffic is refused until a valid refresh. A new TLS context carries no resumption state from
the old one.

An audit failure disables readiness and new forwarding and cancels live sessions. A process restart
is required after repairing the sink. A record cannot be guaranteed after the sink itself fails or
after an uncatchable process termination. Collect/rotate stdout or the append file externally; no
durable queue or retention engine is included. Use a regular local file or a continuously drained
stdout collector because synchronous audit writes depend on the sink making progress.

The workspace Zetta writer is explicitly deferred behind this interface to zetta#1281. This release
does not claim to have written records into Zetta. Lake certificate issuance and operator projection,
deployment and NetworkPolicy generation remain in their respective repositories. Gateways and mesh
are outside issue #3. See [verification](tunnel/testing.md) for executable acceptance coverage.
