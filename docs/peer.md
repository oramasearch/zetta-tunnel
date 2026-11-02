# Peer gateway contract

`zetta-tunnel peer` is the gateway at one end of a Lake `PeerConnection`. Each instance represents
one peer row. It publishes local listeners for imported named services and accepts mutual-TLS
connections for exported named services. No pod, service or VPC address is sent as the routing
identity, so identical private addresses and ports at the two sites do not conflict.

```text
local workload -> import listener -> mutual TLS -> remote gateway -> named export target
```

The operator's network policy permits workloads to reach only their declared import listeners and
permits the gateway to reach only projected export targets. Gateway name/port authorization is an
additional enforcement layer.

## Gateway protocol

For each local connection to an import listener, the gateway opens a TLS 1.3 connection to the
configured remote gateway. It sends this bounded ASCII request:

```text
ZTPR1 <peer-id> <service-name> <port>\n
```

The remote gateway verifies the certificate and exact peer identity before it reads the request.
It then requires the projected peer UUID and an exact exported service-name/port pair. Only after
the target connects and the allow record is flushed does it answer `ZTPA1\n`. The importing gateway
also flushes its allow record before it forwards local application bytes. The preface is limited to
511 bytes. Application traffic after the acknowledgement is an unchanged bidirectional TCP byte
stream; application TLS can run inside it.

Requests with another peer UUID, name or port are closed without connecting a target. Service
names are lowercase ASCII DNS-style names without wildcards. Numeric addresses are never service
names.

## Operator-projected peer

The operator publishes one complete JSON file by atomic replacement. The source is a present
`network_peers` row. It resolves each Lake export `target_kind` and `target_id` to its local target,
adds the target's service name, and allocates one private local listener for every import:

```json
{
  "peer": {
    "id": "11111111-1111-4111-8111-111111111111",
    "workspace": "workspace-example",
    "remote": "peer-b.example.internal:7446",
    "imports": [
      {
        "name": "writer.eu",
        "port": 5432,
        "listen": "0.0.0.0:15432"
      }
    ],
    "exports": [
      {
        "name": "writer.us",
        "port": 5432,
        "target": "writer.v1-us.svc.cluster.local:5432"
      }
    ]
  }
}
```

The document and peer objects accept exactly the shown fields. UUIDs use lowercase canonical
notation, workspace values use Kubernetes namespace syntax, service names are lowercase and ports
are in 1–65535. Import listeners must use numeric IP addresses. Remote and export targets may use
DNS names or numeric addresses. Import name/port pairs, import listeners and export name/port pairs
cannot repeat.

The file limit is 1 MiB, with at most 256 imports, 256 exports and eight JSON nesting levels. The
gateway checks replacement metadata every two seconds and before authorization. SIGHUP forces a
reload on POSIX; Windows uses the periodic check. Changed authorization closes active sessions.
A missing, unreadable or invalid file removes all import listeners, closes all sessions and makes
readiness fail. This is the revocation behavior for a row whose `desired` value becomes `absent`:
the operator removes its projection after withdrawing the generated Services and policies. A valid
peer with empty import and export arrays is ready but exchanges no services.

## Command-line configuration

There are no environment variables or implicit configuration files. Unknown, duplicate,
missing-value and other-role flags fail startup. Listener values must be numeric IP addresses with
explicit nonzero ports.

| Flag | Meaning/default |
|---|---|
| `--configuration FILE` | Required operator-projected peer document |
| `--cert FILE` | Required PEM certificate chain for this gateway |
| `--key FILE` | Required PEM private key for this gateway |
| `--ca FILE` | Required PEM trust roots for the remote gateway |
| `--peer-name DNS_OR_IP` | Required exact identity expected in the remote certificate |
| `--listen IP:PORT` | Mutual-TLS gateway listener; `0.0.0.0:7446` |
| `--health-listen IP:PORT` | Private plain-HTTP probe listener; `127.0.0.1:8080` |
| `--max-sessions N` | `128`; authorized sessions, range 1–4096 across imports and exports |
| `--max-pending-sessions N` | `128`; separate setup budget, range 1–4096 |
| `--max-pending-per-source N` | `32`; pending sockets per source IP, range 1–4096 |
| `--audit FILE` | Append JSON lines to a file; `-` writes stdout and is the default |

The local certificate must support both TLS client and server authentication and contain the exact
DNS or IP identity configured by the other gateway. Both sides always require a certificate rooted
in `--ca`; TLS 1.2 and earlier, missing certificates, an untrusted chain and a different identity
are refused. The private key is read only by the process and is never logged. Certificate or key
loading failure stops startup.

The TLS listener must be reachable only from the named remote peer. Import and probe listeners are
plain TCP and must remain private to their intended workloads and the platform, respectively.

## Health, readiness and resources

`GET /healthz` returns 200 while the event loop responds. `GET /readyz` returns 200 only while the
peer projection, TLS credentials and audit sink are usable. Other paths return 404. There are at most 16 probe
connections, a five-second probe deadline and a 4 KiB request-header limit.

Each direction uses one 16 KiB copy buffer. A request buffers at most 512 bytes before the newline.
TLS authentication, request authorization and target setup have a ten-second deadline. Session
capacity is fixed by `--max-sessions` (default 128). Pending connections use a separate
`--max-pending-sessions` budget (128) and `--max-pending-per-source` share (32); both accept
1–4096. These setup budgets cover both the public peer listener and private import listeners.
Exports enter the active budget after mutual TLS and service authorization; imports do so after
the remote service acknowledges setup. Deadlines and the decision record's `started_at` begin at acceptance, and progress never extends
the ten-second setup deadline. Overflow is refused while probes remain responsive.

TLS contexts are loaded at startup and refreshed every two seconds or on SIGHUP, outside accept
handling. Streams retain their context snapshot. Invalid credentials fail readiness and refuse
new traffic until a valid refresh. Source quotas use the normalized socket IP without its port;
a proxy that hides client addresses shares one quota, so configure limits for that topology. SIGINT
and SIGTERM close all listeners and sessions. Metrics are not implemented; decision records are
the current observability interface.

## Decision records

Authorization fails closed around the audit sink. Both gateways flush an allow before forwarding
application data. Sink failure disables readiness, closes sessions and refuses new traffic.
Payloads, certificate contents and process credentials are never logged.

| Field | Meaning |
|---|---|
| `schema` | Integer `1` |
| `event` / `role` | `peer_decision` / `peer` |
| `timestamp` / `started_at` | UTC RFC3339 record and local TCP-accept times |
| `session_id` | Process-local integer connection identifier |
| `decision` | `allow` or `deny` |
| `reason` | Fixed reason such as `service_allowed`, `service_absent`, `remote_denied`, `tls_authentication`, `target_connect`, `capacity`, `setup_timeout`, `configuration_changed` or `configuration_unavailable` |
| `peer_id` / `workspace` | Projected peer row and workspace when available |
| `direction` | `import` on the initiating side or `export` on the target side |
| `service` / `port` | Requested normalized service and port when available |
| `peer` | Numeric connecting workload or gateway address and ephemeral port |
| `target` | Import listener or authorized local export endpoint; empty before authorization |

The file/stdout writer is the current sink. Workspace Zetta delivery depends on zetta#1281; until
that contract lands, the operator collects JSON lines without claiming durable Zetta delivery.

See [verification](peer/testing.md) for executable acceptance coverage.
