# Mesh node agent contract

`zetta-tunnel mesh` is the platform-owned node agent for enrolled workloads. It enters each
workload's Linux network namespace, installs kernel capture rules, and owns two fixed listeners in
that namespace:

```text
workload TCP -> 127.0.0.1:15001 -> TLS 1.3 -> destination pod:15008 -> local application
```

The application still connects to its ordinary destination address and port. It does not know
about the agent and needs no capability or injected proxy. The agent uses the socket's original
destination to select one exact projected route. Traffic between the two agents uses mutual TLS;
the destination agent authenticates the source workload certificate and authorizes its identity
for the requested application port. Cilium remains the cluster policy enforcer and permits the
agent-to-agent port only for declared `Connection`s.

The role is Linux-only. Configuration parsing, flags, netlink wire tests and the non-capture roles
continue to build on macOS and Windows. The Linux implementation talks directly to the kernel
nftables netlink API; it does not invoke or ship an nftables or iptables executable.

## Enrolment and fail-closed order

The operator must use this order for every pod selected by a `NetworkSandbox`:

1. Apply the Cilium/default-deny policy. A declared workload connection permits only TCP port
   15008 between enrolled pod addresses, not the application port.
2. Create the pod sandbox while the platform startup gate keeps application containers stopped.
3. Atomically replace the node's mesh projection with the sandbox network-namespace path, pod UID
   and verified namespace inode.
4. Wait for mesh readiness. The agent atomically creates the namespace's nftables table and rules,
   then binds its capture listeners.
5. Release the application startup gate.

Before step 4, Cilium refuses application-port traffic. Between capture installation and listener
startup, redirected connects find no listener and fail. Once ready, all workload TCP output except
agent-marked traffic is redirected to port 15001. All incoming TCP except the mutual-TLS port is
redirected to port 15008, where plaintext and untrusted certificates are rejected. Workloads run
under restricted Pod Security and cannot set the reserved socket mark or change namespace rules.

The capture table deliberately remains installed for the life of the network namespace. If the
agent crashes, is killed, loses its projection, cannot reload certificates, or cannot write its
audit sink, listeners and sessions close while the rules remain; new traffic is refused. On agent
restart, the agent finds the existing table and binds the same listeners. A restarted pod has a new
network namespace, so the operator replaces its projection and repeats the startup gate. To
unenrol a live pod, the operator first withdraws its connection policies and then replaces the pod;
the agent never removes capture from a running namespace.

The node agent needs `CAP_SYS_ADMIN` to enter network namespaces, `CAP_NET_ADMIN` there to install
capture, and permission to open marked sockets. These privileges belong only to the agent in the
platform system namespace. Workload containers retain the restricted profile with no added
capabilities. The agent needs a read-only host proc mount exposing process directories, cgroup
metadata and network-namespace handles, and a read-only certificate projection.

## Operator projection

The operator publishes one complete JSON file by atomic replacement. A workload entry is present
only while its pod sandbox is enrolled on this node.

```json
{
  "mesh": {
    "node": "aks-node-000001",
    "workloads": [
      {
        "identity": "api.workspace-example.test",
        "network_namespace": "/host/proc/1842/ns/net",
        "pod_uid": "11111111-2222-3333-4444-555555555555",
        "network_namespace_inode": 4026533001,
        "tls": {
          "certificate": "certificates/api.pem",
          "key": "certificates/api.key",
          "ca": "certificates/workload-ca.pem"
        },
        "routes": [
          {
            "destination": "10.224.4.19:8080",
            "mesh": "10.224.4.19:15008",
            "identity": "worker.workspace-example.test"
          }
        ],
        "ports": [
          {
            "port": 8080,
            "target": "127.0.0.1:8080",
            "sources": ["frontend.workspace-example.test"]
          }
        ]
      }
    ]
  }
}
```

The document and every nested object accept exactly the shown fields. Node and workload identities
are lowercase DNS-style names. `network_namespace` and TLS paths may be absolute or relative to the
projection. The namespace path must end in `<positive-pid>/ns/net`; named namespace paths alone
are no longer accepted. `pod_uid` is the lowercase UUID from the Kubernetes API.
`network_namespace_inode` is a positive unsigned 64-bit integer. The node projector obtains it with
`fstat` on the namespace descriptor opened relative to the process directory whose cgroup it
checked; it rechecks membership around that open and omits processes that disappeared or changed.

Before installing a runtime, the agent opens the process directory once and opens `cgroup` and
`ns/net` relative to that descriptor. It checks exact pod membership before and after opening the
namespace, compares its inode with the projection and requires a Linux network namespace handle.
Membership accepts an exact `pod<uid>` cgroupfs component or the corresponding guaranteed,
burstable or besteffort systemd pod slice, including the driver's underscore spelling of the UID.
A UID prefix or a different pod component fails validation.

Capture installation, both listeners and both session directions use that pinned descriptor.
Sessions retain ownership through runtime withdrawal, so process death, PID reuse or path
replacement cannot redirect an installed workload identity to another namespace. Reload and
restart repeat identity validation; any mismatch closes traffic and leaves readiness false.

This contract must release together with the operator projector update. Projections without
`pod_uid` or `network_namespace_inode` fail closed, including projections from older operators.

Linux capture currently accepts IPv4 addresses with explicit ports. Destination and
mesh addresses must be numeric to prevent DNS changes from widening a route. A target preserves
its declared port. Duplicate identities, namespaces, destinations, target ports and source
identities are invalid.

The file limit is 1 MiB, with at most 128 workloads, 256 routes per workload, 256 inbound ports per
workload, 256 source identities per port and ten JSON nesting levels. An empty workload array is a
valid ready node with no enrolled pods. The agent checks replacement metadata four times per second;
SIGHUP forces a reload. **A reload is per workload** (LSR-178, zetta-tunnel#30): a workload whose
projection did not change keeps its listeners and sessions; a removed or changed workload's
listeners and sessions are closed, alone; and a workload that cannot be set up (a capture port
already taken inside its namespace, a certificate that does not load) is refused on its own, with a
diagnostic, while every other workload keeps serving. A missing, unreadable or invalid projection
fails readiness, closes every workload and leaves capture rules in place.

## Mesh protocol and certificates

The outbound agent connects to the projected numeric mesh address on port 15008 using TLS 1.3. It
requires the exact projected destination identity in the certificate's DNS subject alternative
name, a chain rooted in the workload CA, and a valid certificate lifetime. The destination requires
a client certificate from the same projected CA and exactly one lowercase DNS identity. It then
authorizes that identity against `ports[].sources`.

After TLS authentication the source sends a bounded ASCII request:

```text
ZTM1 <destination-identity> <application-port>\n
```

The destination checks its own identity, the source identity and the exact port, connects only the
projected loopback target, flushes its allow record, and replies `ZTMA1\n`. The source flushes its
own allow record only after that acknowledgement. Application bytes are forwarded only after both
records succeed. A preface is limited to 511 bytes. Certificate contents, keys and application
payloads are never logged.

Each workload needs a certificate and private key usable for TLS client and server authentication,
with its exact DNS identity, plus the CA file used to verify other workload certificates. Private
keys are read only by the node agent. Certificate or CA loading failure keeps the node unready and
does not disable capture.

## Command line, ports and probes

There are no environment variables or implicit configuration files. Unknown, duplicate,
missing-value and other-role flags fail startup.

| Flag | Meaning/default |
|---|---|
| `--configuration FILE` | Required operator projection |
| `--health-listen IP:PORT` | Host-network plain HTTP probes and metrics; `127.0.0.1:8080` |
| `--audit FILE` | Append JSON lines; `-` writes stdout and is the default |
| `--max-sessions N` | Combined inbound/outbound limit for the node; `128`, range 1–4096 |
| `--max-sessions-per-workload N` | One workload's share of `--max-sessions`; `0` selects max(1, max-sessions/4), otherwise at most `--max-sessions` (LSR-177) |
| `--setup-timeout N` | Connect, TLS and preface deadline in seconds; `10`, range 1–60 |
| `--idle-timeout N` | An established session with no traffic either way for N seconds is closed; `300`, range 1–86400 (LSR-177) |

Inside every enrolled pod namespace, TCP 15001 is the loopback-only outbound capture port and TCP
15008 is the mutual-TLS inbound port. Neither is configurable, so operator policy and probes have a
stable contract. Port 15001 must never be exposed outside the namespace. Port 15008 is reachable
only from source pods named by declared connections.

`GET /healthz` returns 200 while the host listener responds. `GET /readyz` returns 200 while the
projection is loaded and the audit sink is usable. A workload that could not be set up does not
make the node unready, so one workload cannot take the others down; it is counted in
`zetta_mesh_workload_failures_total` and named on stderr.
`GET /metrics` returns Prometheus text. Other paths return 404. The host-network probe listener must
remain private to the platform.

Metrics are `zetta_mesh_sessions`, `zetta_mesh_allows_total`, `zetta_mesh_denials_total`,
`zetta_mesh_capacity_denials_total`, `zetta_mesh_reloads_total`,
`zetta_mesh_reload_failures_total` and `zetta_mesh_workload_failures_total`. Session capacity is
shared by the node and capped per workload, so one workload's sessions never take every slot
(zetta-tunnel#29); an idle session is closed after `--idle-timeout`. Each session uses one 16 KiB copy
buffer and one detached worker; overflow closes the accepted socket while probes remain responsive.
SIGINT and SIGTERM close listeners and sessions but do not remove namespace capture.

## Decision records

The JSON-lines event is `mesh_decision`, role `mesh`, schema `1`. Each record includes `timestamp`,
`node`, local `workload`, authenticated `peer`, original `destination`, application `port`,
`direction`, `decision` and a fixed `reason`. Reasons include `identity_allowed`,
`destination_absent`, `source_absent`, `invalid_preface`, `remote_denied` and `session_failure`.
Allow records precede application forwarding. Audit failure removes readiness and closes traffic.

Workspace Zetta delivery remains dependent on zetta#1281. Until that contract lands, the operator
collects JSON lines without claiming durable delivery.

See [verification](mesh/testing.md) for portable and privileged Linux proofs.

## Startup and reload diagnostics

A refused projection emits one bounded stderr line with its stage and a zero-based workload index
where applicable. Stages distinguish projection reading/validation, workload TLS validation,
namespace identity validation, namespace capture, each listener address, listener threads and
projection metadata. Namespace and socket failures include the operation, numeric errno and its message. Kernel capture failures name
the table, chain or rule operation and include the netlink error, sequence/type and any extended
kernel error text or attribute offset. TLS loading reports the failed setting and OpenSSL/errno
codes without certificate, key, file contents or OpenSSL error-data strings.

Malformed JSON reports only its error ID and byte position, never the input snippet. Filesystem
errors omit configured paths. Control characters are replaced and diagnostic detail is bounded.
On a projection that cannot be read, readiness remains 503, every listener and session closes, and
installed capture stays in place. A single workload's failure closes only that workload. Startup failures before the probe listener opens exit with status 2 and a diagnostic.
See [netlink and diagnostics](mesh/netlink.md) for examples, wire contracts and troubleshooting.
