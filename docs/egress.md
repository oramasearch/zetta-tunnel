# Egress gateway contract

`zetta-tunnel egress` is the DNS-name provider for an operator `EgressRule`. Workloads connect only
to this gateway, and the operator's Cilium policy blocks their direct path to the destination. The
gateway authorizes the numeric source IP, exact DNS name and destination port before it forwards
any application bytes.

```text
workload -> egress gateway -> gateway DNS resolution -> named TCP destination
```

The role does not accept a client-supplied resolved address. It resolves an authorized name itself
and connects one endpoint returned by that lookup. An unauthorized name is refused before DNS,
even when the workload resolved that name to the same address as an allowed name. The connected
socket remains bound to that numeric endpoint for its lifetime. IPv4 and IPv6 literals are always
refused by this role; CIDR `EgressRule`s are enforced directly by Cilium and do not use the gateway.

## Destination protocols

HTTPS clients connect to the gateway and send their ordinary TLS ClientHello. The gateway parses a
possibly fragmented ClientHello, requires exactly one valid host-name SNI value, authorizes that
name with `--sni-port`, and forwards every TLS byte unchanged. It does not terminate application
TLS. A missing, malformed, duplicate or numeric SNI is refused. Encrypted ClientHello cannot supply
the visible routing name and is therefore not supported.

Other TCP clients send this ASCII preface, followed immediately by application bytes:

```text
ZTEG1 <dns-name> <port>\n
```

The gateway consumes the preface. It is limited to 511 bytes, has exactly three space-separated
fields and permits only an exact DNS name and a decimal port from 1 through 65535. Applications can
use a small protocol adapter when they cannot write the preface themselves. TLS on a port other
than the gateway instance's `--sni-port` uses this explicit form.

## Operator-projected rules

The operator publishes a complete JSON file by atomic replacement. A rule is the Lake
`network_egress_rules` row plus the current numeric pod IPs selected by its `source_kind` and
`source_id`:

```json
{
  "rules": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "workspace": "workspace-example",
      "source_ips": ["10.224.1.17", "10.224.1.18"],
      "dns_name": "api.example.com",
      "ports": [443, 8443]
    }
  ]
}
```

Names are ASCII DNS names. Matching is case-insensitive and one final dot is normalized away;
wildcards are not supported. Source entries must be numeric IPv4 or IPv6 addresses. UUIDs use
lowercase canonical notation, workspace values use Kubernetes namespace syntax, ports cannot
repeat, and two rules cannot authorize the same source/name/port tuple. Unknown or missing fields,
duplicate JSON keys, duplicate rule IDs and malformed values reject the whole snapshot.

The file limit is 1 MiB, with at most 10,000 rules, 256 source IPs and 64 ports per rule, and eight
JSON nesting levels. The gateway checks replacement metadata every two seconds and before each
authorization. SIGHUP forces a reload on POSIX; Windows uses the periodic check. A missing,
unreadable or invalid file clears all authorization, makes readiness fail and closes live sessions.
Removing or changing a rule closes its sessions. An empty valid snapshot is ready and authorizes
nobody. The operator must update the projection when selected pod IPs change.

## Command-line configuration

There are no environment variables or implicit configuration files. Unknown, duplicate,
missing-value and other-role flags fail startup. Listener values must be numeric IP addresses with
explicit nonzero ports.

| Flag | Meaning/default |
|---|---|
| `--rules FILE` | Required operator-projected rule snapshot |
| `--listen IP:PORT` | Workload listener; `0.0.0.0:7445` |
| `--health-listen IP:PORT` | Private plain-HTTP probe listener; `127.0.0.1:8080` |
| `--sni-port PORT` | Destination port inferred for TLS SNI traffic; `443` |
| `--max-sessions N` | `128`; range 1–4096, including connections still identifying or resolving |
| `--audit FILE` | Append JSON lines to a file; `-` writes stdout and is the default |

The gateway expects no certificates or private keys. Application TLS stays end-to-end between the
workload and destination. Its probe listener is unauthenticated plain HTTP and must remain private.
Cilium must restrict the workload listener to the source pods represented in the projected rules;
the source-IP check is the second enforcement layer.

## Health, readiness and resources

`GET /healthz` returns 200 while the event loop responds. `GET /readyz` returns 200 only while the
rule snapshot and audit sink are usable. Other paths return 404. There are at most 16 probe
connections, a five-second probe deadline and a 4 KiB request-header limit.

Each direction uses one 16 KiB copy buffer. Destination identification buffers at most 70 KiB,
including a TLS ClientHello limited to 65,535 bytes. Identification, DNS and connect share a
ten-second setup deadline. Session capacity is fixed by `--max-sessions`; overflow is refused.
SIGINT and SIGTERM close listeners and sessions. Metrics are not implemented; decision records are
the current observability interface.

## Decision records

Authorization is fail closed around `AuditSink`: an allow record is flushed after DNS/connect and
before any workload bytes are sent upstream. A sink failure disables readiness, closes sessions and
refuses new traffic. Payloads, DNS response contents beyond the selected numeric endpoint, and
process credentials are never logged.

| Field | Meaning |
|---|---|
| `schema` | Integer `1` |
| `event` / `role` | `egress_decision` / `egress` |
| `timestamp` / `started_at` | UTC RFC3339 record and TCP-accept times |
| `decision` | `allow` or `deny` |
| `reason` | Fixed internal reason such as `rule_allowed`, `rule_absent`, `ip_literal`, `sni_required`, `invalid_request`, `dns_resolution`, `upstream_connect`, `capacity`, `setup_timeout` or `rules_unavailable` |
| `rule_id` / `workspace` | Authorizing projected rule, empty when no rule matched |
| `source` | Numeric workload address and ephemeral port |
| `dns_name` / `port` | Requested normalized name and destination port when parsing succeeded |
| `protocol` | `https_sni` or `explicit` |
| `resolved_address` | Numeric connected endpoint on an allow decision |

`JsonLinesSink` supplies the file/stdout writer. The workspace Zetta writer remains behind the same
interface and depends on the record-ingestion contract tracked by zetta#1281; until that lands, the
operator must collect JSON lines without claiming they were durably written into Zetta.

See [verification](egress/testing.md) for executable coverage.
