# Ingress gateway contract

`zetta-tunnel ingress` implements decision D8's data plane: public TLS termination and
HTTP host/path routing to operator-selected Services. The operator owns deployment, Service
resolution, certificate mounts, network policies and cluster cutover (orama-operator#473).
The gateway does not watch Kubernetes or write Lake's control plane. Migration `0084_network`
does not define an ingress table; existing operator Ingress desired state supplies these routes.

## Deployment and flags

```sh
zetta-tunnel ingress --configuration /etc/zetta-ingress/routes.json \
  --listen 0.0.0.0:8443 --health-listen 0.0.0.0:8080 --audit -
```

Run as a non-root user, with read-only configuration/certificate mounts and restricted Pod
Security. A LoadBalancer Service maps public TCP 443 to pod TCP 8443. No `NET_ADMIN`, host
networking, privileged ports, external service, database or internet access is required.
Use network policy to admit only declared backend Services and DNS. Keep probes private.

| Flag | Default | Meaning |
|---|---|---|
| `--configuration FILE` | required | Projected routes; relative file paths resolve beside this file |
| `--listen IP:PORT` | `0.0.0.0:8443` | Public TLS; numeric IPv4 or bracketed IPv6 |
| `--health-listen IP:PORT` | `127.0.0.1:8080` | Private plain HTTP probes and metrics |
| `--audit FILE\|-` | `-` | Append JSON lines to a file, or stdout |
| `--max-sessions N` | `128` | Public TCP connections including pending TLS; range 1–4096 |
| `--max-requests N` | `256` | Backend requests across all connections; range 1–4096 |
| `--idle-timeout-seconds N` | `60` | No-progress connection/request deadline; range 1–86400 |
| `--setup-timeout-seconds N` | `10` | TLS, backend setup and HTTP/1 header deadline; range 1–300 |

There are no environment-variable overrides. Unknown, duplicate, empty or incomplete flags
fail startup. `ingress --help` lists all flags. `SIGINT`/`SIGTERM` close listeners and traffic;
`SIGHUP` forces revalidation and closes existing public connections.

## Operator projection

```json
{
  "hosts": [
    {
      "name": "lake.example.com",
      "certificate": "certificates/lake/tls.crt",
      "key": "certificates/lake/tls.key",
      "routes": [
        {
          "id": "lake-api",
          "path": "/api",
          "path_type": "Prefix",
          "target": "http://lake.lake-system.svc.cluster.local:3000",
          "max_body_bytes": 10485760
        },
        {
          "id": "lake-root",
          "path": "/",
          "path_type": "Prefix",
          "target": "http://lake.lake-system.svc.cluster.local:3000",
          "max_body_bytes": 1048576
        }
      ]
    }
  ]
}
```

All shown fields are required. The only optional route fields are `ca` and `server_name`,
both required for `https://` targets and forbidden for `http://` targets. HTTPS example:

```json
{
  "id": "zetta-api",
  "path": "/",
  "path_type": "Prefix",
  "target": "https://zetta.workspace.svc.cluster.local:443",
  "ca": "certificates/backend-ca.pem",
  "server_name": "zetta.workspace.svc.cluster.local",
  "max_body_bytes": 0
}
```

Targets require an explicit port and contain no URL path, credentials, query or fragment.
They can use Service DNS names or operator-selected numeric addresses. Clients cannot choose
upstream addresses. Route IDs are globally unique lower-case letters, digits and hyphens,
at most 63 characters. Hosts are exact lower-case DNS names, without wildcard routes or IP literals.
A document has 1–256 hosts, each with 1–256 routes. JSON and each PEM input are limited to 1 MiB.
Duplicate keys, unknown fields, duplicate hosts/routes/IDs and excessive nesting fail closed.

`max_body_bytes` applies to Content-Length and streamed chunked/HTTP/2 bodies. `0` explicitly
allows an unlimited total body while memory remains bounded. A known excessive length receives
413 before connecting to a Service. A streamed body crossing the limit stops at that point;
the Service may already have received its allowed prefix. Applications must not commit partial
uploads as complete transactions.

## Certificates and reload

Mount cert-manager Secret `tls.crt` (leaf followed by intermediates) and `tls.key`. The key must
match the leaf; the leaf must be currently valid for server authentication and its DNS SAN must
cover the configured host. A wildcard SAN may cover exact configured hosts. Public TLS uses
TLS 1.3, selects a certificate by SNI, and negotiates `h2` or `http/1.1` through ALPN; absent ALPN
uses HTTP/1.1. Missing/unknown SNI and unsupported ALPN fail the handshake. There is no fallback
certificate or verification bypass. Clients verify the cert-manager chain and hostname; they
do not need a client certificate. Tunnel/peer mutual TLS is unchanged.

HTTPS backends verify the configured CA chain, certificate validity, server purpose and
`server_name` SAN. There is no insecure option. HTTP backends are an explicit plaintext hop
protected by operator network policy, matching conventional TLS-terminating ingress.

Configuration and all certificate files are revalidated every two seconds. Content hashes detect
route, key, chain and backend-CA changes, including Kubernetes `..data` symlink rotation and
same-size/same-mtime replacements. A changed projection closes existing connections before
serving the replacement. Invalid, missing, expired or mismatched files clear readiness and close
traffic; the previous configuration is not kept active. Valid files recover readiness. Mount a
complete generation atomically to avoid a transient fail-closed interval.

## HTTP behavior

- Host/HTTP/2 authority must match TLS SNI after DNS normalization, otherwise 421.
  HTTP/2 connection coalescing cannot cross configured hosts.
- `Exact` matches the entire path; `Prefix` matches segments. Longest matching path wins,
  with Exact winning ties. `/api` does not match `/apiculture`. No match returns 404.
- Queries do not affect route selection and are forwarded unchanged. There is no rewrite.
  Percent-encoded printable path characters are decoded for matching. Dot segments, repeated
  slashes, encoded separators/control bytes and double encoding are rejected with 400.
- HTTP/1.1 keep-alive supports up to 1,000 requests per connection. Each request uses a separate
  HTTP/1.1 backend connection; there is no backend pooling. HTTP/2 supports 32 concurrent streams
  per connection, with nghttp2 HPACK, SETTINGS, stream resets and flow control.
- Request and response buffering is off. Uploads, chunked responses and server-sent events pass
  incrementally. HTTP/2 credit is returned as uploads are consumed; downstream pressure pauses
  upstream reads. Bodies are never spooled to disk. Chunk framing is regenerated as needed;
  trailers are consumed and discarded.
- HTTP/1.1 WebSocket Upgrade is supported, followed by bidirectional byte forwarding. Extended
  HTTP/2 CONNECT is not advertised or accepted; WebSocket clients use HTTP/1.1 Upgrade.
- `Expect: 100-continue`, HEAD, fixed-length and close-delimited responses are supported. Early
  backend responses stop uploads. HTTP/1 closes that connection; HTTP/2 terminates the upload
  stream without terminating other streams.
- Hop-by-hop fields and Connection-nominated fields are removed. Forwarded, X-Forwarded-* and
  X-Real-IP are replaced by the gateway's observed source, host and HTTPS scheme. Application
  Authorization, Cookie and Set-Cookie fields are forwarded. Backends must trust forwarding
  headers only from the gateway's network identity.
- Duplicate Host/length/transfer-coding fields, conflicting framing, folded/invalid headers,
  unsupported transfer coding and forward-proxy targets are rejected. CONNECT and TRACE are
  disabled. Headers are bounded to 32 KiB/100 fields, request targets to 8 KiB.

The role consumes explicit projection, not arbitrary nginx annotations or snippets. The operator
must preserve application authentication/authorization before cutover; this role does not
implement nginx external-auth subrequests. Local fixtures exercise all five host categories
with distinct verified certificates. Actual deployment and ingress-nginx comparison remain the
coordinator's cluster verification.

## Health, metrics and audit

Private endpoints: `GET /healthz` returns 200 while the loop is alive; `GET /readyz` returns 200
only with valid projection and writable audit, otherwise 503; `GET /metrics` exposes Prometheus
text. Other paths return 404. Probe connections have a separate cap of 16 and a five-second
deadline, independent of public connection capacity.

All metrics use the `zetta_ingress_` prefix:

| Suffix | Type | Meaning |
|---|---|---|
| `ready`, `connections_active`, `requests_active` | gauge | Readiness and resource use |
| `connections_total`, `requests_total` | counter | Accepted TCP connections and parsed requests entering routing |
| `request_errors_total`, `connection_errors_total` | counter | Failed requests and connection/protocol errors |
| `capacity_rejections_total`, `timeouts_total` | counter | Refused connections and expired deadlines |
| `request_body_bytes_total`, `response_body_bytes_total` | counter | Forwarded body/WebSocket bytes, excluding framing |
| `reloads_total`, `reload_failures_total` | counter | Applied projections and validation failures |
| `responses_total{class="1xx"..."5xx"}` | counter | Responses by status class |

Metrics have no client/path/host labels. They are aggregate process counters, not nginx's
per-Ingress byte series used by existing app billing; that operator integration needs a
coordinated cutover. No authorization header, cookie, query, body, private key or credential is
logged. Before connecting to an authorized route, audit writes `schema`, `event=ingress_request`,
`role`, `timestamp`, `request_id`, configured `host`/`route`, observed `source`, and `decision=allow`.
Rejections are counted without reflecting attacker input into logs. Audit failure clears
readiness and closes traffic. Use continuously drained stdout or a local writable file;
workspace Zetta delivery remains zetta#1281.
After audit-sink failure, repair the sink and restart the process to restore readiness.

One Corosio event loop owns protocol state. Public connections/backend requests have explicit
caps; HTTP/2 uses 65,535-byte receive windows, a 16 KiB pending response chunk per stream, and
bounded control acknowledgements/header continuations. Copies yield to the loop. Expired,
reset or disconnected streams cancel work and release sockets/window credit.

See [verification](ingress/testing.md) and [local benchmark](ingress/benchmark.md).
