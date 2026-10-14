# Endpoint role

`zetta-tunnel endpoint` accepts relay mTLS on port 7444 by default and opens only the one
`--target host:port` configured at startup. It requires `--cert`, `--key`, the operator's relay CA
in `--ca`, and the relay workload's exact SAN in `--peer-name`. The operator gives each endpoint
certificate the DNS SAN `endpoint.<grant-uuid>` and generates its narrow target Connection and
network policy. No client payload can select a different target.

The [developer tunnel contract](tunnel.md) lists every flag, certificate expectation and protocol
detail. There are no implicit config files, role environment variables or Lake API calls. The
separate `--health-listen` port defaults to `127.0.0.1:8080`, exposing `/healthz` and `/readyz`.
Metrics are absent. `--audit` selects stdout or an append-only JSON-lines file; the relay's audit
contains the grant/workspace identity, while endpoint records describe its transport sessions.
