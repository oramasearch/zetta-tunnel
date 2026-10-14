# Relay role

`zetta-tunnel relay` accepts developer mTLS on port 7443 by default. It requires `--cert`, `--key`,
the developer tunnel CA in `--ca`, the operator's `--grants` file, and independent workload
credentials `--endpoint-cert`, `--endpoint-key`, `--endpoint-ca` for the endpoint hop.
The verified developer URI SAN selects a grant. The grant selects exactly one endpoint, whose
server SAN must be `endpoint.<grant-uuid>`. A TCP/TLS passthrough ingress preserves this identity.

The [developer tunnel contract](tunnel.md) specifies the grant JSON, reload/expiry/revocation
behavior, audit fields and all flags. Configuration comes only from flags and mounted files;
there are no Lake API calls or role environment variables. The separate `--health-listen` port
defaults to `127.0.0.1:8080`, with `/healthz` and `/readyz`. There is no metrics route. Collect the
JSON-lines audit sink on stdout or the file selected by `--audit`.
