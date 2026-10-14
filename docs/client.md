# Client role

`zetta-tunnel client --cert grant.pem --key grant.key --ca relay-ca.pem
--relay relay.example:7443 --listen 127.0.0.1:5433` exposes a grant on a loopback port.
The developer obtains the grant certificate from Lake's existing sign-in flow. The client opens
an outbound mutual TLS 1.3 connection for each local TCP connection. It requires the relay's exact
server SAN, using `--server-name` when that differs from the connection hostname.

All flags, defaults, certificate requirements and resource limits are in the
[developer tunnel contract](tunnel.md#command-line-configuration). There are no implicit config
files, role environment variables, HTTP health/readiness paths or metrics for this role. Use
`psql postgresql://USER@127.0.0.1:5433/DATABASE` with the target's database credentials; the tunnel
does not replace database authentication.
