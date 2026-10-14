# Transport

The `zetta_tunnel_transport` library is the common encrypted byte transport for zetta-tunnel. It
implements secure-networking decision D5: TLS 1.3 over Corosio's OpenSSL provider. Its public C++26
interface is `include/zetta_tunnel/transport.hpp`; no Corosio or OpenSSL type crosses that boundary.
This keeps replacement by Zetta's shared transport library local to the implementation.

## Trust and identity

`TlsContext` loads one endpoint certificate, its private key and one CA bundle from PEM files. A
`Client` also requires the expected server identity. A `Server` requires the expected client
identity. Both identities are matched against the peer certificate's DNS subject alternative names
during the TLS handshake.

Every connection has all of these properties:

- TLS 1.3 is both the minimum and maximum protocol version.
- The peer must present a certificate. Optional peer certificates are not supported.
- The chain must verify against the configured CA bundle.
- Certificate validity dates are checked by OpenSSL.
- The expected DNS identity must match a certificate SAN.
- No application frame is read or written before the handshake succeeds.

Credential loading and handshake errors throw `zetta_tunnel::transport::Error`. Error messages name
the failed operation but never contain key or certificate contents. A failure closes the TCP socket;
there is no plaintext fallback.

## Interface

```cpp
#include <zetta_tunnel/transport.hpp>

namespace transport = zetta_tunnel::transport;

transport::TlsContext credentials({
    .certificate = "client-cert.pem",
    .private_key = "client-key.pem",
    .certificate_authority = "orama-ca.pem",
});

transport::Client client(credentials, "gateway.orama.internal");
auto connection = client.connect("127.0.0.1", 7443);
```

`Server::listen()` binds an IPv4 address and accepts one mutually authenticated connection per
`accept()` call. `Client::connect()` accepts an IPv4 address, IPv6 address or DNS name and resolves it
through Corosio. Operations on a connection are serialized; callers do not issue simultaneous reads,
writes or shutdowns on the same object.

`Connection::shutdown()` initiates the TLS `close_notify` exchange and then closes TCP. Both
endpoints should enter shutdown after their last frame. Corosio's terminal truncated-stream result is
accepted only after local TLS shutdown has been initiated, to cover a peer that has already finished
closing; other shutdown errors are reported. Destroying a connection closes its socket if graceful
shutdown was not completed.

## Frame format

The encrypted stream carries a sequence of frames:

| Field | Size | Encoding |
|---|---:|---|
| payload length | 4 bytes | unsigned big-endian integer |
| payload | declared length | uninterpreted bytes |

Frames may be empty and may contain any byte value. The maximum payload is 16 MiB. A larger outgoing
frame is rejected locally; a larger peer declaration closes the connection before allocating the
payload.

## Verification

`transport_test` creates throwaway Ed25519 CAs and identities with OpenSSL APIs. CTest covers a
binary round trip and clean shutdown. It separately proves that the server refuses these peers
before application data:

- a TLS client with no certificate;
- a certificate signed by another CA;
- an expired certificate;
- a trusted certificate with the wrong pinned identity.

The same source and tests build as a static library by default and as a shared library with
`-DBUILD_SHARED_LIBS=ON`.
