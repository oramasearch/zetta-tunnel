# Releases

One page per tagged release, newest first. A page states what the release includes, what it does
not include, known issues, verification output, and where the image has run. The first release also
lists every role in the image.

The full promotion, image and digest contract is in [Image and releases](../image.md). A release has
one `vX.Y.Z` name shared by the Git tag, GitHub release and Docker Hub image tag. The image
tag names the digest already deployed and verified; it is never produced by a second build.

| Release | Date | Summary |
|---|---|---|
| [v0.3.0](v0.3.0.md) | 2026-11-15 | Two security fixes (a rotated or withdrawn credential ends its sessions; an ingress host can require the edge's client certificate, and edge headers pass only from it), the MIT licence, the CLA and an SBOM. A v0.2.0 configuration runs unchanged |
| [v0.2.0](v0.2.0.md) | 2026-11-02 | Four security fixes (grants bound to their customer CA, separate pending admission, resolved egress addresses checked, pinned mesh namespaces) and the peer setup deadline that blocked the hub's distant clusters. The grants file and mesh projection change: the operator must follow (orama-operator#844, #869) |
| [v0.1.0](v0.1.0.md) | 2026-10-15 | The first release: every role (client, relay, endpoint, egress, peer, ingress, mesh), the mutual TLS 1.3 transport, the image and the portable tunnel clients |

`CMakeLists.txt`'s `VERSION` is the one place the version is set; `zetta-tunnel --version` reports
it, and the test `release_notes_exist_for_project_version` fails when that version has no page here.

