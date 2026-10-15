# Releases

One page per tagged release, newest first. A page states what the release includes, what it does
not include, known issues, verification output, and where the image has run. The first release also
lists every role in the image.

The full promotion, image and digest contract is in [Image and releases](../image.md). A release has
one `vX.Y.Z` name shared by the Git tag, GitHub release and private Docker Hub image tag. The image
tag names the digest already deployed and verified; it is never produced by a second build.

| Release | Date | Summary |
|---|---|---|
| [v0.1.0](v0.1.0.md) | 2026-10-15 | The first release: every role (client, relay, endpoint, egress, peer, ingress, mesh), the mutual TLS 1.3 transport, the private image and the portable tunnel clients |

`CMakeLists.txt`'s `VERSION` is the one place the version is set; `zetta-tunnel --version` reports
it, and the test `release_notes_exist_for_project_version` fails when that version has no page here.

