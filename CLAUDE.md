# zetta-tunnel

Orama's own network layer, in C++26: tunnels, the mesh and the ingress. Read [`README.md`](README.md)
first: it says what this is, why it exists, and which parts are built. The design in
[orama-operator#437](https://github.com/oramasearch/orama-operator/issues/437) is decided; the
mutual TLS transport, developer tunnel roles, DNS-name egress gateway and peer gateway are
implemented. The issue #3 contract is in [`docs/tunnel.md`](docs/tunnel.md), issue #4 is in
[`docs/egress.md`](docs/egress.md), and issue #5 is in [`docs/peer.md`](docs/peer.md); JSON-lines
audit is built and the Zetta writer is deferred to zetta#1281.

The organisation's rules are in the umbrella bridge's `CLAUDE.md`
(https://github.com/oramasearch/orama-bridge). The ones that apply here every day:

- **Branches:** work branches from `origin/dev`, and every pull request targets `dev`
  (`gh pr create --base dev`). `main` moves only on a release. Merge with merge commits, never
  squash.
- **Private:** this repository and its Docker Hub repository `oramasearch/zetta-tunnel` are
  private. Never make either public.
- **Licences:** every dependency is permissively licensed (Apache-2.0, MIT, BSD, ISC, Boost) and
  recorded where it is added. No GPL, LGPL, AGPL, SSPL, BUSL or source-available code is linked or
  shipped.
- **No CI.** Proof is the local build and `ctest`, stated in the pull request.
- **No AI attribution** in commits, pull requests or release notes.
- **Never write the word "seam"**; name the mechanism.
- **The version** is written once, in `project(VERSION)` in `CMakeLists.txt`; `--version` and its
  test read it from there.
