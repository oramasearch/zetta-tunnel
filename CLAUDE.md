# zetta-tunnel

Orama's own network layer, in C++26: tunnels, the mesh and the ingress. Read [`README.md`](README.md)
first: it says what this is, why it exists, and which parts are built. The contracts are documented
per component: the tunnel in [`docs/tunnel.md`](docs/tunnel.md), egress in
[`docs/egress.md`](docs/egress.md), peers in [`docs/peer.md`](docs/peer.md), ingress in
[`docs/ingress.md`](docs/ingress.md), the mesh node agent in [`docs/mesh.md`](docs/mesh.md) and the
image in [`docs/image.md`](docs/image.md). The architecture is [`docs/architecture.md`](docs/architecture.md).

## Build and test

```sh
cmake -S . -B build -G Ninja
cmake --build build -j 6
ctest --test-dir build --output-on-failure
```

State in the pull request which tests you ran and their result.

## Rules

- **Branches:** branch from `dev`, and open every pull request against `dev`. `main` holds the last
  release and moves only when a release is cut. Pull requests are merged with merge commits, never
  squashed.
- **Documentation is part of every change:** the relevant page under `docs/`, and any status line in
  `README.md` or this file, change in the same commit as the code.
- **Licences:** every dependency is permissively licensed (Apache-2.0, MIT, BSD, ISC, Boost) and
  recorded in [`docs/licences.md`](docs/licences.md) when it is added. No GPL, LGPL, AGPL, SSPL, BUSL
  or source-available code is linked or shipped.
- **No AI attribution** in commits, pull requests or release notes: no `Co-Authored-By` trailers
  for an assistant, no "Generated with" lines.
- **Never write the word "seam"**; name the mechanism (interface, extension point, injected
  dependency, boundary).
- **No time or size estimates**; report what was done.
- **The version** is written once, in `project(VERSION)` in `CMakeLists.txt`; `--version` and its
  test read it from there.
- A segfault, bus error or abort in a test is a memory bug, not a flake: rebuild with
  AddressSanitizer (`-fsanitize=address -fno-omit-frame-pointer`) in its own build directory and run
  the suite under it.
- Report vulnerabilities privately, as [`SECURITY.md`](SECURITY.md) describes.
