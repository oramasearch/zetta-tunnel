# Contributing to zetta-tunnel

Thank you for helping. zetta-tunnel is the network layer of Orama Lake: tunnels, the mesh and the
ingress, in C++26. [`README.md`](README.md) says what it is and which parts are built;
[`docs/`](docs/README.md) has each role's contract.

## Build and test

```sh
cmake -S . -B build -G Ninja
cmake --build build -j 6
ctest --test-dir build --output-on-failure
```

Prerequisites are in [`docs/tunnel/testing.md`](docs/tunnel/testing.md). Say in your pull request
which tests you ran and on which platform.

## Pull requests

- Branch from `dev` and open the pull request against `dev`. `main` holds the last release.
- Documentation is part of the change: update the role's page under `docs/` and any status line in
  `README.md` in the same pull request as the code.
- Every dependency is permissively licensed (Apache-2.0, MIT, BSD, ISC, Boost) and recorded in
  [`docs/licences.md`](docs/licences.md). No GPL, LGPL, AGPL, SSPL, BUSL or source-available code is
  linked or shipped.
- The version is written once, in `project(VERSION)` in `CMakeLists.txt`; `--version` and its test
  read it from there.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit subjects.

## Security

Report a vulnerability privately, as [`SECURITY.md`](SECURITY.md) describes, never in a public issue.
