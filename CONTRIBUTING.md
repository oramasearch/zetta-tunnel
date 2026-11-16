# Contributing to zetta-tunnel

Thank you for helping. zetta-tunnel is the network layer of Orama Lake: tunnels, the mesh and the
ingress, in C++26. [`README.md`](README.md) says what it is and which parts are built;
[`docs/`](docs/README.md) has each role's contract. This document says how to build and test it,
how a change gets in, and the one thing every contributor does first: sign the Contributor License
Agreement.

## Before you start

- For a bug, open an issue with what you did, what you expected and what happened, and the
  version or commit.
- For a larger change (a new feature, a new dependency, a change to an interface), open an issue
  first so the approach can be agreed before you write it.
- **Security issues are never reported in a public issue.** See [SECURITY.md](SECURITY.md): write
  to **security@orama.com**.

## Build and test

You need a C++26 compiler (Clang 17 or newer), CMake 3.28 or newer, Ninja, OpenSSL 3,
nlohmann/json 3.12, pkg-config, libnghttp2 1.61 or newer, and Python 3 for the tests. See
[build prerequisites and verification](docs/tunnel/testing.md).

```sh
git submodule update --init --recursive
cmake -S . -B build -G Ninja
cmake --build build -j 6
ctest --test-dir build --output-on-failure
./build/zetta-tunnel --version
```

Build out of the source tree, as above; CMake refuses an in-tree build. Say in your pull request
which tests you ran and on which platform.

## Making a change

1. Fork the repository and branch from `dev`. `main` is the last release; it moves only when a
   release is cut.
2. Keep one change per pull request, with the tests that prove it. A change in behavior updates
   the role's page under `docs/` and any status line in `README.md` in the same pull request.
3. Write commit messages in the [Conventional Commits](https://www.conventionalcommits.org/) form,
   for example `fix(api): reject an empty name`.
4. Sign the Contributor License Agreement before your first pull request is merged (next section).
5. Open the pull request against `dev`. Start its description with what changes, why, and how.

Two rules hold for every change:

- Every dependency is permissively licensed (Apache-2.0, MIT, BSD, ISC, Boost) and recorded in
  [`docs/licences.md`](docs/licences.md). No GPL, LGPL, AGPL, SSPL, BUSL or source-available code is
  linked or shipped.
- The version is written once, in `project(VERSION)` in `CMakeLists.txt`; `--version` and its test
  read it from there.

A maintainer reviews it. Pull requests are merged with a merge commit, so every commit you make
stays in the history.

## Contributor License Agreement

zetta-tunnel is owned by OramaSearch, Inc. Every contributor signs the
[Contributor License Agreement](CLA.md) (CLA) once, before their first pull request is merged. Under
it you assign the copyright in your contributions to OramaSearch, Inc., you keep a licence to use
your own contributions for any purpose, and you grant a patent licence for them. The project is
published under the MIT License (see [LICENSE](LICENSE)).

When you open your first pull request, a bot comments on it with a link to the agreement. Sign
there with your GitHub account; it covers all your later contributions to projects of OramaSearch,
Inc. If you contribute as part of your job, your employer signs too: write to
**opensource@orama.com** for the entity agreement.

## License headers

Every source file starts with the line `SPDX-License-Identifier: MIT`, in that file's comment
syntax, for example `// SPDX-License-Identifier: MIT`. Add it to a new file yourself, or run:

```sh
python3 tools/spdx-headers.py           # adds the line where it is missing
python3 tools/spdx-headers.py --check   # lists files without it
```

Code copied from another project keeps its own license header and is listed in
[THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES). Say so in the pull request, with where it came from
and its license; it must be compatible with the MIT License.

## Code of conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md). Report unacceptable
behavior to **conduct@orama.com**.
