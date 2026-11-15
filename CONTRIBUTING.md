# Contributing to zetta-tunnel

Thank you for helping. zetta-tunnel is the network layer of Orama Lake: tunnels, the mesh and the
ingress, in C++26. [`README.md`](README.md) says what it is and which parts are built;
[`docs/`](docs/README.md) has each role's contract. This document says how to build and test it,
how a change gets in, and the one thing every commit needs: a sign-off.

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
4. Sign off every commit (next section).
5. Open the pull request against `dev`. Start its description with what changes, why, and how.

Two rules hold for every change:

- Every dependency is permissively licensed (Apache-2.0, MIT, BSD, ISC, Boost) and recorded in
  [`docs/licences.md`](docs/licences.md). No GPL, LGPL, AGPL, SSPL, BUSL or source-available code is
  linked or shipped.
- The version is written once, in `project(VERSION)` in `CMakeLists.txt`; `--version` and its test
  read it from there.

A maintainer reviews it. Pull requests are merged with a merge commit, so every commit you sign
stays in the history.

## Sign your commits (Developer Certificate of Origin)

zetta-tunnel takes contributions under the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO). There is no contributor license agreement to sign. Your contribution is licensed under the
project's license, the MIT License (see [LICENSE](LICENSE)).

By adding a `Signed-off-by` line to a commit, you certify the DCO below for that commit. Git adds
the line for you with `-s`:

```sh
git commit -s -m "fix(api): reject an empty name"
```

which records:

```
Signed-off-by: Your Name <you@example.com>
```

The name and address are the ones in your `git config user.name` and `user.email`. Use your real
name; anonymous contributions cannot be accepted. To sign commits you have already made:

```sh
git commit --amend -s --no-edit        # the last commit
git rebase --signoff dev               # every commit on your branch
```

A pull request with an unsigned commit is not merged until it is signed.

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

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
