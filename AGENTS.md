# AGENTS.md

Read [`CLAUDE.md`](CLAUDE.md) and [`README.md`](README.md) first; they apply in full to every agent.

Non-negotiables:
- Work on a feature branch from `dev`; open the pull request against `dev`. Never push to `main` or
  `dev` directly.
- Documentation is part of every change: the relevant page under `docs/` and any status line in
  `README.md` or `CLAUDE.md` change in the same commit as the code.
- No AI attribution of any kind in commits or pull requests.
- No time or size estimates. Never write the word "seam".
- Every dependency is permissively licensed and recorded in `docs/licences.md`.
- Build: `cmake -S . -B build -G Ninja && cmake --build build -j 6 && ctest --test-dir build --output-on-failure`.
