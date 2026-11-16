#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Add an `SPDX-License-Identifier: MIT` header to every source file Orama wrote.

Run from anywhere inside the repository:

    python3 tools/spdx-headers.py           # add the header where it is missing
    python3 tools/spdx-headers.py --check   # list files without it; exit 1 if any

The script is idempotent: a file that already carries an SPDX identifier is left
alone, so it can be re-run at any time, for example after other branches merge.
If a merge conflicts on these one-line headers, take the other side's version of
the file and run the script again.

Orama's own early header ("Copyright 2026 OramaSearch. Licensed under the Apache
License, Version 2.0.", written before the project chose MIT) is replaced by the
identifier; the copyright holder is named once, in COPYRIGHT and LICENSE.

What it touches: tracked files whose extension or name is a known source or build
script type (C, C++, CUDA, Go, Rust, TypeScript, JavaScript, Python, shell, CMake,
CSS, Dockerfiles, Makefiles). What it leaves alone:

- submodules and symbolic links;
- paths under a directory named `third_party`, `vendor`, `external`,
  `node_modules`, `testdata` or `fixtures`, and paths matched by the optional
  `tools/spdx-headers.ignore` file (one fnmatch pattern per line, `#` comments);
- files whose first lines carry someone else's copyright or license notice: they
  are listed as "foreign" for a person to review, never edited;
- binary files, files that are not UTF-8, data and configuration formats
  (JSON, YAML, TOML, Markdown, SQL, HTML, SVG).
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys

IDENTIFIER = "SPDX-License-Identifier: MIT"
HEAD_LINES = 40

SLASH = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h++",
    ".ipp", ".tpp", ".inl", ".cu", ".cuh", ".m", ".mm", ".go", ".rs", ".ts",
    ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".java", ".kt",
    ".swift", ".proto", ".scss", ".zig",
}
HASH = {
    ".py", ".pyi", ".sh", ".bash", ".zsh", ".cmake", ".rb", ".pl", ".ps1",
    ".tf", ".bazel", ".bzl", ".star", ".mk",
}
HASH_NAMES = {"CMakeLists.txt", "Dockerfile", "Makefile", "GNUmakefile", "BUILD", "WORKSPACE"}
BLOCK = {".css"}

SKIP_DIRS = {"third_party", "vendor", "external", "node_modules", "testdata", "fixtures"}

FOREIGN = re.compile(r"copyright|licen[cs]ed under|\blicense:|all rights reserved", re.IGNORECASE)
OURS = re.compile(r"orama", re.IGNORECASE)
DOCKER_DIRECTIVE = re.compile(r"^#\s*(syntax|escape|check)\s*=", re.IGNORECASE)
PY_CODING = re.compile(r"^#.*coding[:=]")
COMMENT_STARTS = ("//", "#", "/*", "*", '"""', "'''")
# The header Orama's earliest Go and Rust files were scaffolded with, before the
# project chose MIT. It is Orama's own notice, so it is replaced, not kept.
OLD_ORAMA_HEADER = re.compile(
    r"\A(?:/\*\s*\n\s*Copyright \d{4} OramaSearch\.\s*\n\s*Licensed under the Apache License, "
    r"Version 2\.0\.\s*\n\s*\*/\s*\n"
    r"|// Copyright \d{4} OramaSearch\.\s*\n// Licensed under the Apache License, Version 2\.0\.\s*\n)"
    r"(?:[ \t]*\n)?"
)


def style_for(path: str) -> str | None:
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    if name in HASH_NAMES or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return "hash"
    if ext in SLASH:
        return "slash"
    if ext in HASH:
        return "hash"
    if ext in BLOCK:
        return "block"
    return None


def repo_root() -> str:
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True,
                         capture_output=True, text=True)
    return out.stdout.strip()


def tracked_files(root: str) -> list[str]:
    out = subprocess.run(["git", "-C", root, "ls-files", "-s", "-z"], check=True,
                         capture_output=True)
    files = []
    for entry in out.stdout.split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode = meta.split()[0]
        if mode in (b"160000", b"120000"):
            continue
        files.append(path.decode("utf-8", "surrogateescape"))
    return files


def ignore_patterns(root: str) -> list[str]:
    path = os.path.join(root, "tools", "spdx-headers.ignore")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]


def ignored(path: str, patterns: list[str]) -> bool:
    parts = path.split("/")
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return True
    return any(fnmatch.fnmatch(path, pat) or path.startswith(pat.rstrip("/") + "/")
               for pat in patterns)


def header_line(style: str) -> str:
    if style == "slash":
        return "// " + IDENTIFIER
    if style == "hash":
        return "# " + IDENTIFIER
    return "/* " + IDENTIFIER + " */"


def insertion_index(lines: list[str], style: str, path: str) -> int:
    i = 0
    if lines and lines[0].startswith("#!") and not lines[0].startswith("#!["):
        i = 1
    if style == "hash":
        name = os.path.basename(path)
        if name.startswith("Dockerfile") or name.endswith(".Dockerfile"):
            while i < len(lines) and DOCKER_DIRECTIVE.match(lines[i]):
                i += 1
        elif path.endswith((".py", ".pyi")):
            if i < len(lines) and PY_CODING.match(lines[i]):
                i += 1
    if style == "block" and i < len(lines) and lines[i].lstrip().startswith("@charset"):
        i += 1
    return i


def process(path: str, apply: bool) -> str:
    """Return 'ok', 'added', 'missing', 'foreign' or 'skip'."""
    style = style_for(path)
    if style is None:
        return "skip"
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return "skip"
    if b"\0" in raw:
        return "skip"
    bom = raw.startswith(b"\xef\xbb\xbf")
    try:
        text = raw[3:].decode("utf-8") if bom else raw.decode("utf-8")
    except UnicodeDecodeError:
        return "skip"
    old = OLD_ORAMA_HEADER.match(text.replace("\r\n", "\n"))
    if old:
        if not apply:
            return "missing"
        crlf = "\r\n" in text[:4096]
        body = text.replace("\r\n", "\n")[old.end():]
        text = body.replace("\n", "\r\n") if crlf else body
    head = text.splitlines()[:HEAD_LINES]
    head_text = "\n".join(head)
    if "SPDX-License-Identifier" in head_text:
        return "ok"
    comments = [ln for ln in head if ln.lstrip().startswith(COMMENT_STARTS)]
    if any(FOREIGN.search(ln) and not OURS.search(ln) for ln in comments):
        return "foreign"
    if not apply:
        return "missing"
    newline = "\r\n" if "\r\n" in text[:4096] else "\n"
    lines = text.splitlines(keepends=True)
    i = insertion_index(lines, style, path)
    insert = [header_line(style) + newline]
    if i < len(lines) and lines[i].strip() != "":
        insert.append(newline)
    if i > 0 and not lines[i - 1].endswith(("\n", "\r")):
        lines[i - 1] += newline
    out = "".join(lines[:i] + insert + lines[i:])
    data = (b"\xef\xbb\xbf" if bom else b"") + out.encode("utf-8")
    with open(path, "wb") as fh:
        fh.write(data)
    return "added"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true",
                        help="report files without the header and exit 1 if any")
    parser.add_argument("--quiet", action="store_true", help="print only the summary")
    args = parser.parse_args()

    root = repo_root()
    os.chdir(root)
    patterns = ignore_patterns(root)
    counts = {"ok": 0, "added": 0, "missing": 0, "foreign": 0, "skip": 0}
    foreign, missing = [], []
    for path in sorted(tracked_files(root)):
        if ignored(path, patterns):
            counts["skip"] += 1
            continue
        result = process(path, apply=not args.check)
        counts[result] += 1
        if result == "foreign":
            foreign.append(path)
        elif result == "missing":
            missing.append(path)

    if not args.quiet:
        for path in missing:
            print(f"missing: {path}")
        for path in foreign:
            print(f"foreign (review, not edited): {path}")
    print(f"spdx-headers: {counts['ok']} already tagged, {counts['added']} tagged now, "
          f"{counts['missing']} missing, {len(foreign)} foreign, {counts['skip']} not source")
    return 1 if args.check and missing else 0


if __name__ == "__main__":
    sys.exit(main())
