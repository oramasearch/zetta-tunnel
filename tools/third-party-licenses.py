#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate THIRD_PARTY_LICENSES from tools/third-party-licenses.json.

    python3 tools/third-party-licenses.py           # write THIRD_PARTY_LICENSES
    python3 tools/third-party-licenses.py --check   # exit 1 if the file is out of date

The JSON lists every component this repository includes, fetches, links or bundles. A
component's version is either written in the JSON or, for a git submodule, read from the
submodule pin (`"submodule": "modules/<name>"`). Its license text comes from one of:

- `"github": "owner/repo"` (+ optional `"path"`): the file at the pinned ref, through the
  GitHub API (the `gh` CLI when installed, otherwise `GITHUB_TOKEN` or anonymous);
- `"url"`: a plain download;
- `"file"`: a file in this repository;
- `"text"`: written inline, for a notice that has no file (public domain, not distributed).

Components marked `"table_only": true` are listed in the summary without their text (for
example a benchmark's own dependency tree, whose texts ship with each crate).

Only the standard library is used. Network access is needed to regenerate the file.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import urllib.request

ROOT = subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True,
                      capture_output=True, text=True).stdout.strip()
SPEC = os.path.join(ROOT, "tools", "third-party-licenses.json")
OUT = os.path.join(ROOT, "THIRD_PARTY_LICENSES")
RULE = "=" * 80
THIN = "-" * 80


def submodule_pin(path: str) -> str:
    out = subprocess.run(["git", "-C", ROOT, "ls-tree", "HEAD", path], check=True,
                         capture_output=True, text=True).stdout.split()
    if len(out) < 3 or out[1] != "commit":
        raise SystemExit(f"{path} is not a submodule")
    return out[2]


def github_file(repo: str, ref: str, path: str | None) -> str:
    endpoint = (f"repos/{repo}/contents/{path}?ref={ref}" if path
                else f"repos/{repo}/license?ref={ref}")
    if shutil.which("gh"):
        raw = subprocess.run(["gh", "api", endpoint], check=True, capture_output=True,
                             text=True).stdout
    else:
        request = urllib.request.Request(f"https://api.github.com/{endpoint}")
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(request) as response:
            raw = response.read().decode()
    return base64.b64decode(json.loads(raw)["content"]).decode("utf-8", "replace")


def download(url: str) -> str:
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8", "replace")


def license_text(component: dict, ref: str) -> str:
    if "text" in component:
        return component["text"]
    if "file" in component:
        with open(os.path.join(ROOT, component["file"]), encoding="utf-8") as fh:
            return fh.read()
    if "url" in component:
        return download(component["url"])
    return github_file(component["github"], component.get("ref", ref), component.get("path"))


def render(spec: dict) -> str:
    components = spec["components"]
    rows = []
    for c in components:
        version = submodule_pin(c["submodule"]) if "submodule" in c else c.get("version", "-")
        c["_version"] = version
        rows.append((c["name"], version[:12] if "submodule" in c else version, c["license"],
                     c["use"], c.get("source", "")))
    header = ("Component", "Version", "License", "How used", "Source")
    widths = [max(len(r[i]) for r in rows + [header]) for i in range(4)]

    def line(r):
        return "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(r[:4])) + "  " + r[4]

    out = [f"Third-party software in {spec['repository']}", "",
           f"{spec['repository']} is licensed under the MIT License (see LICENSE). It includes or uses the",
           "components below, each under its own license. This file is generated; do not edit it by hand.",
           "Generated with: python3 tools/third-party-licenses.py",
           "From: tools/third-party-licenses.json and the submodule pins of this commit", ""]
    if spec.get("preamble"):
        out += [spec["preamble"].rstrip(), ""]
    out += ["Summary", "", line(header)] + [line(r) for r in rows] + [""]
    for c in components:
        if c.get("note"):
            out += [f"{c['name']}: {c['note']}"]
    out.append("")
    for c in components:
        if c.get("table_only"):
            continue
        out += [RULE, f"{c['name']} {c['_version']} — {c['license']}", c.get("source", ""), THIN,
                license_text(c, c["_version"]).strip(), ""]
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    with open(SPEC, encoding="utf-8") as fh:
        spec = json.load(fh)
    text = render(spec)
    if "--check" in sys.argv:
        with open(OUT, encoding="utf-8") as fh:
            current = fh.read()
        if current != text:
            print("THIRD_PARTY_LICENSES is out of date: run python3 tools/third-party-licenses.py")
            return 1
        return 0
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"THIRD_PARTY_LICENSES: {len(spec['components'])} components")
    return 0


if __name__ == "__main__":
    sys.exit(main())
