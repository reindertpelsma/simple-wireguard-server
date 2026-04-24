#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC_FILES = [
    ROOT / "README.md",
    *sorted((ROOT / "docs").rglob("*.md")),
]
BAD_TEXT_RE = re.compile(r"<<<<<<<|=======|>>>>>>>|\[TODO\]|TODO|FIXME")
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def iter_bad_links(path: pathlib.Path):
    text = path.read_text(encoding="utf-8")
    for link in LINK_RE.findall(text):
        if link.startswith(("http://", "https://", "#", "mailto:")):
            continue
        target = (path.parent / link).resolve()
        if not target.exists():
            yield link


def main() -> int:
    failed = False
    for path in DOC_FILES:
        text = path.read_text(encoding="utf-8")
        if BAD_TEXT_RE.search(text):
            print(f"bad marker in {path.relative_to(ROOT)}", file=sys.stderr)
            failed = True
        for link in iter_bad_links(path):
            print(f"broken link in {path.relative_to(ROOT)} -> {link}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print("docs check ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
