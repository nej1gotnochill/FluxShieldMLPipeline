#!/usr/bin/env python3
"""Assemble dashboard/index.html from the standalone sources.

Layout of index.html (must match exactly one <style> block and four
inline <script> blocks):

    head ... <style>  <- style.css   </style> body markup
    <script> <- data.js   </script>
    <script> <- loader.js </script>
    <script> <- charts.js </script>
    <script> <- app.js    </script>
    tail

Run from this directory:  python build.py
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = ["style.css", "data.js", "loader.js", "charts.js", "app.js"]
INDEX = os.path.join(HERE, "index.html")

SPLIT_RE = re.compile(r"(<style>|</style>|<script>|</script>)")


def fail(msg: str) -> None:
    print("build.py: " + msg, file=sys.stderr)
    sys.exit(1)


def main() -> None:
    with open(INDEX, encoding="utf-8") as f:
        parts = SPLIT_RE.split(f.read())

    # parts alternates: text, marker, text, marker, ... (odd length)
    markers = parts[1::2]
    texts = parts[0::2]

    expected = ["<style>", "</style>"] + ["<script>", "</script>"] * 4
    if markers != expected:
        fail("unexpected index.html layout; markers found: "
             + json.dumps(markers))

    chunks = []
    for name in SOURCES:
        with open(os.path.join(HERE, name), encoding="utf-8") as f:
            chunks.append(f.read().rstrip("\n"))

    # texts indexes: 0 head, 1 css, 2 mid1, 3 js1, 4 mid2, 5 js2,
    #                6 mid3, 7 js3, 8 mid4, 9 js4(app), 10 tail
    texts[1] = "\n" + chunks[0] + "\n"          # style.css
    for i, name in enumerate(SOURCES[1:], start=1):
        texts[2 * i + 1] = "\n" + chunks[i] + "\n"

    out = "".join(t + m for t, m in zip(texts[:-1], markers)) + texts[-1]

    tmp = INDEX + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(out)
    os.replace(tmp, INDEX)
    print("built index.html (%d lines) from %s"
          % (out.count("\n") + 1, ", ".join(SOURCES)))


if __name__ == "__main__":
    main()
