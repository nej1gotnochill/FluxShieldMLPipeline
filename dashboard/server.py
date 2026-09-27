#!/usr/bin/env python3
"""Tiny static server for the Netra dashboard.

Same as `python -m http.server`, but sends `Cache-Control: no-cache` for
HTML so browser refreshes always pick up a rebuilt index.html (the stock
server sends no cache headers, so browsers heuristically cache the page
and code fixes appear "missing" until a hard refresh).

Usage: python server.py [port]     (default 8000)
"""
from __future__ import annotations

import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))


class NoCacheHTMLHandler(SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        if self.path in ("/", "/index.html") or self.path.startswith("/?"):
            self.send_header("Cache-Control", "no-cache, must-revalidate")
        super().end_headers()


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    os.chdir(HERE)
    srv = ThreadingHTTPServer(("127.0.0.1", port), NoCacheHTMLHandler)
    print(f"Netra dashboard: http://localhost:{port}  (no-cache HTML)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
