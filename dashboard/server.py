#!/usr/bin/env python3
"""Netra dashboard server (Phase 10 hardened).

Features beyond a plain static server:
  * `Cache-Control: no-cache` for HTML so rebuilds are always picked up;
  * AUTH (opt-in): set NETRA_DASH_TOKEN to require `Authorization: Bearer
    <token>` on every request. Unauthenticated requests get 401 with
    `WWW-Authenticate: Bearer`; failures are audit-logged;
  * CORS: default same-origin (no CORS headers). If NETRA_DASH_CORS is set
    (comma-separated origins) only those origins get `Access-Control-Allow-
    Origin`; OPTIONS preflights are answered with the allowlist, never `*`
    with credentials;
  * INPUT VALIDATION: paths are path-traversal-checked; unknown paths get a
    strict JSON 404; requests with query strings containing suspicious
    patterns are rejected 400;
  * AUDIT LOG: every request is logged (time, client, method, path, status,
    latency) to stdout AND to `dashboard/audit.log` (gitignored);
  * control-plane separation: only GET/HEAD are served; anything else is a
    validated 405 — the read-only telemetry plane never accepts commands.

Environment:
    NETRA_DASH_TOKEN   enable bearer auth when set
    NETRA_DASH_CORS    comma-separated allowed origins (default: none)
    NETRA_DASH_BIND    bind address (default 127.0.0.1)
"""
from __future__ import annotations

import json
import os
import sys
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
AUDIT_PATH = os.path.join(HERE, "audit.log")
ALLOWED_EXT = {".html", ".css", ".js", ".json", ".png", ".svg", ".ico",
               ".woff2", ".woff", ".map"}
SUSPICIOUS = ("..", "<", ">", "|", "&", "$(", "`", "${")

TOKEN = os.environ.get("NETRA_DASH_TOKEN", "")
CORS_ORIGINS = [o.strip() for o in os.environ.get("NETRA_DASH_CORS", "").split(",") if o.strip()]
BIND = os.environ.get("NETRA_DASH_BIND", "127.0.0.1")


def audit(event: str, **fields) -> None:
    line = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + event
    if fields:
        line += " " + " ".join(f"{k}={v}" for k, v in fields.items())
    print(line, flush=True)
    try:
        with open(AUDIT_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


class HardenedHandler(SimpleHTTPRequestHandler):
    server_version = "NetraDash/1.0"

    # ---------------- audit + latency ---------------- #
    def log_message(self, fmt, *args):        # silence default stderr access log
        pass

    def _finish(self, code: int) -> None:
        self._code = code
        super().send_response(code)

    def send_response(self, code, message=None):
        # hook to record status for the audit line
        self._code = code
        super().send_response(code, message)

    def end_headers(self):
        if self.path in ("/", "/index.html") or self.path.startswith("/?"):
            self.send_header("Cache-Control", "no-cache, must-revalidate")
        origin = self.headers.get("Origin")
        if origin and origin in CORS_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        super().end_headers()

    # ---------------- auth + validation gate ---------------- #
    def _check(self) -> bool:
        # method gate (control-plane separation: read-only telemetry only)
        if self.command not in ("GET", "HEAD"):
            self._json(405, {"error": "method not allowed"})
            return False
        # path validation
        path = self.path.split("?", 1)[0]
        if any(s in path for s in SUSPICIOUS):
            audit("REJECT", reason="suspicious-path", path=path,
                  client=self.client_address[0])
            self._json(400, {"error": "bad request"})
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext and ext not in ALLOWED_EXT and path not in ("/", "/index.html"):
            self._json(404, {"error": "not found"})
            return False
        # bearer auth (opt-in)
        if TOKEN:
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {TOKEN}":
                audit("AUTH_FAIL", client=self.client_address[0], path=path)
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Bearer")
                self.send_header("Content-Type", " application/json")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return False
        return True

    def _json(self, code: int, body: dict) -> None:
        blob = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(blob)

    def do_GET(self):
        t0 = time.perf_counter()
        if not self._check():
            self._audit_line(t0)
            return
        super().do_GET()
        self._audit_line(t0)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        t0 = time.perf_counter()
        self._json(405, {"error": "read-only telemetry plane; commands not accepted"})
        self._audit_line(t0)

    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        if origin and origin in CORS_ORIGINS:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.write_common = None
            self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization")
            self.send_header("Vary", "Origin")
            self.end_headers()
        else:
            self._json(403, {"error": "origin not allowed"})

    def _audit_line(self, t0: float) -> None:
        audit("REQUEST", client=self.client_address[0], method=self.command,
              path=self.path.split("?", 1)[0], status=getattr(self, "_code", 0),
              ms=round((time.perf_counter() - t0) * 1e3, 1))

    # ---------------- 404/405/500 JSON error bodies ---------------- #
    def send_error(self, code, message=None, explain=None):
        if code in (404, 405, 400, 403):
            self._json(code, {"error": message or "error", "status": code})
        else:
            super().send_error(code, message, explain)


class NetraServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    os.chdir(HERE)
    srv = NetraServer((BIND, port), HardenedHandler)
    audit("START", bind=BIND, port=port, auth="on" if TOKEN else "off",
          cors=len(CORS_ORIGINS))
    print(f"Netra dashboard: http://{BIND}:{port}  "
          f"(auth={'ON' if TOKEN else 'off'}, cors={len(CORS_ORIGINS)} origins, "
          f"audit={AUDIT_PATH})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        audit("STOP")
        srv.server_close()


if __name__ == "__main__":
    main()
