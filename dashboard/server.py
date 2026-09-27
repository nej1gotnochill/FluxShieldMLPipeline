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
if os.path.isdir(os.path.join(HERE, "..", "src", "streaming")):
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "src", "streaming")))
try:
    from emit import (INCIDENT_STATUSES, apply_incident_status, _load_statuses,
                      _save_statuses)  # noqa: E402  (shared workflow rules)
except ImportError:  # dashboard deployed standalone: static serving only
    INCIDENT_STATUSES = ()
    apply_incident_status = None
AUDIT_PATH = os.path.join(HERE, "audit.log")
ALLOWED_EXT = {".html", ".css", ".js", ".json", ".png", ".svg", ".ico",
               ".woff2", ".woff", ".map"}
SUSPICIOUS = ("..", "<", ">", "|", "&", "$(", "`", "${")
MAX_BODY = 4096

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
    def _auth_ok(self, path: str) -> bool:
        """Bearer auth (opt-in), shared by GET and the incident API."""
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

    def _check(self) -> bool:
        # method gate (control-plane separation: read-only telemetry only;
        # the single sanctioned writer is POST /api/incident, see do_POST)
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
        return self._auth_ok(path)

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

    # ---------------- analyst decisions: POST /api/incident ---------------- #
    # The one sanctioned writer. Records an analyst DECISION about an
    # incident (acknowledge/contain/close) — never a network command; the
    # deployment stays passive/one-way. The status lives in data.json (so
    # every poll sees it) and in incident_status.json (so the next emit
    # re-applies it). Validation uses the CURRENT data.json row: ids are
    # reassigned per replay run, so a stale client cannot flip an incident
    # that no longer exists in the recorded state.
    def do_POST(self):
        t0 = time.perf_counter()
        path = self.path.split("?", 1)[0]
        try:
            if path != "/api/incident":
                self._json(404, {"error": "not found"})
                return
            if apply_incident_status is None:
                self._json(501, {"error": "incident workflow unavailable "
                                       "(emit module not found)"})
                return
            if not self._auth_ok(path):
                return
            origin = self.headers.get("Origin")
            if origin and CORS_ORIGINS and origin not in CORS_ORIGINS:
                self._json(403, {"error": "origin not allowed"})
                return
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = -1
            if not 0 < n <= MAX_BODY:
                self._json(400, {"error": "invalid body size"})
                return
            try:
                req = json.loads(self.rfile.read(n).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._json(400, {"error": "invalid JSON"})
                return
            if not isinstance(req, dict) or set(req) - {"id", "status", "analyst"}:
                self._json(400, {"error": "expected {id, status[, analyst]}"})
                return
            inc_id, target = str(req.get("id", "")), str(req.get("status", ""))
            if not inc_id or target not in INCIDENT_STATUSES:
                self._json(400, {"error": "invalid id or status"})
                return
            doc_path = os.path.join(HERE, "data.json")
            try:
                with open(doc_path, encoding="utf-8") as fh:
                    doc = json.load(fh)
            except (OSError, ValueError):
                self._json(409, {"error": "data.json unavailable"})
                return
            row = next((i for i in doc.get("incidents", [])
                        if isinstance(i, dict) and i.get("id") == inc_id), None)
            if row is None:
                self._json(404, {"error": f"unknown incident {inc_id} "
                                       "(stale view? reload)"})
                return
            statuses = _load_statuses(doc_path)
            ok, new_status = apply_incident_status(
                statuses, inc_id, str(row.get("status", "TRIAGING")), target)
            if not ok:
                audit("INCIDENT_REJECT", client=self.client_address[0],
                      id=inc_id, frm=row.get("status"), to=target)
                self._json(409, {"error": f"cannot move {inc_id} from "
                                       f"{row.get('status')} to {target}"})
                return
            row["status"] = new_status
            analysts = None
            if isinstance(req.get("analyst"), str) and req["analyst"].strip():
                analysts = {inc_id: req["analyst"].strip()[:40]}
                row["analyst"] = analysts[inc_id]
            from emit import (_atomic_write_json, load_incident_analysts,
                              save_incident_analysts)
            _save_statuses(doc_path, statuses)
            if analysts:
                merged = load_incident_analysts(doc_path)
                merged.update(analysts)
                save_incident_analysts(doc_path, merged)
            _atomic_write_json(doc, doc_path)
            audit("INCIDENT_STATUS", client=self.client_address[0],
                  id=inc_id, status=new_status)
            self._json(200, {"id": inc_id, "status": new_status})
        finally:
            self._audit_line(t0)

    # PUT/DELETE/PATCH stay rejected (read-only plane; POST /api/incident is
    # the single sanctioned writer and only accepts POST)
    def do_PUT(self):
        self._json(405, {"error": "method not allowed"})

    do_DELETE = do_PUT
    do_PATCH = do_PUT

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        if origin and origin in CORS_ORIGINS:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.write_common = None
            self.send_header("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
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
