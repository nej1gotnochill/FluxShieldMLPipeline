#!/usr/bin/env sh
# Start the Netra dashboard server (server.py: no-cache HTML) in the background.
# Idempotent: re-running while it is up just prints the URL.
# Artifacts: server.log, .server.pid (both git-ignored).
# Works on Git Bash/Windows and POSIX shells: the PID stored is the real
# Windows PID (from netstat), since MSYS `$!`/`kill` can't see it.
#
# Usage: ./start.sh [port]      (default port: 8000, or NETRA_PORT env)
set -eu

PORT="${1:-${NETRA_PORT:-8000}}"
cd "$(dirname "$0")"

# Already up? (HTTP check is the reliable liveness test on Windows)
if curl -s -o /dev/null -m 2 "http://127.0.0.1:${PORT}/" 2>/dev/null; then
  OLD_PID="$(cat .server.pid 2>/dev/null || true)"
  echo "Netra dashboard already running (pid ${OLD_PID:-unknown}): http://localhost:${PORT}"
  exit 0
fi
rm -f .server.pid   # stale pid file, port is dead

nohup python server.py "$PORT" > server.log 2>&1 &
disown 2>/dev/null || true

# Wait for the listener, then record the real (Windows) PID from netstat.
i=0
until curl -s -o /dev/null -m 2 "http://127.0.0.1:${PORT}/" 2>/dev/null; do
  i=$((i + 1))
  if [ "$i" -ge 20 ]; then
    echo "ERROR: server did not come up on port ${PORT}. See server.log:" >&2
    tail -5 server.log >&2 || true
    exit 1
  fi
  sleep 0.5
done

REAL_PID="$(netstat -ano 2>/dev/null | grep ":${PORT} " | grep -i listen | awk '{print $NF}' | head -1)"
if [ -n "$REAL_PID" ]; then
  echo "$REAL_PID" > .server.pid
else
  echo "$!" > .server.pid   # non-Windows fallback
fi

echo "Netra dashboard running (pid $(cat .server.pid)): http://localhost:${PORT}  [log: server.log]"
