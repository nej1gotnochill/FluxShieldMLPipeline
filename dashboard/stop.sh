#!/usr/bin/env sh
# Stop the Netra dashboard server started by start.sh.
# Primary: PID from .server.pid (the real Windows PID). Fallback: whatever
# is listening on the dashboard port. Prints a clear message if not running.
#
# Usage: ./stop.sh
set -u

cd "$(dirname "$0")"

stopped=0

if [ -f .server.pid ]; then
  PID="$(cat .server.pid 2>/dev/null || true)"
  if [ -n "$PID" ] && [ "$PID" != "0" ]; then
    taskkill //F //PID "$PID" >/dev/null 2>&1 || kill "$PID" 2>/dev/null || true
    echo "Netra dashboard stopped (pid $PID)"
    stopped=1
  fi
  rm -f .server.pid
fi

# Fallback: pid file missing/stale but something still listens on :8000.
if [ "$stopped" -eq 0 ]; then
  PIDS="$(netstat -ano 2>/dev/null | grep ':8000 ' | grep -i listen | awk '{print $NF}' | sort -u)"
  for P in $PIDS; do
    if [ -n "$P" ] && [ "$P" != "0" ]; then
      taskkill //F //PID "$P" >/dev/null 2>&1 || kill "$P" 2>/dev/null || true
      echo "Netra dashboard stopped (pid $P, found via port 8000)"
      stopped=1
    fi
  done
  rm -f .server.pid
fi

if [ "$stopped" -eq 0 ]; then
  echo "Netra dashboard is not running"
fi
