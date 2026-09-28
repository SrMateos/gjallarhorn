#!/usr/bin/env bash
# Stop the Laya server. It intentionally does not stop when Claude Code exits:
# it is shared across sessions and reloading it takes seconds.
STATE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/laya-guard"
PIDFILE="$STATE_DIR/laya.pid"
if [[ -f "$PIDFILE" ]]; then
  kill -- -"$(cat "$PIDFILE")" 2>/dev/null || kill "$(cat "$PIDFILE")" 2>/dev/null
  rm -f "$PIDFILE"
  echo "laya-serve stopped"
else
  echo "no pidfile at $PIDFILE"
fi
