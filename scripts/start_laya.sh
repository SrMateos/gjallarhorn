#!/usr/bin/env bash
# SessionStart: start laya-serve in the background unless it is already running.
# Must return quickly and print NOTHING (SessionStart stdout is added to Claude's context).
set -u
PORT="${LAYA_GUARD_PORT:-8765}"
STATE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/laya-guard"
mkdir -p "$STATE_DIR"
PIDFILE="$STATE_DIR/laya.pid"
LOG="$STATE_DIR/laya-serve.log"
KEYFILE="$STATE_DIR/api_key"

# Something is already listening -> nothing to do (the server is shared across sessions)
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then exit 0; fi
# A start is already in progress (e.g. downloading the model on first run)
if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then exit 0; fi

# Local API key so nothing else on the machine can use the server
if [[ ! -s "$KEYFILE" ]]; then
  head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' > "$KEYFILE"
  chmod 600 "$KEYFILE"
fi

# setsid + nohup: the server survives Claude Code exiting
LAYA_HOST=127.0.0.1 LAYA_PORT="$PORT" LAYA_API_KEY="$(cat "$KEYFILE")" \
LAYA_MAX_TOKEN_BUDGET=8192 \
  setsid nohup uvx --from "laya[serve]" laya-serve >>"$LOG" 2>&1 < /dev/null &
echo $! > "$PIDFILE"

# Warm-up: once the port opens, send one request per checkpoint so both get loaded
# (by default the Router keeps english and multilingual resident at the same time)
( for _ in $(seq 1 600); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
      for M in english multilingual; do
        curl -s -m 180 "http://127.0.0.1:$PORT/v1/systemone" \
          -H "Authorization: Bearer $(cat "$KEYFILE")" -H 'Content-Type: application/json' \
          -d '{"state":{"action":"ls"},"model":"'"$M"'",
               "questions":{"risk":{"type":"choice","instructions":"warmup",
               "criteria":{"A":"dangerous","B":"routine"}}}}' >>"$LOG" 2>&1
      done
      break
    fi
    sleep 1
  done ) >/dev/null 2>&1 < /dev/null &
disown -a 2>/dev/null
exit 0
