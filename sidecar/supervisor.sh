#!/bin/sh
# Tiny supervisor: respawn the python sidecar process forever.
# `make reload` (-> reload.sh) kills the python child; this loop
# brings it back with freshly imported source.
# SIGTERM/INT to the supervisor itself shuts everything down cleanly.
set -u

export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1

shutting_down=0
child=""

handle_term() {
    shutting_down=1
    [ -n "$child" ] && kill -TERM "$child" 2>/dev/null
}

trap handle_term TERM INT

while :; do
    python -u /opt/proxy/main.py &
    child=$!
    wait "$child" 2>/dev/null || true

    if [ "$shutting_down" = "1" ]; then
        exit 0
    fi

    echo "[supervisor] python exited; restarting"
    sleep 0.3
done
