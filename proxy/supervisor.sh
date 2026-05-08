#!/bin/sh
# Tiny supervisor: respawn the python sidecar process forever.
# `make reload` (-> reload.sh) kills the python child; this loop
# brings it back with freshly imported source.
# SIGTERM/INT to the supervisor itself shuts everything down cleanly.
#
# Secrets pipeline: docker run -i hands stdin to this process. We read
# all of it once into a non-exported shell variable (heap, not environ
# -- not visible via /proc/$pid/environ) and re-pipe to each python
# spawn so `make reload` doesn't need to re-prompt. The cached value
# never touches a file or the environment.
set -u

export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1

# Slurp stdin once. Empty stdin -> empty string -> python sees empty
# stdin and treats secrets as {}.
secrets=$(cat)

shutting_down=0
child=""

handle_term() {
    shutting_down=1
    [ -n "$child" ] && kill -TERM "$child" 2>/dev/null
}

trap handle_term TERM INT

while :; do
    printf '%s' "$secrets" | python -u /opt/proxy/main.py &
    child=$!
    wait "$child" 2>/dev/null || true

    if [ "$shutting_down" = "1" ]; then
        exit 0
    fi

    echo "[supervisor] python exited; restarting"
    sleep 0.3
done
