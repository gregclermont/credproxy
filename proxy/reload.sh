#!/bin/sh
# Triggered by `make reload`. Kills the python child; the supervisor
# (PID 1) respawns it with fresh source.
exec pkill -TERM -f /opt/proxy/main.py
