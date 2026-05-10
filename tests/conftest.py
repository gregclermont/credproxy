# tests/ run via `credproxy test` against the proxy image, with the proxy
# directory bind-mounted at /opt/proxy. Make those modules importable.
import sys

sys.path.insert(0, "/opt/proxy")
