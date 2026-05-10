# Image-internal runtime constants -- single source of truth for shell
# + python inside the proxy container. Sourced by entrypoint.sh and
# parsed by constants.py.
#
# Plain KEY=VALUE only (no `export`, no command substitution): the
# python parser is intentionally minimal.
#
# These are NOT the values the host CLI consumes -- those are published
# as Docker LABELs on the proxy image (see proxy/Dockerfile).

MITMPROXY_UID=31337
HTTP_PORT=39998
PROXY_PORT=39999
SENTINEL_IP=169.254.1.1
