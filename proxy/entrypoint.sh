#!/bin/sh
# Proxy entrypoint. Runs as root: installs iptables rules in this netns
# (which becomes the shared netns for the workspace container), then drops
# to uid 31337 and execs the python supervisor.
set -eu

MITMPROXY_UID=31337
PROXY_PORT=39999
BOOTSTRAP_PORT=39998
SENTINEL_IP=169.254.1.1

echo "[entrypoint] installing iptables rules"

# Bind sentinel address; gives an implicit route via lo. Idempotent.
ip addr add "${SENTINEL_IP}/32" dev lo 2>/dev/null || true

# Make proxy.local resolve. Workspace containers joined via
# --network=container: inherit /etc/hosts from this container.
if ! grep -q "proxy.local" /etc/hosts; then
    echo "${SENTINEL_IP} proxy.local" >> /etc/hosts
fi

# nat OUTPUT — order matters.
# 1. Sentinel:80 -> bootstrap HTTP API (handled by aiohttp in main.py).
iptables -t nat -A OUTPUT -d "$SENTINEL_IP" -p tcp --dport 80 \
    -j REDIRECT --to-port "$BOOTSTRAP_PORT"
# 2. Don't loop mitmproxy's own outbound back into itself.
iptables -t nat -A OUTPUT -m owner --uid-owner "$MITMPROXY_UID" -j RETURN
# 3. Don't touch workspace-internal loopback.
iptables -t nat -A OUTPUT -d 127.0.0.0/8 -j RETURN
# 4. Send everything else to mitmproxy.
iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port "$PROXY_PORT"

# filter OUTPUT — force HTTP/3 to fall back to TCP.
iptables -A OUTPUT -p udp --dport 443 -j DROP

# IPv6: not supported in v1; drop everything. May fail in environments
# without ip6tables; non-fatal.
ip6tables -P OUTPUT  DROP 2>/dev/null || true
ip6tables -P INPUT   DROP 2>/dev/null || true
ip6tables -P FORWARD DROP 2>/dev/null || true

echo "[entrypoint] dropping to uid $MITMPROXY_UID, exec supervisor"
# setpriv preserves env, so HOME would still point at /root. mitmproxy reads
# ~/.mitmproxy as its confdir; force it to mitmuser's home.
exec env HOME=/home/mitmuser setpriv \
    --reuid="$MITMPROXY_UID" \
    --regid="$MITMPROXY_UID" \
    --clear-groups \
    /opt/proxy/supervisor.sh
