FROM python:3.12-slim

# Must match MITMPROXY_UID in proxy/constants.sh (drift would silently
# break the iptables --uid-owner rule).
ARG MITMPROXY_UID=31337

# Image's published "API contract" with the host CLI: which port the
# HTTP listener uses, and which paths the in-container code reads from
# / writes to. The CLI reads these via `docker inspect` and uses them
# to build `docker run --tmpfs / --mount / -p` flags. Values must
# agree with proxy/constants.sh and the hardcoded paths in admin.py;
# bumping any of them is a CLI/image API break.
LABEL credproxy.port.http="39998"
LABEL credproxy.mount.tmpfs="/run/secrets"
LABEL credproxy.mount.token="/run/secrets-ro/auth.token"
LABEL credproxy.mount.source="/opt/proxy"

RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        procps \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --uid ${MITMPROXY_UID} --create-home --shell /bin/sh mitmuser

WORKDIR /opt/proxy

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.sh main.py addon.py bootstrap.py \
     admin.py config.py constants.sh constants.py ./
RUN chmod 0755 entrypoint.sh

ENTRYPOINT ["/opt/proxy/entrypoint.sh"]
