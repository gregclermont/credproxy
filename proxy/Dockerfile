# check=skip=SecretsUsedInArgOrEnv
# (suppresses a false positive on CREDPROXY_TOKEN_PATH -- the value is a
# filesystem path, not a secret. The lint matches any "TOKEN" substring.)

FROM python:3.12-slim

# Image constants -- single source of truth for both the in-container
# code (via the inherited process environment) and the host CLI (via
# `docker inspect`'s `Config.Env`). `ENV` is also visible to subsequent
# `RUN`/`WORKDIR`/`COPY` steps, so build-time uses pull from the same
# place. Bumping any value is an image/CLI API break -- rebuild after.
ENV CREDPROXY_MITMPROXY_UID=31337 \
    CREDPROXY_HTTP_PORT=39998 \
    CREDPROXY_PROXY_PORT=39999 \
    CREDPROXY_SENTINEL_IP=169.254.1.1 \
    CREDPROXY_TMPFS=/run/secrets \
    CREDPROXY_TOKEN_PATH=/run/secrets-ro/auth.token \
    CREDPROXY_SOURCE=/opt/proxy

RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        procps \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --uid ${CREDPROXY_MITMPROXY_UID} --create-home --shell /bin/sh mitmuser

WORKDIR ${CREDPROXY_SOURCE}

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy every proxy module with a glob, not a hand-maintained list: a new module
# (or one some other module imports) can't then be silently left out of the
# image. The baked image is the audited runtime artifact -- `dev` bind-mounts
# proxy/ over /opt/proxy for live edits, but production runs these layers, so a
# missing module here is a boot-time crash that only the no-mount path hits.
COPY entrypoint.sh ./
COPY *.py ./
RUN chmod 0755 entrypoint.sh

ENTRYPOINT ["/opt/proxy/entrypoint.sh"]
