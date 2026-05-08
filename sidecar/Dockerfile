FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        procps \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --uid 31337 --create-home --shell /bin/sh mitmuser

WORKDIR /opt/proxy

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.sh supervisor.sh reload.sh main.py addon.py ./
RUN chmod 0755 entrypoint.sh supervisor.sh reload.sh

ENTRYPOINT ["/opt/proxy/entrypoint.sh"]
