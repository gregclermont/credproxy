PROXY_NAME      := credproxy
PROXY_IMAGE     := credproxy:dev
WORKSPACE_IMAGE := python:3.12-slim

# bash, not dash: the `up` recipe relies on bash's behavior of honoring
# `</dev/stdin` on backgrounded jobs. dash redirects backgrounded stdin
# to /dev/null per POSIX even with the explicit redirect.
SHELL := /bin/bash

.DEFAULT_GOAL := help

.PHONY: help build up down restart logs reload shell workspace rebuild test set-config

help:
	@echo "credproxy dev harness"
	@echo ""
	@echo "  make build       build the proxy image"
	@echo "  make up          start the proxy with an empty config; admin"
	@echo "                   token is generated and saved to .run/auth.token"
	@echo "  make down        stop and remove the proxy container"
	@echo "  make restart     down + up (no rebuild)"
	@echo "  make logs        tail proxy logs"
	@echo "  make reload      hot-reload python (re-reads /run/secrets/config.json)"
	@echo "  make shell       open a shell in the proxy (root)"
	@echo "  make workspace   run a workspace container joined to the proxy netns"
	@echo "  make rebuild     down + build + up"
	@echo "  make test        run pytest in the proxy image"
	@echo "  make set-config  resolve proxy/config.yaml \$${secret:NAME} refs"
	@echo "                   from host env and POST via /admin/config."
	@echo "                   e.g. GITHUB_PAT=\$$(op read 'op://...') make set-config"

build:
	docker build -t $(PROXY_IMAGE) proxy/

up:
	@# Generate an auth token, save host-side at .run/auth.token (0600),
	@# and pipe a {"auth_token": "..."} envelope into the container's
	@# stdin. TOKEN is passed to python via env (not argv) so it doesn't
	@# show in ps. The supervisor reads this once and persists it on
	@# tmpfs so reloads keep the same token.
	@#
	@# Why not `docker run -d`? It closes stdin, defeating the pipeline.
	@# We run in foreground + background. POSIX shells default
	@# backgrounded jobs' stdin to /dev/null, so we redirect </dev/stdin
	@# explicitly to keep the pipe attached.
	@mkdir -p .run
	@TOKEN=$$(openssl rand -hex 16); \
	echo -n "$$TOKEN" > .run/auth.token; \
	chmod 600 .run/auth.token; \
	TOKEN="$$TOKEN" python3 -c 'import json,os; print(json.dumps({"auth_token":os.environ["TOKEN"]}))' \
		| docker run -i --rm \
			--name $(PROXY_NAME) \
			--cap-add NET_ADMIN \
			--tmpfs /run/secrets:size=64k,uid=31337,mode=0700 \
			-p 127.0.0.1:39997:39997 \
			-v $(CURDIR)/proxy:/opt/proxy \
			$(PROXY_IMAGE) </dev/stdin >/dev/null 2>&1 &
	@sleep 0.5
	@docker ps --filter name=$(PROXY_NAME) --format '{{.Names}}' \
		| grep -q $(PROXY_NAME) \
		&& echo "$(PROXY_NAME) started; token in .run/auth.token" \
		|| (echo "$(PROXY_NAME) failed to start; check 'docker logs'"; exit 1)

down:
	-docker rm -f $(PROXY_NAME) 2>/dev/null

restart: down up

logs:
	docker logs -f $(PROXY_NAME)

reload:
	docker exec $(PROXY_NAME) /opt/proxy/reload.sh

shell:
	docker exec -it --user 0 $(PROXY_NAME) bash

workspace:
	docker run --rm -it --network=container:$(PROXY_NAME) \
		$(WORKSPACE_IMAGE) bash

rebuild: down build up

test:
	docker run --rm \
		-v $(CURDIR)/proxy:/opt/proxy \
		-v $(CURDIR)/tests:/opt/tests \
		-w /opt \
		--entrypoint python \
		$(PROXY_IMAGE) \
		-m pytest -v tests/

set-config:
	@./bin/credproxy push-config
