PROXY_NAME      := credproxy
PROXY_IMAGE     := credproxy:dev
WORKSPACE_IMAGE := python:3.12-slim

# bash, not dash: the `up` recipe relies on bash's behavior of honoring
# `</dev/stdin` on backgrounded jobs. dash redirects backgrounded stdin
# to /dev/null per POSIX even with the explicit redirect.
SHELL := /bin/bash

.DEFAULT_GOAL := help

.PHONY: help build up down restart logs reload shell workspace rebuild

help:
	@echo "credproxy dev harness"
	@echo ""
	@echo "  make build      build the proxy image"
	@echo "  make up         start the proxy; reads JSON secrets from stdin"
	@echo "                  e.g. echo '{\"GITHUB_PAT\":\"ghp_...\"}' | make up"
	@echo "                  no secrets needed: make up </dev/null"
	@echo "  make down       stop and remove the proxy container"
	@echo "  make restart    down + up (no rebuild) -- expects secrets on stdin"
	@echo "  make logs       tail proxy logs"
	@echo "  make reload     hot-reload python code (secrets cached in supervisor)"
	@echo "  make shell      open a shell in the proxy (root)"
	@echo "  make workspace  run a workspace container joined to the proxy netns"
	@echo "  make rebuild    down + build + up -- expects secrets on stdin"

build:
	docker build -t $(PROXY_IMAGE) proxy/

up:
	@# `docker run -d` closes stdin, defeating the secrets pipeline.
	@# Instead we run in the foreground and background it. POSIX shells
	@# default backgrounded jobs' stdin to /dev/null, so we explicitly
	@# redirect </dev/stdin to keep the pipe attached -- that's how EOF
	@# from the source `echo {...} | make up` reaches the supervisor's cat.
	docker run -i --rm \
		--name $(PROXY_NAME) \
		--cap-add NET_ADMIN \
		-v $(CURDIR)/proxy:/opt/proxy \
		$(PROXY_IMAGE) </dev/stdin >/dev/null 2>&1 &
	@sleep 0.5
	@docker ps --filter name=$(PROXY_NAME) --format '{{.Names}}' \
		| grep -q $(PROXY_NAME) \
		&& echo "$(PROXY_NAME) started" \
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
