PROXY_NAME      := credproxy
PROXY_IMAGE     := credproxy:dev
WORKSPACE_IMAGE := python:3.12-slim

.DEFAULT_GOAL := help

.PHONY: help build up down restart logs reload shell workspace rebuild

help:
	@echo "credproxy dev harness"
	@echo ""
	@echo "  make build      build the proxy image"
	@echo "  make up         start the proxy (bind-mounts ./proxy -> /opt/proxy)"
	@echo "  make down       stop and remove the proxy container"
	@echo "  make restart    down + up (no rebuild)"
	@echo "  make logs       tail proxy logs"
	@echo "  make reload     hot-reload python code in the running proxy"
	@echo "  make shell      open a shell in the proxy (root)"
	@echo "  make workspace  run a workspace container joined to the proxy netns"
	@echo "  make rebuild    down + build + up"

build:
	docker build -t $(PROXY_IMAGE) proxy/

up:
	docker run -d --rm \
		--name $(PROXY_NAME) \
		--cap-add NET_ADMIN \
		-v $(CURDIR)/proxy:/opt/proxy \
		$(PROXY_IMAGE)

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
