SIDECAR_NAME  := credproxy-sidecar
SIDECAR_IMAGE := credproxy-sidecar:dev
AGENT_IMAGE   := python:3.12-slim

.DEFAULT_GOAL := help

.PHONY: help build up down restart logs reload shell agent rebuild

help:
	@echo "credproxy dev harness"
	@echo ""
	@echo "  make build     build the sidecar image"
	@echo "  make up        start the sidecar (bind-mounts ./sidecar -> /opt/proxy)"
	@echo "  make down      stop and remove the sidecar"
	@echo "  make restart   down + up (no rebuild)"
	@echo "  make logs      tail sidecar logs"
	@echo "  make reload    hot-reload python code in the running sidecar"
	@echo "  make shell     open a shell in the sidecar (root)"
	@echo "  make agent     run an agent container joined to the sidecar netns"
	@echo "  make rebuild   down + build + up"

build:
	docker build -t $(SIDECAR_IMAGE) sidecar/

up:
	docker run -d --rm \
		--name $(SIDECAR_NAME) \
		--cap-add NET_ADMIN \
		-v $(CURDIR)/sidecar:/opt/proxy \
		$(SIDECAR_IMAGE)

down:
	-docker rm -f $(SIDECAR_NAME) 2>/dev/null

restart: down up

logs:
	docker logs -f $(SIDECAR_NAME)

reload:
	docker exec $(SIDECAR_NAME) /opt/proxy/reload.sh

shell:
	docker exec -it --user 0 $(SIDECAR_NAME) bash

agent:
	docker run --rm -it --network=container:$(SIDECAR_NAME) \
		$(AGENT_IMAGE) bash

rebuild: down build up
