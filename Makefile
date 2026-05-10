PROXY_NAME      := credproxy
PROXY_IMAGE     := credproxy:dev
WORKSPACE_IMAGE := python:3.12-slim

.DEFAULT_GOAL := help

.PHONY: help build up down restart logs reload shell workspace rebuild test set-config

TOKEN_FILE := .run/auth.token

help:
	@echo "credproxy dev harness"
	@echo ""
	@echo "  make build       build the proxy image"
	@echo "  make up          start the proxy (generates $(TOKEN_FILE) if absent)"
	@echo "  make down        stop and remove the proxy container"
	@echo "  make restart     down + up (no rebuild)"
	@echo "  make logs        tail proxy logs"
	@echo "  make reload      hot-reload python (re-reads /run/secrets/*)"
	@echo "  make shell       open a shell in the proxy (root)"
	@echo "  make workspace   run a workspace container joined to the proxy netns"
	@echo "  make rebuild     down + build + up"
	@echo "  make test        run pytest in the proxy image"
	@echo "  make set-config  init or update: resolve proxy/config.yaml \$${secret:NAME} refs"
	@echo "                   from host env and POST via /admin/config."
	@echo "                   e.g. GITHUB_PAT=\$$(op read 'op://...') make set-config"

build:
	docker build -t $(PROXY_IMAGE) proxy/

$(TOKEN_FILE):
	@mkdir -p $(dir $@)
	@python3 -c 'import secrets; print(secrets.token_hex(16))' > $@
	@chmod 0600 $@
	@echo "generated $@"

up: $(TOKEN_FILE)
	docker run -d --rm \
		--name $(PROXY_NAME) \
		--cap-add NET_ADMIN \
		--tmpfs /run/secrets:size=64k,uid=31337,mode=0700 \
		--mount type=bind,source=$(CURDIR)/$(TOKEN_FILE),target=/run/secrets-ro/auth.token,readonly \
		-p 127.0.0.1:39998:39998 \
		-v $(CURDIR)/proxy:/opt/proxy \
		$(PROXY_IMAGE) >/dev/null
	@echo "$(PROXY_NAME) started; run 'make set-config' to push config"

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
