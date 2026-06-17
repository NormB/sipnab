# sipnab MCP diagnostic harness
#
#   make up        # generate token (once), build images, start the stack
#   make logs      # follow logs
#   make mcp-test  # exercise the MCP HTTP endpoint locally with the token
#   make laptop    # print the MCP client config for your laptop
#   make down      # stop and remove the stack
#
.DEFAULT_GOAL := help
SHELL := /bin/bash
COMPOSE := docker compose
TOKEN_FILE := secrets/mcp.token
ENV_FILE := .env

# Host IP the laptop will use to reach this box (best-effort autodetect).
HOST_IP ?= $(shell ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $$7; exit}')
MCP_PORT ?= $(shell . ./$(ENV_FILE) 2>/dev/null; echo $${MCP_PORT:-8731})

.PHONY: help
help:
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

$(ENV_FILE):
	@cp .env.example $(ENV_FILE) && echo "created $(ENV_FILE) (edit as needed)"

$(TOKEN_FILE):
	@openssl rand -hex 32 > $(TOKEN_FILE)
	@# world-readable: sipnab drops to 'nobody' before reading it inside the container
	@chmod 644 $(TOKEN_FILE)
	@echo "generated MCP bearer token -> $(TOKEN_FILE)"

.PHONY: token
token: $(TOKEN_FILE) ## Generate the MCP bearer token (idempotent)

.PHONY: build
build: $(ENV_FILE) ## Build all images
	$(COMPOSE) build

.PHONY: host-prep
host-prep: ## Ensure bridged container traffic is delivered (sets a sysctl; needs sudo)
	@if [ "$$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null)" = "1" ]; then \
	  echo "host-prep: setting net.bridge.bridge-nf-call-iptables=0 (required so SIP/RTP reaches containers)"; \
	  sudo sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null; \
	else echo "host-prep: bridge-nf-call-iptables already disabled — ok"; fi

.PHONY: up
up: $(ENV_FILE) $(TOKEN_FILE) host-prep ## Build (if needed) and start the whole stack
	$(COMPOSE) up -d --build
	@echo
	@$(MAKE) --no-print-directory laptop

.PHONY: recreate
recreate: host-prep ## Recreate the stack (use after editing opensips: rebuilds netns dependents too)
	$(COMPOSE) up -d --build --force-recreate

.PHONY: down
down: ## Stop and remove the stack
	$(COMPOSE) down

.PHONY: ps
ps: ## Show container status
	$(COMPOSE) ps

.PHONY: logs
logs: ## Follow logs from all services
	$(COMPOSE) logs -f --tail=50

.PHONY: logs-sipnab
logs-sipnab: ## Follow sipnab logs only
	$(COMPOSE) logs -f --tail=100 sipnab

.PHONY: mcp-test
mcp-test: ## Call the MCP endpoint locally (initialize + tools/list + list_dialogs)
	@./scripts/mcp-smoke.sh "http://127.0.0.1:$(MCP_PORT)/mcp" "$$(cat $(TOKEN_FILE))"

.PHONY: laptop
laptop: ## Print MCP client config + connection details for your laptop
	@./scripts/print-laptop-config.sh "$(HOST_IP)" "$(MCP_PORT)" "$(TOKEN_FILE)"

.PHONY: scenarios
scenarios: ## List the SIPp scenarios the UAC loop cycles through
	@cat sipp/scenario-matrix.txt

.PHONY: clean
clean: down ## Remove the stack, images, and captured pcaps
	-$(COMPOSE) down --rmi local -v
	-rm -f captures/*.pcap captures/*.pcapng captures/*.json
