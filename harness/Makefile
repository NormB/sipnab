# sipnab MCP diagnostic harness
#
#   make up          # generate signing key (once), build images, start the stack
#   make logs        # follow logs
#   make mcp-test    # exercise the MCP HTTP endpoint locally with the current token
#   make laptop      # print the MCP client config for your laptop
#   make down        # stop and remove the stack
#
#   make up ANCHOR=rtpproxy   # same stack, media anchored by rtpproxy
#   make up ANCHOR=none       # same stack, endpoints exchange media directly
#
.DEFAULT_GOAL := help
SHELL := /bin/bash

# ---- Media anchor ----------------------------------------------------------
# ONE variable, deliberately. The anchor choice has two halves that must agree
# -- which relay CONTAINER runs, and which relay OpenSIPS is configured to talk
# to -- and a harness that made you set both would eventually be run with them
# disagreeing, which presents as a 500 on every INVITE with nothing in either
# log saying why. ANCHOR sets the compose profile and MEDIA_ANCHOR together.
#
# Precedence: `make up ANCHOR=x` beats MEDIA_ANCHOR in .env beats rtpengine.
ANCHOR ?= $(shell . ./$(ENV_FILE) 2>/dev/null; echo $${MEDIA_ANCHOR:-rtpengine})
VALID_ANCHORS := rtpengine rtpproxy none

COMPOSE := MEDIA_ANCHOR=$(ANCHOR) docker compose --profile $(ANCHOR)
# Every profile at once, for teardown only: `make down` must remove the relay
# that is running, not the relay the current ANCHOR names.
COMPOSE_ALL := docker compose --profile rtpengine --profile rtpproxy --profile none

# What the stack is ACTUALLY running, read from the container rather than
# assumed from .env -- the two drift the moment anyone runs `make up ANCHOR=x`.
RUNNING_ANCHOR = $(shell docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' opensips-1 2>/dev/null | sed -n 's/^MEDIA_ANCHOR=//p')
# Presence is a SEPARATE question from which anchor. An empty RUNNING_ANCHOR
# means either "no container" or "a container built before this variable
# existed", and reporting the second as "the stack is down" sends you to
# `make up` looking for a failure that is not there.
OPENSIPS_PRESENT = $(shell docker inspect -f '{{.Id}}' opensips-1 2>/dev/null)
# Long-lived HMAC signing key (the real secret; stays on the host). The bearer
# TOKEN_FILE is a short-lived artifact the sipnab container re-mints on a timer.
SIGNING_KEY_FILE := secrets/mcp.signing-key
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

$(SIGNING_KEY_FILE):
	@openssl rand -hex 32 > $(SIGNING_KEY_FILE)
	@# world-readable: sipnab drops to 'nobody' before reading it inside the container
	@chmod 644 $(SIGNING_KEY_FILE)
	@echo "generated MCP HMAC signing key -> $(SIGNING_KEY_FILE)"

.PHONY: answer-audio
answer-audio: sipp/scenarios/g711a_answer.pcap ## Generate the callee's audio (distinct tone + SSRC)
sipp/scenarios/g711a_answer.pcap:
	@python3 scripts/make-pcma-pcap.py $@ --hz 660 --seconds 90 --ssrc 0x5AFE1234

.PHONY: api-key
api-key: secrets/api.key ## Generate the REST API key (idempotent)
secrets/api.key:
# 0600, not 0644. `umask 077` already yields owner-only and an explicit chmod
# widening it back was cargo-culted from the signing key beside it, leaving a
# live credential world-readable on a multi-user host. Nothing needs the wider
# mode: the entrypoint reads this as root before sipnab drops privileges to
# `nobody`, and root is not subject to the permission bits.
	@umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > $@
	@chmod 0600 $@
	@echo "wrote $@ (0600)"

.PHONY: signing-key
signing-key: $(SIGNING_KEY_FILE) ## Generate the long-lived MCP signing key (idempotent)

.PHONY: check-anchor
check-anchor:
	@case " $(VALID_ANCHORS) " in \
	  *" $(ANCHOR) "*) ;; \
	  *) echo "ANCHOR='$(ANCHOR)' is not one of: $(VALID_ANCHORS)" >&2; exit 1;; \
	esac

.PHONY: anchor
anchor: ## Show the selected media anchor and the one actually running
	@echo "selected: $(ANCHOR)"
	@if [ -z "$(OPENSIPS_PRESENT)" ]; then \
	  echo "running:  (stack is down)"; \
	elif [ -z "$(RUNNING_ANCHOR)" ]; then \
	  echo "running:  (unset -- container predates MEDIA_ANCHOR; 'make up' recreates it)"; \
	else \
	  echo "running:  $(RUNNING_ANCHOR)"; \
	fi

.PHONY: stop-other-anchors
stop-other-anchors: ## Remove relay containers belonging to a different anchor
	@# A relay left over from the previous anchor keeps its published ports, so
	@# the incoming relay fails to bind and the stack comes up half-swapped.
	@for a in $(filter-out $(ANCHOR),rtpengine rtpproxy); do \
	  case $$a in \
	    rtpengine) victims="sipnab-relay rtpengine";; \
	    rtpproxy)  victims="sipnab-relay-rtpproxy rtpproxy";; \
	  esac; \
	  for v in $$victims; do \
	    docker rm -f "$$v" >/dev/null 2>&1 && echo "  removed $$v (anchor $$a)"; \
	  done; \
	done; true

.PHONY: build
build: $(ENV_FILE) check-anchor ## Build all images
	$(COMPOSE) build

.PHONY: host-prep
host-prep: ## Ensure bridged container traffic is delivered (sets a sysctl; needs sudo)
	@if [ "$$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null)" = "1" ]; then \
	  echo "host-prep: setting net.bridge.bridge-nf-call-iptables=0 (required so SIP/RTP reaches containers)"; \
	  sudo sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null; \
	else echo "host-prep: bridge-nf-call-iptables already disabled — ok"; fi

.PHONY: up
up: $(ENV_FILE) $(SIGNING_KEY_FILE) check-anchor host-prep stop-other-anchors ## Build (if needed) and start the whole stack
	@# An anchor change rewrites opensips-1's environment, and sipnab-proxy
	@# lives in its NAMESPACE -- so recreating the owner without its dependents
	@# leaves the capture point attached to a namespace that no longer exists.
	@# Compose only recreates what it can see has changed, hence the explicit
	@# --force-recreate on a switch and not on a plain restart.
	@if [ -n "$(OPENSIPS_PRESENT)" ] && [ "$(RUNNING_ANCHOR)" != "$(ANCHOR)" ]; then \
	  echo "anchor: $(if $(RUNNING_ANCHOR),$(RUNNING_ANCHOR),unset) -> $(ANCHOR) (recreating the netns owner and its dependents)"; \
	  $(COMPOSE) up -d --build --force-recreate; \
	else \
	  $(COMPOSE) up -d --build; \
	fi
	@echo
	@echo "media anchor: $(ANCHOR)"
	@$(MAKE) --no-print-directory laptop

.PHONY: wait-token
wait-token: ## Wait until the sipnab rotator has published the first bearer token
	@i=0; while [ ! -s "$(TOKEN_FILE)" ]; do \
	  i=$$((i+1)); \
	  [ $$i -gt 30 ] && { echo "timed out waiting for $(TOKEN_FILE); is the sipnab container up? (make logs-sipnab)" >&2; exit 1; }; \
	  sleep 1; \
	done

.PHONY: recreate
recreate: host-prep ## Recreate the stack (use after editing opensips: rebuilds netns dependents too)
	$(COMPOSE) up -d --build --force-recreate

.PHONY: down
down: ## Stop and remove the stack (every anchor profile)
	$(COMPOSE_ALL) down

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
mcp-test: wait-token ## Call the MCP endpoint locally (initialize + tools/list + list_dialogs)
	@./scripts/mcp-smoke.sh "http://127.0.0.1:$(MCP_PORT)/mcp" "$$(cat $(TOKEN_FILE))"

.PHONY: laptop
laptop: wait-token ## Print MCP client config + connection details for your laptop
	@./scripts/print-laptop-config.sh "$(HOST_IP)" "$(MCP_PORT)" "$(TOKEN_FILE)"

.PHONY: scenarios
scenarios: ## List the SIPp scenarios the UAC loop cycles through
	@cat sipp/scenario-matrix.txt

.PHONY: clean
clean: down ## Remove the stack, images, and captured pcaps
	-$(COMPOSE_ALL) down --rmi local -v
	-rm -f captures/*.pcap captures/*.pcapng captures/*.json
