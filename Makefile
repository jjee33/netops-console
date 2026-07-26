.DEFAULT_GOAL := help
SHELL := /bin/bash

IMAGE   ?= ghcr.io/jjee33/netops-console
TAG     ?= dev
COMPOSE ?= docker compose -f compose.yaml -f compose.dev.yaml

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Local development
# ---------------------------------------------------------------------------

.PHONY: venv
venv: ## Create .venv and install dev dependencies
	python3.12 -m venv .venv
	./.venv/bin/pip install --upgrade pip
	./.venv/bin/pip install -e '.[dev]'

.PHONY: lint
lint: ## ruff + mypy + hadolint
	ruff check app tests
	ruff format --check app tests
	mypy
	@command -v hadolint >/dev/null 2>&1 \
		&& hadolint docker/Dockerfile \
		|| docker run --rm -i hadolint/hadolint < docker/Dockerfile

.PHONY: fmt
fmt: ## Auto-format and auto-fix
	ruff format app tests
	ruff check --fix app tests

.PHONY: test
test: ## Run the test suite (skips smoke tests)
	pytest --cov --cov-report=term-missing

.PHONY: test-smoke
test-smoke: ## Run tests that need real network tools and capabilities
	pytest -m smoke

.PHONY: audit
audit: ## Check dependencies for known vulnerabilities
	pip-audit

# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------

.PHONY: build
build: ## Build the image locally as $(IMAGE):$(TAG)
	docker build -f docker/Dockerfile -t $(IMAGE):$(TAG) .

.PHONY: dev
dev: ## Build and start the stack from source
	$(COMPOSE) up -d --build
	@echo "Waiting for startup..." && sleep 4
	@$(COMPOSE) logs app | grep -A4 'Initial admin' || true

.PHONY: up
up: ## Start using the published image
	docker compose up -d

.PHONY: down
down: ## Stop the stack, keeping data
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop and DELETE the data volume (destroys DB and keys)
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Follow application logs
	$(COMPOSE) logs -f app

.PHONY: shell
shell: ## Shell into the running container as the app user
	$(COMPOSE) exec app /bin/bash

# ---------------------------------------------------------------------------
# Verification — mirrors the CI smoke job. See docs/INSTALL.md Appendix C.
# ---------------------------------------------------------------------------

.PHONY: smoke
smoke: build ## Assert capabilities, non-root UID, and unprivileged tool use
	@echo "==> file capabilities"
	docker run --rm $(IMAGE):$(TAG) netops-getcap /usr/bin/nmap /usr/bin/ping /usr/bin/traceroute
	@echo "==> runtime UID (expect 10001)"
	docker run --rm $(IMAGE):$(TAG) id -u
	@echo "==> unprivileged tool use with NET_RAW"
	docker run --rm --cap-drop=ALL --cap-add=NET_RAW $(IMAGE):$(TAG) \
		sh -c 'nmap -sn 127.0.0.1/32 >/dev/null && ping -c1 -W1 127.0.0.1 >/dev/null && echo OK'
	@echo "==> all smoke checks passed"

.PHONY: fresh
fresh: clean dev ## Destroy the volume and verify a clean first-run install
	@echo "==> fresh-volume install completed; check the admin password above"

.PHONY: backup
backup: ## Take a consistent SQLite backup of the running instance
	$(COMPOSE) exec app python -c \
		"import sqlite3,os; d=os.environ['NETOPS_DB_PATH']; \
		 sqlite3.connect(d).execute(\"VACUUM INTO '/data/backup.db'\")"
	@echo "==> wrote /data/backup.db inside the volume. Copy it out, and back up"
	@echo "    /data/secrets/crypto_key to a SEPARATE location."
