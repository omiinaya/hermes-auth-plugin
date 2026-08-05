# Prefer the project venv; fall back to system python3.
PY ?= $(shell command -v .venv/bin/python 2>/dev/null || command -v python3)

.PHONY: install dev test lint coverage check clean clean-db plugin-install plugin-symlink server docker docker-run admin

install:
	$(PY) -m pip install -e .

dev:
	$(PY) -m pip install -e ".[all,dev]"

test:
	$(PY) -m pytest tests/ -v --tb=short -n auto

test-verbose:
	$(PY) -m pytest tests/ -v --tb=long -s

test-server:
	$(PY) -m pytest tests/test_server.py -v --tb=short

coverage:
	$(PY) -m pytest tests/ --cov=hermes_id --cov-branch --cov-report=term-missing --cov-fail-under=85 -q

coverage-html:
	$(PY) -m pytest tests/ --cov=hermes_id --cov-branch --cov-report=html --cov-fail-under=85 -q

lint:
	$(PY) -m py_compile src/hermes_id/*.py
	@command -v .venv/bin/ruff >/dev/null || { echo "ERROR: ruff not installed — run 'make dev'"; exit 1; }
	.venv/bin/ruff check src/ tests/

# One-command pre-push gate: lint + tests + the coverage gate.
check:
	$(MAKE) lint
	$(MAKE) coverage

clean:
	rm -rf build/ dist/ *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete

# Data-loss footgun guard: databases are NOT build artifacts, so `clean`
# never touches them. Use this target explicitly (and only on dev DBs):
clean-db:
	@echo "Removing local dev databases (repo-root only):"
	rm -fv agent_registry.db invalidated_tokens.db

server:
	@echo "Starting hermes-id Auth Server..."
	hermes-id server --host 0.0.0.0 --port 9488

server-dev:
	@echo "Starting hermes-id Auth Server (dev, auto-reload)..."
	hermes-id server --host 127.0.0.1 --port 9488 --db /tmp/hermes-id-dev.db

docker:
	docker build -t hermes-id-auth .

docker-run:
	docker run -d --name hermes-id-auth \
		-p 9488:9488 \
		-e HERMES_ID_PASSPHRASE="${HERMES_ID_PASSPHRASE}" \
		-e HERMES_ID_ADMIN_KEY="${HERMES_ID_ADMIN_KEY}" \
		-v $(PWD)/identity:/app/identity \
		-v $(PWD)/data:/app/data \
		hermes-id-auth

admin:
	@echo "Usage: make admin ARGS=\"--server http://localhost:9488 --admin-key KEY <cmd>\""
	hermes-id-admin $(ARGS)

plugin-install:
	@echo "Installing Hermes plugin..."
	@mkdir -p ~/.hermes/plugins/hermes-id
	@cp plugins/hermes-id/* ~/.hermes/plugins/hermes-id/
	@hermes plugins enable hermes-id 2>/dev/null || echo "Run 'hermes plugins enable hermes-id' manually"
	@echo "✅ Plugin installed. Restart gateway to pick up changes."

plugin-symlink:
	@echo "Creating plugin symlink..."
	@mkdir -p ~/.hermes/plugins
	@ln -sfn $(PWD)/plugins/hermes-id ~/.hermes/plugins/hermes-id
	@echo "✅ Plugin symlinked. Run 'hermes plugins enable hermes-id'"

example-service:
	@echo "Starting example protected service..."
	python examples/protected_service.py

example-agent:
	python examples/agent_client.py

changelog:
	@cat CHANGELOG.md
