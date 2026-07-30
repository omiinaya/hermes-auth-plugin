.PHONY: install dev test lint clean plugin-install

install:
	pip install -e .

dev:
	pip install -e ".[all]"

test:
	python -m pytest tests/ -v --tb=short

test-verbose:
	python -m pytest tests/ -v --tb=long -s

lint:
	python -m py_compile src/hermes_id/*.py
	flake8 src/ plugins/ tests/ 2>/dev/null || true

clean:
	rm -rf build/ dist/ *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete

plugin-install:
	@echo "Installing Hermes plugin..."
	@mkdir -p ~/.hermes/plugins/hermes-id
	@cp plugins/hermes-id/* ~/.hermes/plugins/hermes-id/
	@hermes plugins enable hermes-id 2>/dev/null || echo "Run 'hermes plugins enable hermes-id' manually"
	@echo "✅ Plugin installed. Restart gateway with 'hermes gateway restart'"

plugin-symlink:
	@echo "Creating plugin symlink..."
	@mkdir -p ~/.hermes/plugins
	@ln -sfn $(PWD)/plugins/hermes-id ~/.hermes/plugins/hermes-id
	@echo "✅ Plugin symlinked. Run 'hermes plugins enable hermes-id'"
