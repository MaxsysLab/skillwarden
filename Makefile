# SkillWarden: development tasks. Assumes `uv` is on PATH.
.PHONY: help install dev test cov lint fmt typecheck clean scan-demo audit audit-fetch

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

install: ## Install the package (prod)
	uv sync

dev: ## Install with dev + yara extras
	uv sync --extra dev --extra yara

test: ## Run the test suite
	uv run pytest -q

cov: ## Run tests with coverage
	uv run pytest --cov=skillwarden --cov-report=term-missing

lint: ## Lint with ruff
	uv run ruff check src tests scripts

fmt: ## Format with ruff
	uv run ruff format src tests scripts && uv run ruff check --fix src tests scripts

typecheck: ## Static type check
	uv run mypy src

scan-demo: ## Scan the bundled malicious fixture
	uv run skillwarden scan tests/fixtures/malicious_skill --no-llm

audit: ## Offline false-positive audit of the cached corpus (no network; fails on any benign CRITICAL)
	uv run python scripts/fp_audit.py

audit-fetch: ## Same, but first clone the trusted corpus (explicit network opt-in)
	uv run python scripts/fp_audit.py --fetch

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
