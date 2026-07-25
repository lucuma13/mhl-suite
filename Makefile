.DEFAULT_GOAL := help
.PHONY: setup-dev upgrade pre-commit test install uninstall reinstall clean help

NAME := $(notdir $(CURDIR))

setup-dev: ## Install uv, sync dependencies, and enable the pre-commit hooks
ifeq ($(OS),Windows_NT)
	winget install -e --silent --accept-package-agreements --accept-source-agreements astral-sh.uv
else ifeq ($(shell uname -s),Darwin)
	brew install uv
else
	curl -LsSf https://astral.sh/uv/install.sh | sh
endif
	uv sync --all-extras
	uv run pre-commit install

upgrade: ## Upgrade dependencies
	uv sync --upgrade --all-extras

pre-commit: ## Run all pre-commit hooks over the whole tree
	uv run pre-commit run --all-files

test: ## Run the test suite with coverage
	uv run pytest

install: ## Install as an editable global uv tool
	uv tool install --force -e .

uninstall: ## Uninstall the tool and clear its cache
	-uv tool uninstall $(NAME)
	uv cache clean $(NAME)

reinstall: ## Uninstall any previous copy, then install fresh
	$(MAKE) uninstall
	$(MAKE) install

clean: ## Remove build artifacts and tool caches
	rm -rf build dist coverage.xml .coverage .pytest_cache .ruff_cache .hypothesis
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2}'
