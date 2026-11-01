PYTHON ?= python3

.PHONY: help install lint convert convert-check test all clean

help:  ## Show available targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

install:  ## Install pinned dependencies
	$(PYTHON) -m pip install -r requirements.txt

lint:  ## yamllint all YAML (Sigma rules, pipelines, workflows)
	$(PYTHON) -m yamllint --strict .

convert:  ## Convert Sigma rules to Splunk SPL under detections/splunk/
	$(PYTHON) scripts/convert.py

convert-check:  ## Fail if committed SPL is out of date with the Sigma source
	$(PYTHON) scripts/convert.py --check

test:  ## Run the pytest suite
	$(PYTHON) -m pytest

all: lint convert-check test  ## Everything CI runs

clean:  ## Remove caches
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache
