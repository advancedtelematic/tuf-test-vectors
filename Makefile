.DEFAULT_GOAL := help
OPEN=$(word 1, $(wildcard /usr/bin/xdg-open /usr/bin/open))

.PHONY: help
help: ## Print the help message
	@awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {printf "\033[36m%s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST) | \
		sort | \
		column -s ':' -t

.PHONY: clean
clean: ## Remove temp resources
	@rm -rf venv vectors metadata *.egg-info \
		`find . -type d -name __pycache__` \
		`find . -type f -name '*.pyc'` \
		.cache .coverage htmlcov

.PHONY: generate
generate: init ## Generate Uptane test vectors
	@. venv/bin/activate && \
		./generator.py -o vectors --ecu-identifier 123 --hardware-id abc

.PHONY: init
init: venv ## Initialize the environment
	@. venv/bin/activate && \
		pip install -Ur requirements.txt && \
		mkdir -p vectors

.PHONY: init-dev
init-dev: venv ## Initialize the dev environment
	@. venv/bin/activate && \
		pip install -Ur requirements-dev.txt

TEST ?= 'tests/'
.PHONY: test
test: init-dev ## Run the test suite
	@. venv/bin/activate && \
		python -m pytest -v --cov tuf_vectors --cov-report html --cov-report term-missing $(TEST)

.PHONY: update
update: ## Update the requirements and virtualenv
	@pip-compile -U requirements.in --output-file requirements.txt && \
		pip-compile -U requirements-dev.in requirements.in --output-file requirements-dev.txt && \
		$(MAKE) init

venv: ## Create the virtualenv
	@if [ ! -d venv ]; then virtualenv -p `which python3` venv; fi


.PHONY: lint
lint: init-dev ## Lint the python files
	@. venv/bin/activate && \
		flake8

.PHONY: open-coverage-report
open-coverage-report: ## Open the coverage report in your browser
	@$(OPEN) htmlcov/index.html
