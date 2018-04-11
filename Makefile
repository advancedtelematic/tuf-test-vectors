.DEFAULT_GOAL := generate

.PHONY: all
all: generate test ## DO ALL THE THINGS

.PHONY: clean
clean: ## Remove temp resources
	@rm -rf venv vectors metadata *.egg-info \
		`find . -type d -name __pycache__` \
		`find . -type f -name '*.pyc'` \
		.cache .coverage htmlcov

.PHONY: generate
generate: generate-tuf generate-uptane ## Generate all test vectors

.PHONY: generate-tuf
generate-tuf: init ## Generate TUF test vectors
	@. venv/bin/activate && \
		./generator.py -t tuf -o vectors/tuf

.PHONY: generate-update
generate-uptane: init ## Generate Uptane test vectors
	@. venv/bin/activate && \
		./generator.py -t uptane -o vectors/uptane --include-custom --ecu-identifier 123 --hardware-id abc

.PHONY: help
help: ## Show this message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: init
init: venv ## Initialize the environment
	@. venv/bin/activate && \
		pip install -Ur requirements.txt && \
		mkdir -p metadata/tuf metadata/uptane vectors/tuf vectors/uptane

.PHONY: init-dev
init-dev: venv ## Initialize the dev environment
	@. venv/bin/activate && \
		pip install -Ur requirements-dev.txt

TEST ?= 'tests/'
.PHONY: test
test: init-dev ## Run the test suite
	@. venv/bin/activate && \
		python -m pytest -v --cov tuf_vectors --cov-report html --cov-report term $(TEST)

.PHONY: update
update: ## Update the requirements and virtualenv
	@pip-compile requirements.in --output-file requirements.txt && \
		pip-compile requirements-dev.in requirements.in --output-file requirements-dev.txt && \
		$(MAKE) init

venv: ## Create the virtualenv
	@if [ ! -d venv ]; then virtualenv -p `which python3` venv; fi


.PHONY: lint
lint: init-dev ## Lint the python files
	flake8
