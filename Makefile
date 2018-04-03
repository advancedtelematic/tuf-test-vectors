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
		./generator.py -t uptane -o vectors/uptane

.PHONY: help
help: ## Show this message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: init
init: venv ## Initialize the environment
	@. venv/bin/activate && \
		pip install -Ur requirements.txt && \
		mkdir -p metadata/tuf metadata/uptane vectors/tuf vectors/uptane

.PHONY: init-dev
init-dev: init ## Initialize the dev environment
	@. venv/bin/activate && \
		pip install -Ur requirements-dev.txt

.PHONY: run
run: init ## Run the server
	@. venv/bin/activate && \
		./server.py -t tuf

.PHONY: test
test: init-dev ## Run the test suite
	@. venv/bin/activate && \
		./test.sh

.PHONY: update
update: ## Update the requirements and virtualenv
	@pip-compile requirements.in && \
		pip-compile requirements-dev.in && \
		$(MAKE) init

venv: ## Create the virtualenv
	@if [ ! -d venv ]; then virtualenv -p `which python3` venv; fi
