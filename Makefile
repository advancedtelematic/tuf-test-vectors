.PHONY: all clean generate generate-tuf generate-uptane help init init-dev run test update venv
.DEFAULT_GOAL := generate

all: generate test ## DO ALL THE THINGS
	@true

clean: ## Remove temp resources
	@rm -rf venv vectors metadata *.egg-info \
		`find . -type d -name __pycache__` \
		`find . -type f -name '*.pyc'` \
		.cache .coverage htmlcov

generate: generate-tuf generate-uptane ## Generate all test vectors
	@true

generate-tuf: init ## Generate TUF test vectors
	@. venv/bin/activate && \
		./generator.py -t tuf -o vectors/tuf

generate-uptane: init ## Generate Uptane test vectors
	@. venv/bin/activate && \
		./generator.py -t uptane -o vectors/uptane

help: ## Show this message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

init: venv ## Initialize the environment
	@. venv/bin/activate && \
		pip install -Ur requirements.txt && \
		mkdir -p metadata/tuf metadata/uptane vectors/tuf vectors/uptane

init-dev: init ## Initialize the dev environment
	@. venv/bin/activate && \
		pip install -Ur requirements-dev.txt

run: init ## Run the server
	@. venv/bin/activate && \
		./server.py -t tuf

test: init-dev ## Run the test suite
	@. venv/bin/activate && \
		./test.sh

update: ## Update the requirements and virtualenv
	@pip-compile requirements.in && \
		pip-compile requirements-dev.in && \
		$(MAKE) init

venv: ## Create the virtualenv
	@if [ ! -d venv ]; then virtualenv -p `which python3` venv; fi
