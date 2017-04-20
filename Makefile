.PHONY: generate help init run venv
.DEFAULT_GOAL := run

generate: init ## Generate test vectors
	@./generator.py

help: ## Show this message and exit
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

init: venv ## Initialize the environment
	. venv/bin/activate && \
	pip install -Ur requirements.txt

run: generate ## Run a webserver on localhost:8080 to server TUF content
	@./server.py

venv: ## Create the virtualenv
	@if [ ! -d venv ]; then virtualenv -p `which python3` venv; fi
