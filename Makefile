.PHONY: clean generate help init run update venv
.DEFAULT_GOAL := run

clean: ## Remove temp resources
	@rm -rf venv

generate: init ## Generate test vectors
	@./generator.py

help: ## Show this message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

init: venv ## Initialize the environment
	@. venv/bin/activate && \
		pip install -Ur requirements.txt

run: init ## Run a webserver on localhost:8080 to serve the TUF content
	@./server.py

update: ## Update the requirements and virtualenv
	@pip-compile requirements.in && \
		$(MAKE) init

venv: ## Create the virtualenv
	@if [ ! -d venv ]; then virtualenv -p `which python3` venv; fi
