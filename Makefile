.PHONY: clean clean-rsa generate generate-tuf generate-uptane help init run update venv
.DEFAULT_GOAL := generate

clean: ## Remove temp resources
	@rm -rf venv

clean-rsa: ## `git checkout` on the repos with RSA keys (because of non-determinism)
	@grep -HrnIl -- '-----BEGIN' tuf/ uptane/ \
		| sed -e 's:^\([^/]*/[^/]*/\)\(.*\):\1:g' \
		| sort -u \
		| xargs git checkout --

generate: generate-tuf generate-uptane ## Generate all test vectors
	@true

generate-tuf: init ## Generate TUF test vectors
	@mkdir -p tuf && \
		./generator.py -t tuf -o tuf

generate-uptane: init ## Generate Uptane test vectors
	@mkdir -p uptane && \
		./generator.py -t uptane -o uptane

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
