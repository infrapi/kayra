GOFMT_FILES?=$$(find . -name '*.go' | grep -vE '(./dist|./_local)')
GO_CMD ?= go
SHELL := /bin/bash

.PHONY: all build vet fmt test docs docs-serve
all: build vet fmt test

build:
	$(GO_CMD) build ./...

vet:
	$(GO_CMD) vet ./...

fmt:
	$(GO_CMD)fmt -w $(GOFMT_FILES)

test:
	$(GO_CMD) test -v -timeout 60s -coverprofile=cover.out -cover ./...
	$(GO_CMD) tool cover -func=cover.out
	$(GO_CMD) tool cover -html=cover.out -o coverage.html

docs:
	@echo "Building documentation with MkDocs..."
	@command -v mkdocs >/dev/null 2>&1 || (echo "Error: mkdocs not found. Install with: pip install mkdocs-material mkdocs-git-revision-date-localized-plugin" && exit 1)
	@mkdocs build
	@echo "Documentation built in site/"
	@echo "To serve locally, run: make docs-serve"

docs-serve:
	@echo "Serving documentation at http://localhost:8000"
	@command -v mkdocs >/dev/null 2>&1 || (echo "Error: mkdocs not found. Install with: pip install mkdocs-material mkdocs-git-revision-date-localized-plugin" && exit 1)
	@mkdocs serve
