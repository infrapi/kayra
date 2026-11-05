TEST?=$$(go list ./...)
GOFMT_FILES?=$$(find . -name '*.go' | grep -vE './_local')
GO_CMD ?= go
SHELL := /bin/bash

# go test, golangci-lint and gosec all stop at a module boundary, so every
# target below has to walk the modules itself.
MODULES ?= .

.PHONY: setup clean tidy fmt lint security test docs
all: setup clean tidy fmt lint security test

setup:
	@command -v golangci-lint 2>&1 > /dev/null || go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@command -v gosec 2>&1 > /dev/null         || go install github.com/securego/gosec/v2/cmd/gosec@latest
	@command -v goreleaser 2>&1 > /dev/null    || go install github.com/goreleaser/goreleaser@latest

clean:
	rm -rf ./dist

tidy:
	@for module in $(MODULES); do \
		echo "==> tidy $$module"; \
		(cd $$module && $(GO_CMD) mod tidy) || exit 1; \
	done

fmt:
	$(GO_CMD)fmt -w $(GOFMT_FILES)

lint:
	@for module in $(MODULES); do \
		echo "==> lint $$module"; \
		(cd $$module && golangci-lint run) || exit 1; \
	done

security:
	@for module in $(MODULES); do \
		echo "==> security $$module"; \
		(cd $$module && gosec -exclude-dir _local -quiet ./...) || exit 1; \
	done

# The root module keeps its 60s budget, most of which pkg/http spends on real
# retry backoff. The cluster module gets its own, because it starts real gossip
# clusters and waits for them to converge.
test:
	$(GO_CMD) test -v -timeout 60s -coverprofile=cover.out -cover $(TEST)
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

docs-deploy:
	@echo "Deploying documentation to GitHub Pages..."
	@command -v mkdocs >/dev/null 2>&1 || (echo "Error: mkdocs not found. Install with: pip install mkdocs-material mkdocs-git-revision-date-localized-plugin" && exit 1)
	@mkdocs gh-deploy --force
