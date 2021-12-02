# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

GOLANGCI_VERSION=v1.42.0
export GO111MODULE := on

.PHONY: setupgolangcilint
setupgolangcilint:  ## Install golangci-lint
	@echo "==> Installing golangci-lint..."
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s $(GOLANGCI_VERSION)

.PHONY: deps
deps:  ## Download go module dependencies
	@echo "==> Installing go.mod dependencies..."
	go mod download
	go mod tidy

.PHONY: setup
setup: deps setupgolangcilint ## Set up dev env
	@echo "==> Installing dev tools..."
	go install github.com/google/addlicense@latest
	go install github.com/golang/mock/mockgen@latest
	go install golang.org/x/tools/cmd/goimports@latest

.PHONY: link-git-hooks
link-git-hooks: ## Install git hooks
	@echo "==> Installing all git hooks..."
	find .git/hooks -type l -exec rm {} \;
	find .githooks -type f -exec ln -sf ../../{} .git/hooks/ \;

.PHONY: fmt
fmt: ## Format changed go
	@scripts/fmt.sh

.PHONY: lint
lint: ## Run linter
	@echo "==> Linting all packages..."
	golangci-lint run

.PHONY: fix-lint
fix-lint: ## Fix linting errors
	@echo "==> Fixing lint errors"
	golangci-lint run --fix