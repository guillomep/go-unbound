GO_TEST = go run gotest.tools/gotestsum --format pkgname

LICENCES_IGNORE_LIST = $(shell cat licences/licences-ignore-list.txt)

ifndef $(GOPATH)
    GOPATH=$(shell go env GOPATH)
    export GOPATH
endif

ARTIFACT_NAME = go-unbound

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

show: ## Show variables
	@echo "GOPATH: $(GOPATH)"
	@echo "ARTIFACT_NAME: $(ARTIFACT_NAME)"

##@ Code analysis

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint against code.
	mkdir -p build/reports
	go run github.com/golangci/golangci-lint/cmd/golangci-lint run --timeout 2m

.PHONY: static-analysis
static-analysis: lint vet ## Run static analysis against code.

##@ GO

.PHONY: fmt
fmt: ## Run formating
	go fmt ./...

.PHONY: clean
clean: ## Clean the build directory
	rm -rf ./dist
	rm -rf ./build
	rm -rf ./vendor

.PHONY: build
build: ## Build the binary
	CGO_ENABLED=0 go build -o build/bin/$(ARTIFACT_NAME) ./cmd/webhook

.PHONY: build-linux
build-linux: ## Build the binary for linux
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/bin/$(ARTIFACT_NAME) ./cmd/webhook

.PHONY: run
run:build ## Run the binary on local machine
	build/bin/go-unbound

##@ Test

.PHONY: unit-test
unit-test: ## Run unit tests
	mkdir -p build/reports
	$(GO_TEST) --junitfile build/reports/unit-test.xml -- -race ./... -count=1 -short -cover -coverprofile build/reports/unit-test-coverage.out

##@ Release

.PHONY: release-check
release-check: ## Check if the release will work
	GITHUB_SERVER_URL=github.com GITHUB_REPOSITORY=guillomep/go-unbound goreleaser release --snapshot --clean --skip=publish

##@ License

.PHONY: license-check
license-check: ## Run go-licenses check against code.
	go install github.com/google/go-licenses
	mkdir -p build/reports
	echo "$(LICENCES_IGNORE_LIST)"
	$(GOPATH)/bin/go-licenses check --include_tests --ignore "$(LICENCES_IGNORE_LIST)" ./...

.PHONY: license-report
license-report: ## Create licenses report against code.
	go install github.com/google/go-licenses
	mkdir -p build/reports/licenses
	$(GOPATH)/bin/go-licenses report --include_tests --ignore "$(LICENCES_IGNORE_LIST)" ./... >build/reports/licenses/licenses-list.csv
	cat licences/licenses-manual-list.csv >> build/reports/licenses/licenses-list.csv
