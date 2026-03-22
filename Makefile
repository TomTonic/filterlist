MODULE   := github.com/tomtonic/coredns-regfilter
GO       := go
GOTEST   := $(GO) test
GOLINT   := golangci-lint
BINARY   := regfilter-check
BUILD_DIR:= build

.PHONY: all build test test-race lint vet fmt clean cover bench

all: lint test build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/$(BINARY) ./cmd/regfilter-check

test:
	$(GOTEST) ./... -count=1

test-race:
	$(GOTEST) ./... -race -count=1

lint:
	$(GOLINT) run ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .
	goimports -w .

cover:
	$(GOTEST) ./... -race -coverprofile=coverage.out -covermode=atomic
	$(GO) tool cover -html=coverage.out -o coverage.html

bench:
	$(GOTEST) -bench=. -benchmem ./pkg/automaton/ ./pkg/filterlist/

clean:
	rm -rf $(BUILD_DIR) coverage.out coverage.html
