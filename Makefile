# PII Redactor Gateway — Makefile

GO := go
BINARY := pii-gateway
CMD := ./cmd/gateway

.PHONY: build run test test-race lint clean docker

## Build the gateway binary
build:
	$(GO) build -o $(BINARY).exe $(CMD)

## Run the gateway with default config
run:
	$(GO) run $(CMD) --config config.yaml

## Run all tests
test:
	$(GO) test ./... -v

## Run all tests with race detector
test-race:
	$(GO) test -race ./...

## Run benchmarks
bench:
	$(GO) test ./test/benchmark/ -bench=. -benchmem

## Run linter (requires golangci-lint)
lint:
	golangci-lint run ./...

## Clean build artifacts
clean:
	@if exist $(BINARY).exe del $(BINARY).exe

## Build Docker image
docker:
	docker build -t pii-gateway:latest .
