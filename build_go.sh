#!/bin/bash
docker run --rm -v "$(pwd):/app" -w /app golang:latest bash -c "go build -v -o bin/gateway ./cmd/gateway && go test -v ./..."
