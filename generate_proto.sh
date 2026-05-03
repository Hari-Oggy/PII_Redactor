#!/bin/bash
docker run --rm -v "$(pwd):/app" -w /app golang:1.22 bash -c '
apt-get update && apt-get install -y protobuf-compiler && \
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest && \
export PATH=$PATH:$(go env GOPATH)/bin && \
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative sidecar/ner/ner.proto && \
go mod tidy
'
