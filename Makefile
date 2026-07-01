GOBIN := $(shell go env GOPATH)/bin
export PATH := $(PATH):$(GOBIN)

.PHONY: tools generate tidy build run test

# Install codegen plugins pinned alongside the module.
tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest

generate:
	buf generate --path proto/auth

tidy:
	go mod tidy

build:
	go build -o bin/server ./cmd/server

run:
	go run ./cmd/server

test:
	go test ./...
