BINARY := bin/restricted-access

.PHONY: all build test test-race fmt tidy

all: build

build:
	go build -trimpath -ldflags "-s -w" -o $(BINARY) ./cmd/restricted-access

test:
	go test ./...

test-race:
	go test -race ./...

fmt:
	gofmt -w cmd internal

tidy:
	go mod tidy
