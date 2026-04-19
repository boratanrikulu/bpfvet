.PHONY: all build test lint fmt clean

all: build

build:
	go build -o bin/bpfvet ./cmd/bpfvet

test:
	go test -race -timeout 60s ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

clean:
	rm -rf bin/
