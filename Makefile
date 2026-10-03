BINARY := agent-okta-d

.PHONY: build test lint fmt vet

build:
	go build -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .
