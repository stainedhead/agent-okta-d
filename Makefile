BINARY := agent-okta-d
PKG    := github.com/stainedhead/agent-okta-d
VERSION ?= 0.0.0-dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT) -X $(PKG)/internal/version.Date=$(DATE)
TARGETS := darwin/arm64 linux/amd64 linux/arm64

.PHONY: build test lint fmt vet cover cross check

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

# Coverage gate: >= 80 % for every internal/ package, >= 90 % for pkg/client
# (packages without statements or without tests yet, and the storetest helper, are skipped).
cover:
	@go test -race -cover ./internal/... ./pkg/... | awk '\
	  /storetest/ { next } \
	  /coverage:/ { pct=$$0; sub(/.*coverage: /,"",pct); sub(/%.*/,"",pct); pkg=$$2; \
	    min=(pkg ~ /pkg\/client/)?90:80; print; if (pct+0 < min) { bad=1; print "  below " min "%: " pkg } } \
	  /FAIL/ { bad=1; print } \
	  END { exit bad }'

# Cross-compile every release target (BLD-3). Darwin may need cgo for Keychain
# code, so build it on a mac runner; here CGO is left at the Go default.
cross:
	@set -e; for t in $(TARGETS); do \
	  os=$${t%/*}; arch=$${t#*/}; echo "build $$os/$$arch"; \
	  GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build ./... ; \
	done

# Everything CI runs, locally.
check: fmt vet lint test cover cross
