BINARY := bin/kavach
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all build dist fmt-check test lint selftest frames e2e-live clean

all: build test lint selftest

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/kavach

# Release archives for every supported platform, plus checksums.txt.
# Each platform is staged in build/<name>/ (overwritten on the next run) and packed into dist/.
PLATFORMS := darwin/arm64 darwin/amd64 linux/arm64 linux/amd64
dist:
	@mkdir -p dist build
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; name=kavach_$(VERSION)_$${os}_$${arch}; \
		echo "Building $$name"; \
		mkdir -p build/$$name; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o build/$$name/kavach ./cmd/kavach || exit 1; \
		cp LICENSE README.md build/$$name/; \
		tar -C build -czf dist/$$name.tar.gz $$name || exit 1; \
	done
	@cd dist && (shasum -a 256 kavach_$(VERSION)_*.tar.gz 2>/dev/null || sha256sum kavach_$(VERSION)_*.tar.gz) > checksums.txt
	@cat dist/checksums.txt

fmt-check:
	@test -z "$$(gofmt -l cmd internal)" || (echo "Run gofmt on:"; gofmt -l cmd internal; exit 1)

test:
	go test -race ./...

lint:
	golangci-lint run

selftest: build
	./$(BINARY) selftest

frames: build
	@mkdir -p docs/frames
	@for tape in docs/tapes/*.tape; do \
		echo "Rendering $$tape..."; \
		VHS_NO_SANDBOX=1 PATH="$(CURDIR)/bin:$$PATH" vhs "$$tape"; \
	done

# Optional live test: consumes a few real Anthropic API tokens via `claude -p`.
e2e-live: build
	./scripts/e2e_live.sh "$(CURDIR)/$(BINARY)"

clean:
	rm -rf bin dist build
