VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_SIG  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w -X main.version=$(VERSION) -X main.buildSig=$(BUILD_SIG)
IMAGE      ?= ghcr.io/the-dot-squad/netsurveil-tester
PLATFORMS  ?= linux/amd64,linux/arm64
E2E        := docker compose -f test/e2e/docker-compose.e2e.yml -p nst-e2e

GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
GOVULNCHECK   := go run golang.org/x/vuln/cmd/govulncheck@v1.8.0

# Minimum total statement coverage of ./internal/... enforced by `make cover`.
# Most check code runs only in e2e; raise this as unit coverage grows.
COVER_MIN ?= 45
FUZZTIME  ?= 15s
# package:FuzzFunc pairs run by `make fuzz`.
FUZZ := internal/envelope:FuzzOpen internal/api:FuzzOpenRequest internal/config:FuzzParseSecret \
	internal/check:FuzzParseDNSResponse internal/check:FuzzParseQuoted

.PHONY: build test vet lint vuln cover fuzz ci vectors docker e2e e2e-down clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/nst-node ./cmd/nst-node

test:
	go test -race ./...

vet:
	go vet ./...
	go vet -tags e2e ./test/e2e/...

lint:
	$(GOLANGCI_LINT) run ./...

vuln:
	$(GOVULNCHECK) ./...

cover:
	go test -race -covermode=atomic -coverprofile=coverage.out ./internal/...
	@go tool cover -func=coverage.out | awk -v min=$(COVER_MIN) '/^total:/ { sub("%", "", $$3); printf "coverage %s%% (floor %s%%)\n", $$3, min; if ($$3 + 0 < min) exit 1 }'

fuzz:
	@set -e; for t in $(FUZZ); do \
		echo "fuzz $$t"; go test ./$${t%%:*} -run '^$$' -fuzz "^$${t##*:}$$" -fuzztime $(FUZZTIME); \
	done

# Everything CI runs except docker and e2e.
ci: vet lint test cover vuln build

# Regenerates docs/testvectors.json from the envelope implementation.
vectors:
	go test ./internal/envelope -run TestVectors -update

# Builds for the local platform and loads the image; PLATFORMS applies with PUSH=1.
docker:
	docker buildx build \
		--build-arg VERSION=$(VERSION) --build-arg BUILD_SIG=$(BUILD_SIG) --build-arg BUILD_DATE=$(BUILD_DATE) \
		$(if $(PUSH),--platform $(PLATFORMS) --push,--load) -t $(IMAGE):$(VERSION) .

e2e:
	$(E2E) up --build --abort-on-container-exit --exit-code-from e2e; rc=$$?; $(E2E) down -v --remove-orphans; exit $$rc

e2e-down:
	$(E2E) down -v --remove-orphans

clean:
	rm -rf bin dist coverage.out
