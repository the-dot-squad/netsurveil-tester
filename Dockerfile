# NetSurveil firewall tester node.
# Cross-compiles on the build host for every target platform (docker buildx).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

WORKDIR /src

ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
ARG BUILD_SIG=dev

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
	-ldflags="-s -w -X main.version=${VERSION} -X main.buildSig=${BUILD_SIG}" -o /out/nst-node ./cmd/nst-node

# Root inside the container, but compose drops every capability except
# NET_RAW, which raw ICMP (ping, traceroute) requires.
FROM gcr.io/distroless/static-debian12 AS node
ARG VERSION=dev
ARG BUILD_SIG=dev
ARG BUILD_DATE
LABEL org.opencontainers.image.title="netsurveil-tester" \
	org.opencontainers.image.description="NetSurveil firewall and censorship tester node" \
	org.opencontainers.image.source="https://github.com/the-dot-squad/netsurveil-tester" \
	org.opencontainers.image.licenses="AGPL-3.0-only" \
	org.opencontainers.image.vendor="Payam Foundation" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${BUILD_SIG}" \
	org.opencontainers.image.created="${BUILD_DATE}"
COPY --from=builder /out/nst-node /nst-node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/nst-node", "-healthcheck"]
ENTRYPOINT ["/nst-node"]
