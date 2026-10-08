FROM golang:1.27-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY test ./test
RUN go build -trimpath -o /out/targetsrv ./test/fixtures/targetsrv \
 && go test -c -tags e2e -o /out/e2e.test ./test/e2e

FROM gcr.io/distroless/static-debian12:nonroot AS targetsrv
COPY --from=build /out/targetsrv /targetsrv
ENTRYPOINT ["/targetsrv"]

FROM gcr.io/distroless/static-debian12:nonroot AS e2e
COPY --from=build /out/e2e.test /e2e.test
ENTRYPOINT ["/e2e.test", "-test.v", "-test.timeout=10m"]

FROM alpine:3.24 AS censor
RUN apk add --no-cache iptables iproute2
COPY test/e2e/censor.sh /censor.sh
ENTRYPOINT ["/bin/sh", "/censor.sh"]
