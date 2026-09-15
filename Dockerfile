# Build stage — only the Go toolchain, no external services.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
# VERSION defaults to "dev" for local/unreleased builds; the release
# workflow passes the release tag (e.g. v0.1.0) as a build arg.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X github.com/prampec/trustmate/internal/version.Version=${VERSION}" -o /out/trustmated ./cmd/trustmated

# Runtime stage — scratch: nothing but the static binary and CA certs
# (needed for any future outbound TLS, e.g. a cloud KMS keystore backend).
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/trustmated /trustmated
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/trustmated"]
