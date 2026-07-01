#
# Build context is the PARENT of auth/ and ledger/, because auth/go.mod has
# `replace github.com/nvsces/ledger => ../ledger` and needs the sibling ledger
# module present at build time.
#
#   docker build -f auth/Dockerfile -t serviceconstructor-auth:latest .
#
FROM golang:1.25-alpine AS build
WORKDIR /src

COPY ledger/ ./ledger/
COPY auth/ ./auth/

WORKDIR /src/auth
RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/auth ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/auth /auth
# gRPC :9200, HTTP gateway :8090 (see internal/config/config.go defaults).
EXPOSE 8090 9200
USER nonroot:nonroot
ENTRYPOINT ["/auth"]
