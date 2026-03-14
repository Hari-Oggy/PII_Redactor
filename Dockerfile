# ==============================================================================
# Stage 1: Build
# ==============================================================================
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /pii-gateway ./cmd/gateway

# ==============================================================================
# Stage 2: Runtime (distroless for minimal attack surface)
# ==============================================================================
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /pii-gateway /pii-gateway
COPY config.yaml /config.yaml

EXPOSE 8080 9090

ENTRYPOINT ["/pii-gateway", "--config", "/config.yaml"]
