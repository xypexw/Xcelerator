# ==============================================================================
# Xcellator BFF — Multi-Stage Dockerfile
# ==============================================================================
#
# This Dockerfile uses a multi-stage build to produce a minimal production image:
#   Stage 1 (builder): Compiles the Go binary with all dependencies
#   Stage 2 (runner):  Copies only the binary into a minimal Alpine image
#
# Build:  docker build -t xcellator .
# Run:    docker run -p 8081:8081 -e BACKEND_URL=http://peacock-app:8080 xcellator
#
# Environment variables (all optional, with defaults):
#   BACKEND_URL         — PeacockXTR base URL (default: http://peacock-app:8080)
#   REDIS_ADDR          — Redis address (default: redis:6379)
#   REDIS_PASSWORD      — Redis password (default: empty)
#   REDIS_DB            — Redis database number (default: 0)
#   IDEMPOTENCY_TTL_HRS — Idempotency key TTL in hours (default: 24)
#   PORT                — Listen port (default: 8081)
# ==============================================================================

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

# Install git and ca-certificates (needed for go mod download over HTTPS)
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy dependency files first for Docker layer caching
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build a statically linked binary for maximum portability
# CGO_ENABLED=0 ensures no C library dependencies
# -ldflags="-s -w" strips debug info and symbol table for smaller binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /app/xcellator \
    main.go

# ── Stage 2: Production ──────────────────────────────────────────────────────
FROM alpine:3.19

# Install ca-certificates for HTTPS calls to backend & Redis TLS
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user for security
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Copy the compiled binary from builder stage
COPY --from=builder /app/xcellator .

# Set ownership to non-root user
RUN chown -R appuser:appgroup /app

USER appuser

# Expose the BFF port
EXPOSE 8081

# Health check — polls the /health endpoint every 30 seconds
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8081/health || exit 1

# Run the application
ENTRYPOINT ["./xcellator"]

