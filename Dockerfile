# Build Stage
FROM golang:alpine AS builder

WORKDIR /app

# Copy module files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o linuxguard ./cmd/linuxguard

# Final Production Stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata bash

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/linuxguard /usr/local/bin/linuxguard
COPY --from=builder /app/configs/linuxguard.example.yaml /etc/linuxguard/config.yaml

# Expose default HTTP/WebSocket Dashboard port
EXPOSE 9876

ENTRYPOINT ["/usr/local/bin/linuxguard"]
CMD ["--config", "/etc/linuxguard/config.yaml"]
