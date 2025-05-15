FROM golang:1.20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN make build-linux

# Create final image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates iptables

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/certmitm_unix /app/certmitm

# Create directories for certificates and logs
RUN mkdir -p /app/certs /app/logs

# Expose ports
EXPOSE 8080 8443

# Set entrypoint
ENTRYPOINT ["/app/certmitm"]
