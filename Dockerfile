# Builder stage
FROM golang:1.20-alpine AS builder

WORKDIR /src

# Install git (if modules need fetching) and ca-certificates for build
RUN apk add --no-cache git ca-certificates

COPY go.mod .
COPY main.go .

# Copy static web files into the image for embedding in the final image
COPY index.html /src/index.html
COPY img /src/img

# Prepare logs dir so it gets copied into final image
RUN mkdir -p /logs && touch /logs/access.log && chmod 0644 /logs/access.log

# Build static binary
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w" -o /app/server ./

# Final stage: minimal runtime
FROM scratch

# Copy CA certs (if needed) and the static files
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /app/server /server
COPY --from=builder /src/index.html /static/index.html
COPY --from=builder /src/img /static/img
# Copy prepared logs directory
COPY --from=builder /logs /logs

# Default env (can be overridden)
ENV ACCESS_LOG_FILE=/logs/access.log
ENV ANONYMIZE_IP=true

VOLUME ["/logs"]

EXPOSE 80
ENTRYPOINT ["/server"]
