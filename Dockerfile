# Stage 1: Build the React frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Build the Go binaries
FROM golang:alpine AS go-builder
RUN apk add --no-cache git gcc musl-dev
WORKDIR /src

# Build uwgsocks
COPY --from=uwgsocks-src . /src/userspace-wireguard-socks/
COPY . /src/uwgsocks-ui/
WORKDIR /src/userspace-wireguard-socks
RUN CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o /bin/uwgsocks ./cmd/uwgsocks

# Build uwgkm
WORKDIR /src/uwgsocks-ui/syswg
RUN CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o /bin/uwgkm main.go

# Build uwgsocks-ui
WORKDIR /src/uwgsocks-ui
COPY --from=frontend-builder /app/dist /src/uwgsocks-ui/dist
RUN CGO_ENABLED=1 go build -ldflags="-s -w -extldflags '-static'" -o /bin/uwgsocks-ui .

# Stage 3: Final slim image
FROM scratch
WORKDIR /app

# Copy binaries
COPY --from=go-builder /bin/uwgsocks /app/uwgsocks
COPY --from=go-builder /bin/uwgkm /app/uwgkm
COPY --from=go-builder /bin/uwgsocks-ui /app/uwgsocks-ui

# Copy frontend assets
COPY --from=frontend-builder /app/dist /app/frontend/dist

# Copy CA certs for OIDC/Outbound HTTPS
COPY --from=go-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Create a place for the DB and Unix socket
# (Note: in scratch, you can't chmod, but you can use volumes)
VOLUME ["/app/data"]
EXPOSE 8080 51820/udp

ENTRYPOINT ["/app/uwgsocks-ui"]
CMD ["-listen", "0.0.0.0:8080", "-data-dir", "/app/data", "-wg-url", "unix:///app/data/uwgsocks.sock", "-auto-system"]
