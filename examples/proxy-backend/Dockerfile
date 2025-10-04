FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY examples/proxy-backend/main.go .
RUN go mod init proxy-backend && \
    go build -o proxy-backend main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /build/proxy-backend /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/proxy-backend"]
