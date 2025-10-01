# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/token-gateway ./cmd/gateway

FROM alpine:3.19
RUN addgroup -S gateway && adduser -S gateway -G gateway
WORKDIR /app
COPY --from=build /out/token-gateway /usr/local/bin/token-gateway
COPY config.example.yaml /app/config.yaml
USER gateway
EXPOSE 8080 8443 80 443
ENTRYPOINT ["/usr/local/bin/token-gateway", "-config", "/app/config.yaml"]
