# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/oidc-client ./examples/client

FROM alpine:3.19
RUN addgroup -S client && adduser -S client -G client
WORKDIR /app
COPY --from=build /out/oidc-client /usr/local/bin/oidc-client
USER client
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/oidc-client"]
