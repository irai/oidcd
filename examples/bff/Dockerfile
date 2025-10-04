# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/bff ./examples/bff

FROM alpine:3.19
RUN addgroup -S bff && adduser -S bff -G bff
WORKDIR /app
COPY --from=build /out/bff /usr/local/bin/bff
USER bff
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/bff"]
