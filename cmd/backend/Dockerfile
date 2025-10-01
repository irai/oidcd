# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/backend ./cmd/backend

FROM alpine:3.19
RUN addgroup -S backend && adduser -S backend -G backend
WORKDIR /app
COPY --from=build /out/backend /usr/local/bin/backend
USER backend
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/backend"]
