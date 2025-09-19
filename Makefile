APP=token-gateway

.PHONY: run build tidy test lint

run:
	go run ./cmd/gateway

build:
	go build -o bin/$(APP) ./cmd/gateway

tidy:
	go mod tidy

test:
	go test ./...

lint:
	golangci-lint run
