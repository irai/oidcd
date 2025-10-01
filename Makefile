APP=token-gateway

.PHONY: run build tidy test lint

run:
	go run .

build:
	go build -o bin/$(APP) .

tidy:
	go mod tidy

test:
	go test ./...

lint:
	golangci-lint run
