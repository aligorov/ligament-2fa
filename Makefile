.PHONY: build test lint

build:
	go build -o twofa ./cmd/twofa

test:
	go test ./...

lint:
	go vet ./...
