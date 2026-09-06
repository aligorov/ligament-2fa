.PHONY: build test lint docker e2e

build:
	go build -ldflags "-X main.BuildDate=$(shell date +%F)" -o twofa ./cmd/twofa

test:
	go test ./...

lint:
	go vet ./...

docker:
	docker build --build-arg BUILD_DATE=$(shell date +%F) -t twofa:latest .

# E2E-сценарий: testcontainer PostgreSQL + HTTP + RADIUS (нужен Docker).
e2e:
	go test -tags integration ./internal/e2e/ -v -timeout 300s
