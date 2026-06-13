.PHONY: fmt test build docker-build
fmt:
	gofmt -w ./cmd ./internal

test:
	go test ./...

build:
	go build -o bin/sso-api ./cmd/api

docker-build:
	docker compose build
