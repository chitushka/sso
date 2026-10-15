.PHONY: fmt test build docker-build quality

QUALITY_IMAGE ?= sso-quality

fmt:
	gofmt -w ./cmd ./internal

test:
	go test ./...

build:
	go build -o bin/sso-api ./cmd/api

docker-build:
	docker compose build

quality:
	docker build --file Dockerfile.quality --tag $(QUALITY_IMAGE) .
	docker run --rm $(QUALITY_IMAGE)
