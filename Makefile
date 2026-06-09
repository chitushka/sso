APP_NAME=sso-api

.PHONY: run test build docker-up docker-down migrate-up

run:
	go run ./cmd/api

test:
	go test ./...

build:
	mkdir -p bin
	go build -o bin/$(APP_NAME) ./cmd/api

docker-up:
	docker compose up --build

docker-down:
	docker compose down -v

migrate-up:
	psql "$${DATABASE_URL}" -f migrations/000001_init.up.sql
