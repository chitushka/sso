#!/bin/sh
set -eu

unformatted="$(gofmt -l ./cmd ./internal)"
if [ -n "$unformatted" ]; then
    echo "Требуется gofmt для:"
    echo "$unformatted"
    exit 1
fi

go vet ./...
go test ./...
CGO_ENABLED=1 go test -race ./...
govulncheck ./...
golangci-lint run
