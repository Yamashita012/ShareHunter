#!/usr/bin/env sh
set -eu
go mod tidy
go test ./...
go build -trimpath -ldflags="-s -w" -o sharehunter ./cmd/sharehunter
