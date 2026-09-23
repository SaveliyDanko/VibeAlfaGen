.DEFAULT_GOAL := admin-up
.PHONY: admin-up admin-down admin-logs compose-certs compose-up build run mock-llm load
GO ?= go
CONFIG ?= config.example.yaml

admin-up:
	./scripts/admin-compose.sh up
admin-down:
	./scripts/admin-compose.sh down
admin-logs:
	./scripts/admin-compose.sh logs
compose-certs:
	./scripts/generate-mtls.sh
compose-up: compose-certs
	docker compose up -d --build --wait
build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/proxy ./cmd/proxy
	$(GO) build -trimpath -o bin/admin ./cmd/admin
	$(GO) build -trimpath -o bin/mock-client ./cmd/mock-client
	$(GO) build -trimpath -o bin/mock-llm ./cmd/mock-llm
run:
	$(GO) run ./cmd/proxy -config $(CONFIG)
mock-llm:
	$(GO) run ./cmd/mock-llm
load:
	$(GO) run ./cmd/mock-client -url http://127.0.0.1:8080/process
