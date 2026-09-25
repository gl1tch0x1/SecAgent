.PHONY: all build test clean dev

all: build

# --- Build ---
build: build-rust build-go build-cpp build-python

build-cpp:
	cmake -B cpp-core/build -S cpp-core && cmake --build cpp-core/build

build-rust:
	cd rust-core && cargo build --release

build-go:
	cd go-services/recon && go build ./...
	cd go-services/scanners && go build ./...
	cd go-services/cli && go build -o bin/secagents-cli ./cmd

build-python:
	cd python-agents && pip install -e .

# --- Test ---
test: test-rust test-go test-cpp test-python

test-cpp:
	ctest --test-dir cpp-core/build --output-on-failure

test-rust:
	cd rust-core && cargo test

test-go:
	cd go-services && go test ./recon/... ./scanners/... ./cli/...

test-python:
	pytest tests/unit/

# --- Docker ---
docker-up:
	docker compose up -d

docker-down:
	docker compose down

# --- Clean ---
clean:
	cd rust-core && cargo clean
	cd go-services/recon && go clean
