.PHONY: build test test-race lint run clean

BIN := bin/netprobe-mcp
CONFIG := configs/policy.example.yaml

build:
	mkdir -p bin
	go build -o $(BIN) ./cmd/netprobe-mcp

test:
	go test -count=1 ./...

test-race:
	go test -race -count=1 ./...

fuzz:
	go test -fuzz=FuzzNormalizeHost -fuzztime=10s ./internal/security/

lint:
	go vet ./...

run: build
	./$(BIN) --config=$(CONFIG)

clean:
	rm -rf bin