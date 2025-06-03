.PHONY: all build clean test install run

BINARY_NAME=macos-persist-scan
MAIN_PATH=cmd/macos-persist-scan/main.go

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) $(MAIN_PATH)

clean:
	@echo "Cleaning..."
	go clean
	rm -f $(BINARY_NAME)

test:
	@echo "Running tests..."
	go test -v ./...

install:
	@echo "Installing $(BINARY_NAME)..."
	go install $(MAIN_PATH)

run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BINARY_NAME) scan

run-json: build
	@echo "Running $(BINARY_NAME) with JSON output..."
	./$(BINARY_NAME) scan -o json

deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Build for multiple architectures
build-all:
	@echo "Building for multiple architectures..."
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_NAME)-darwin-amd64 $(MAIN_PATH)
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_NAME)-darwin-arm64 $(MAIN_PATH)

# Create universal binary
universal: build-all
	@echo "Creating universal binary..."
	lipo -create -output $(BINARY_NAME) $(BINARY_NAME)-darwin-amd64 $(BINARY_NAME)-darwin-arm64
	rm $(BINARY_NAME)-darwin-amd64 $(BINARY_NAME)-darwin-arm64