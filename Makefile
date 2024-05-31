# Define the Go commands
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOFMT := $(GOCMD) fmt
GOVET := $(GOCMD) vet
BINARY_NAME := glsa-oval

# All source files
SRC := $(shell find . -type f -name '*.go')

# Default target
all: test build

# Build the binary for Linux AMD64
build-linux-amd64: $(SRC)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)-linux-amd64 -v

# Build the binary for Linux ARM64
build-linux-arm64: $(SRC)
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BINARY_NAME)-linux-arm64 -v

# Build the binary for Windows AMD64
build-windows-amd64: $(SRC)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)-windows-amd64.exe -v

# Run tests
test:
	$(GOTEST) -v ./...

# Format the code
fmt:
	$(GOFMT) ./...

# Vet the code
vet:
	$(GOVET) ./...

# Clean the directory
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)-*

# Install dependencies
deps:
	$(GOCMD) mod tidy

# Show help
help:
	@echo "Makefile commands:"
	@echo "  all                 - Format, vet, test, and build the project"
	@echo "  build-linux-amd64   - Build the project for Linux AMD64"
	@echo "  build-linux-arm64   - Build the project for Linux ARM64"
	@echo "  build-windows-amd64 - Build the project for Windows AMD64"
	@echo "  test                - Run tests"
	@echo "  fmt                 - Format the code"
	@echo "  vet                 - Vet the code"
	@echo "  clean               - Clean the directory"
	@echo "  deps                - Install dependencies"
	@echo "  help                - Show this help"

# Phony targets
.PHONY: all build-linux-amd64 build-linux-arm64 build-windows-amd64 test fmt vet clean deps help
