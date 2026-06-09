APP_NAME := sendpcap
BUILD_DIR := build
MAIN_PATH := ./cmd

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -s -w

# Default target
.PHONY: all
all: build

# Build for all platforms
.PHONY: build
build: build-amd64 build-arm64 build-arm

# Linux x86_64
.PHONY: build-amd64
build-amd64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 $(MAIN_PATH)
	@echo "Built: $(BUILD_DIR)/$(APP_NAME)-linux-amd64"

# Linux ARM64 (aarch64)
.PHONY: build-arm64
build-arm64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 $(MAIN_PATH)
	@echo "Built: $(BUILD_DIR)/$(APP_NAME)-linux-arm64"

# Linux ARM (armv7, 32-bit)
.PHONY: build-arm
build-arm:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)-linux-armv7 $(MAIN_PATH)
	@echo "Built: $(BUILD_DIR)/$(APP_NAME)-linux-armv7"

# Package binaries into tar.gz
.PHONY: package
package: build
	tar czf $(BUILD_DIR)/$(APP_NAME)-$(VERSION).tar.gz -C $(BUILD_DIR) \
		$(APP_NAME)-linux-amd64 \
		$(APP_NAME)-linux-arm64 \
		$(APP_NAME)-linux-armv7 \
	-C $(CURDIR) pcaps 
	@echo "Packaged: $(BUILD_DIR)/$(APP_NAME)-$(VERSION).tar.gz"

# Run tests
.PHONY: test
test:
	go test -v ./...

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

# Show help
.PHONY: help
help:
	@echo "Targets:"
	@echo "  build        Build for all platforms (amd64, arm64, armv7)"
	@echo "  build-amd64  Build for Linux x86_64"
	@echo "  build-arm64  Build for Linux ARM64 (aarch64)"
	@echo "  build-arm    Build for Linux ARMv7 (32-bit)"
	@echo "  package      Build all and package into tar.gz"
	@echo "  test         Run tests"
	@echo "  clean        Remove build artifacts"
