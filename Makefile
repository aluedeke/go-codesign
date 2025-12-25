.PHONY: build clean test install testdata clean-testdata wda-test

# Build configuration
BUILD_DIR := build
BINARY_NAME := go-codesign
WDA_APP := pkg/codesign/testdata/WebDriverAgentRunner-Runner.app
WDA_RESIGNED := /tmp/wda-go-codesign/WebDriverAgentRunner-Runner.app

# Build the binary
build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME)"

# Run tests
test:
	go test ./...

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned build directory"

# Install to GOPATH/bin
install:
	go install .

# Build with version info (optional)
build-release:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Built release binary: $(BUILD_DIR)/$(BINARY_NAME)"

# Download test data (WDA is downloaded automatically on first test run)
testdata:
	@echo "Test data will be downloaded automatically when running tests"
	go test ./pkg/codesign/... -run TestGenerateCodeResources_Files -v

# Clean test data cache
clean-testdata:
	rm -rf pkg/codesign/testdata/
	@echo "Cleaned test data"

# Resign WDA with go-codesign, install on device, and launch
# Requires: CODESIGN_P12, CODESIGN_PROFILE, CODESIGN_PASSWORD environment variables
# Uses go-ios for install and launch (must be installed: brew install go-ios)
wda-test: build testdata
	@echo "=== Resigning WDA with go-codesign ==="
	@if [ -z "$$CODESIGN_P12" ] || [ -z "$$CODESIGN_PROFILE" ]; then \
		echo "Error: Set CODESIGN_P12 and CODESIGN_PROFILE environment variables"; \
		echo "Example: source .env && make wda-test"; \
		exit 1; \
	fi
	@rm -rf /tmp/wda-go-codesign
	@mkdir -p /tmp/wda-go-codesign
	@cp -R $(WDA_APP) $(WDA_RESIGNED)
	$(BUILD_DIR)/$(BINARY_NAME) resign \
		--app=$(WDA_RESIGNED) \
		--p12=$$CODESIGN_P12 \
		--profile=$$CODESIGN_PROFILE \
		--password=$$CODESIGN_PASSWORD \
		--inplace
	@echo ""
	@echo "=== Installing WDA on device ==="
	ios install --path=$(WDA_RESIGNED)
	@echo ""
	@echo "=== Launching WDA ==="
	ios runwda
