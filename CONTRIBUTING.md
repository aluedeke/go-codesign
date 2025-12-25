# Contributing to go-codesign

Thank you for your interest in contributing to go-codesign! This document provides guidelines and instructions for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/go-codesign.git`
3. Create a branch: `git checkout -b feature/your-feature-name`

## Development Setup

### Prerequisites

- Go 1.21 or later
- Make (optional, for using Makefile commands)

### Building

```bash
make build
# or
go build -o build/go-codesign .
```

### Running Tests

```bash
make test
# or
go test ./...
```

Test data (WebDriverAgent) is downloaded automatically on first test run.

## Making Changes

### Code Style

- Follow standard Go conventions and idioms
- Run `go fmt` before committing
- Run `go vet` to catch common issues
- Use `golangci-lint` for comprehensive linting (if configured)

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb in present tense (e.g., "Add", "Fix", "Update")
- Keep the first line under 72 characters
- Reference issues when applicable (e.g., "Fix #123")

Example:
```
Add support for wildcard bundle IDs

- Parse wildcard patterns from provisioning profiles
- Match app bundle IDs against wildcard patterns
- Add tests for wildcard matching

Fixes #42
```

### Pull Requests

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass
4. Update the README if adding new features
5. Submit a pull request with a clear description

## Testing

### Unit Tests

Unit tests are in `*_test.go` files alongside the code they test.

```bash
go test ./pkg/codesign/...
```

### Integration Tests

Integration tests use WebDriverAgent as a real-world test app:

```bash
make test
```

### Device Testing

To test on a real iOS device:

```bash
# Set environment variables
export CODESIGN_P12=/path/to/certificate.p12
export CODESIGN_PROFILE=/path/to/profile.mobileprovision
export CODESIGN_PASSWORD=your-password

# Run the WDA test
make wda-test
```

## Project Structure

```
go-codesign/
├── main.go                 # CLI entry point
├── pkg/codesign/           # Core signing library
│   ├── codesign_native.go  # Code signing implementation
│   ├── entitlements.go     # Entitlements handling
│   ├── resources.go        # CodeResources generation
│   ├── profile.go          # Provisioning profile parsing
│   └── *_test.go           # Tests
├── Makefile
├── README.md
├── CONTRIBUTING.md
└── LICENSE
```

## Reporting Issues

When reporting issues, please include:

1. Go version (`go version`)
2. Operating system and version
3. Steps to reproduce
4. Expected behavior
5. Actual behavior
6. Any error messages or logs

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Feel free to open an issue for questions or discussions about the project.
