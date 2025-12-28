# go-codesign

[![CI](https://github.com/aluedeke/go-codesign/actions/workflows/ci.yml/badge.svg)](https://github.com/aluedeke/go-codesign/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/aluedeke/go-codesign.svg)](https://pkg.go.dev/github.com/aluedeke/go-codesign)
[![npm](https://img.shields.io/npm/v/go-codesign)](https://www.npmjs.com/package/go-codesign)
[![Run with npx](https://img.shields.io/badge/run-npx%20go--codesign-brightgreen)](https://www.npmjs.com/package/go-codesign)


> **Alpha Status**: This project is in early development. The API may change, and there may be bugs or missing features. Use at your own risk and please report any issues you encounter.

A pure Go implementation for iOS code signing. Resign IPA files and `.app` bundles with new certificates and provisioning profiles without requiring Apple's `codesign` tool or macOS.

## Features

- **Cross-platform**: Works on Linux, macOS, and Windows
- **No dependencies on Apple tools**: Pure Go implementation of code signing
- **IPA and .app support**: Resign both IPA files and extracted `.app` bundles
- **Nested bundle signing**: Automatically signs frameworks, plugins, and extensions
- **Bundle ID modification**: Change the app's bundle identifier during resign
- **Signature inspection**: View detailed code signature information
- **Signature comparison**: Compare signatures between two apps

## Installation

### Via npm/npx (easiest)

```bash
npx go-codesign --help
```

Or install globally:

```bash
npm install -g go-codesign
```

### Via Go

```bash
go install github.com/aluedeke/go-codesign@latest
```

### Build from repository

```bash
git clone https://github.com/aluedeke/go-codesign.git
cd go-codesign
make build
```

The binary will be available at `build/go-codesign`.

## Quick Start

### Resign an IPA

```bash
go-codesign resign \
  --app=MyApp.ipa \
  --p12=certificate.p12 \
  --profile=profile.mobileprovision \
  --password=your-p12-password
```

This creates `MyApp-resigned.ipa` with the new signature.

### Resign a .app bundle

```bash
go-codesign resign \
  --app=MyApp.app \
  --p12=certificate.p12 \
  --profile=profile.mobileprovision \
  --password=your-p12-password
```

### Using environment variables

For CI/CD pipelines, you can use environment variables instead of command-line flags:

```bash
export CODESIGN_P12=/path/to/certificate.p12
export CODESIGN_PROFILE=/path/to/profile.mobileprovision
export CODESIGN_PASSWORD=your-p12-password

go-codesign resign --app=MyApp.ipa
```

## Commands

### resign

Resign an IPA file or `.app` bundle with a new signing identity.

```bash
go-codesign resign --app=<path> [options]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--app=<path>` | Path to the input `.ipa` file or `.app` bundle (required) |
| `--p12=<path>` | Path to the P12 certificate file |
| `--profile=<path>` | Path to the provisioning profile |
| `--password=<password>` | Password for the P12 certificate |
| `--output=<path>` | Output path (defaults to `<input>-resigned.<ext>`) |
| `--bundleid=<id>` | New bundle ID to apply |
| `--inplace` | Sign `.app` bundle in-place (modifies original) |

### info

Display information about an app or provisioning profile.

```bash
# View app information
go-codesign info --app=MyApp.ipa

# View provisioning profile
go-codesign info --profile=dev.mobileprovision

# View detailed signature information
go-codesign info --app=MyApp.app --signature

# Include nested bundles
go-codesign info --app=MyApp.app --signature --recursive
```

### diff

Compare code signatures between two apps.

```bash
go-codesign diff --app1=App1.app --app2=App2.app

# Include nested bundles
go-codesign diff --app1=App1.app --app2=App2.app --recursive
```

## Requirements

To resign an iOS app, you need:

1. **P12 Certificate**: A PKCS#12 file containing your signing certificate and private key
2. **Provisioning Profile**: A `.mobileprovision` file that includes:
   - Your signing certificate
   - The app's bundle identifier (or a wildcard)
   - Device UDIDs (for development/ad-hoc profiles)

### Obtaining signing credentials

1. **Apple Developer Account**: Register at [developer.apple.com](https://developer.apple.com)
2. **Create a certificate**: In the Apple Developer portal, create a development or distribution certificate
3. **Export as P12**: Export the certificate with its private key from Keychain Access (macOS) or your certificate manager
4. **Create provisioning profile**: Create a profile that matches your certificate and target devices

## Examples

### Change bundle ID during resign

```bash
go-codesign resign \
  --app=MyApp.ipa \
  --p12=cert.p12 \
  --profile=profile.mobileprovision \
  --password=secret \
  --bundleid=com.example.newapp
```

### Inspect an app's signature

```bash
go-codesign info --app=MyApp.app --signature --recursive
```

Output includes:
- Bundle identifier
- Team ID
- Code directory hashes (SHA-1 and SHA-256)
- Entitlements
- Embedded provisioning profile details

### Compare two app signatures

```bash
go-codesign diff --app1=original.app --app2=resigned.app --recursive
```

## Development

### Prerequisites

- Go 1.21 or later

### Building

```bash
make build        # Build the binary
make test         # Run tests
make clean        # Clean build artifacts
```

### Testing with WebDriverAgent

The project includes integration tests using WebDriverAgent. Test data is downloaded automatically:

```bash
make test              # Run all tests
make wda-test          # Resign WDA, install on device, and launch
make clean-testdata    # Remove cached test data
```

### Project structure

```
go-codesign/
├── main.go                 # CLI entry point
├── pkg/codesign/           # Core signing library
│   ├── codesign_native.go  # Code signing implementation
│   ├── entitlements.go     # Entitlements handling
│   ├── resources.go        # CodeResources generation
│   ├── profile.go          # Provisioning profile parsing
│   └── ...
├── Makefile
└── README.md
```

## How it works

go-codesign implements Apple's code signing format natively in Go:

1. **Parses Mach-O binaries** to understand the executable structure
2. **Generates CodeResources** plist with SHA-1 and SHA-256 hashes of all bundle files
3. **Creates CodeDirectory** structures with page hashes of the executable
4. **Builds CMS signatures** using the provided P12 certificate
5. **Embeds entitlements** in both XML and DER format
6. **Updates load commands** to include the new signature

The implementation is based on Apple's code signing documentation.

## Limitations

- Does not support code signing for macOS apps (iOS only)
- Requires a valid P12 certificate and provisioning profile
- Cannot create signing certificates (use Apple Developer portal)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

- Special thanks to the author of [zsign](https://github.com/zhlynn/zsign) for their excellent work on iOS code signing, which served as the primary reference for this implementation
- Uses [go-ios](https://github.com/danielpaulus/go-ios) for device testing
