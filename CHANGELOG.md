# Changelog

## [0.0.3](https://github.com/aluedeke/go-codesign/compare/v0.0.2...v0.0.3) (2025-12-27)


### Bug Fixes

* specify jsonpath for npm/package.json version updates ([753fbb1](https://github.com/aluedeke/go-codesign/commit/753fbb145e469e53222fe386defd1ce80ffa5f19))
* use OIDC trusted publisher for npm and fix version ([d6d3b62](https://github.com/aluedeke/go-codesign/commit/d6d3b62bf0d35dd519811cf29aa1a73956ba54f4))

## [0.0.2](https://github.com/aluedeke/go-codesign/compare/v0.0.1...v0.0.2) (2025-12-27)


### Bug Fixes

* **ci:** use bash shell for Windows test step
* fix all golangci-lint errors and update to v2 config
* normalize paths to forward slashes for cross-platform compatibility
* fix ZIP path validation for Windows compatibility
* fix nested bundle depth counting for cross-platform compatibility

## [0.0.1](https://github.com/aluedeke/go-codesign/releases/tag/v0.0.1) (2025-12-26)

Initial release.

### Features

* Pure Go iOS code signing implementation
* IPA and .app bundle resigning
