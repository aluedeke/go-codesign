# Changelog

## [0.0.3](https://github.com/aluedeke/go-codesign/compare/v0.0.2...v0.0.3) (2025-12-27)


### Features

* enable auto-merge for release PRs ([a2e6863](https://github.com/aluedeke/go-codesign/commit/a2e6863ed2e420202a585e6f74e0f68d7002921f))


### Bug Fixes

* add checkout step before gh pr merge ([a0696ce](https://github.com/aluedeke/go-codesign/commit/a0696ce3cfc50644a1e0be92e4b3909cc3a8d82e))
* add schema and glob:false for extra-files config ([fe2f584](https://github.com/aluedeke/go-codesign/commit/fe2f584cdd932282dff6ea078680dc9b6290c362))
* specify jsonpath for npm/package.json version updates ([753fbb1](https://github.com/aluedeke/go-codesign/commit/753fbb145e469e53222fe386defd1ce80ffa5f19))
* use correct output format for auto-merge PR number ([31e1a82](https://github.com/aluedeke/go-codesign/commit/31e1a82b0077275db5a2ba04e0da2d4d4a28c540))
* use manifest mode for release-please to enable extra-files config ([2fd0e9c](https://github.com/aluedeke/go-codesign/commit/2fd0e9c31c9ef41fd1cf8838b51862284ce352d0))
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
