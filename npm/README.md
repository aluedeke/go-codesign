# go-codesign

Pure Go implementation for iOS code signing - resign IPA files and .app bundles without macOS.

> **Alpha Status**: This project is in early development. The API may change, and there may be bugs or missing features.

## Usage

```bash
# Run directly with npx (recommended)
npx go-codesign --help

# Resign an IPA
npx go-codesign resign --app=MyApp.ipa --p12=cert.p12 --profile=dev.mobileprovision --password=secret

# View app info
npx go-codesign info --app=MyApp.ipa

# View provisioning profile info
npx go-codesign info --profile=dev.mobileprovision
```

## Documentation

For full documentation, see the [GitHub repository](https://github.com/aluedeke/go-codesign).

## License

MIT
