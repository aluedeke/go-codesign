// Package codesign provides iOS code signing functionality.
//
// This package implements Apple's code signing format natively in Go,
// allowing you to resign IPA files and .app bundles on any platform
// without requiring macOS or Apple's codesign tool.
//
// # Basic Usage
//
// To resign an app:
//
//	signer, err := codesign.NewSigner(p12Data, password, profileData)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	err = signer.SignApp(appPath)
//
// # Features
//
//   - Cross-platform: Works on Linux, macOS, and Windows
//   - IPA and .app support: Resign both IPA files and extracted .app bundles
//   - Nested bundle signing: Automatically signs frameworks, plugins, and extensions
//   - Bundle ID modification: Change the app's bundle identifier during resign
package codesign
