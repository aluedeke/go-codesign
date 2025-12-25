# iOS Code Signing in Pure Go

This package implements iOS IPA re-signing entirely in Go, without requiring external tools like `codesign`, `zsign`, or macOS. It produces signatures compatible with iOS 15+ devices.

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Usage](#usage)
- [Code Signing Internals](#code-signing-internals)
  - [The SuperBlob Structure](#the-superblob-structure)
  - [CodeDirectory](#codedirectory)
  - [Special Slots](#special-slots)
  - [CMS Signature](#cms-signature)
  - [CodeResources](#coderesources)
  - [Entitlements](#entitlements)
- [Certificate Chain](#certificate-chain)
- [Troubleshooting](#troubleshooting)

## Overview

iOS code signing serves two purposes:
1. **Integrity**: Ensures the app hasn't been modified since signing
2. **Identity**: Proves the app was signed by a trusted developer

Every executable in an iOS app bundle contains an embedded code signature that iOS validates before allowing the app to run. This package handles:

- Signing Mach-O executables (main binary, frameworks, dylibs)
- Generating `_CodeSignature/CodeResources` (resource hashes)
- Building entitlements (XML and DER formats)
- Creating CMS/PKCS#7 signatures with Apple-specific attributes

## Requirements

To re-sign an IPA, you need:

1. **Signing Certificate** (`.p12` file)
   - An Apple Developer certificate exported from Keychain
   - Contains your private key and certificate chain
   - Must include intermediate certificates (WWDR G3, Apple Root CA)

2. **Provisioning Profile** (`.mobileprovision` file)
   - Links your certificate to specific app IDs and devices
   - Contains entitlements the app is allowed to use
   - Must match the certificate's Team ID

3. **The IPA file**
   - The app to be re-signed

## Usage

```go
import "github.com/danielpaulus/go-ios/ios/resign"

// Load signing identity from P12
identity, err := resign.LoadSigningIdentity("certificate.p12", "password")

// Load provisioning profile
profile, err := resign.ParseProvisioningProfile("profile.mobileprovision")

// Re-sign the IPA
opts := resign.ResignOptions{
    InputIPA:    "app.ipa",
    OutputIPA:   "resigned.ipa",
    Identity:    identity,
    Profile:     profile,
    NewBundleID: "com.example.newbundleid", // optional
}
err = resign.ResignIPA(opts)
```

## Code Signing Internals

### The SuperBlob Structure

The code signature is embedded at the end of a Mach-O binary as a "SuperBlob" - a container holding multiple signature components:

```
┌─────────────────────────────────────────┐
│ SuperBlob Header                        │
│   magic: 0xfade0cc0                     │
│   length: total size                    │
│   count: number of blobs                │
├─────────────────────────────────────────┤
│ Blob Index (array of slot+offset pairs) │
│   [0] CodeDirectory SHA1    → offset    │
│   [1] Requirements          → offset    │
│   [2] Entitlements          → offset    │
│   [3] Entitlements DER      → offset    │
│   [4] CodeDirectory SHA256  → offset    │
│   [5] CMS Signature         → offset    │
├─────────────────────────────────────────┤
│ CodeDirectory (SHA1)                    │
├─────────────────────────────────────────┤
│ Requirements                            │
├─────────────────────────────────────────┤
│ Entitlements (XML plist)                │
├─────────────────────────────────────────┤
│ Entitlements (DER encoded)              │
├─────────────────────────────────────────┤
│ CodeDirectory (SHA256)                  │
├─────────────────────────────────────────┤
│ CMS Signature (PKCS#7)                  │
└─────────────────────────────────────────┘
```

### CodeDirectory

The CodeDirectory is the heart of code signing. It contains:

1. **Metadata**: Bundle ID, Team ID, version, flags
2. **Special Slot Hashes**: Hashes of Info.plist, entitlements, requirements, CodeResources
3. **Code Page Hashes**: Hash of every 4KB page of the executable

```
CodeDirectory Structure (v0x20400):
┌────────────────────────────────────┐
│ Header (88 bytes)                  │
│   magic: 0xfade0c02                │
│   length, version, flags           │
│   hashOffset, identOffset          │
│   nSpecialSlots, nCodeSlots        │
│   codeLimit, hashSize, hashType    │
│   pageSize (4KB = 12 bits)         │
│   teamOffset                       │
│   execSegBase, execSegLimit        │
├────────────────────────────────────┤
│ Identifier String                  │
│   "com.example.app\0"              │
├────────────────────────────────────┤
│ Team ID String                     │
│   "ABCD1234XY\0"                   │
├────────────────────────────────────┤
│ Special Slot Hashes (negative)     │
│   [-7] Entitlements DER hash       │
│   [-6] (unused)                    │
│   [-5] Entitlements XML hash       │
│   [-4] (unused)                    │
│   [-3] CodeResources hash          │
│   [-2] Requirements hash           │
│   [-1] Info.plist hash             │
├────────────────────────────────────┤
│ Code Page Hashes (positive)        │
│   [0] Hash of bytes 0-4095         │
│   [1] Hash of bytes 4096-8191      │
│   [2] ...                          │
└────────────────────────────────────┘
```

**Why two CodeDirectories?**

Modern iOS requires both SHA1 and SHA256 CodeDirectories:
- **SHA1 CodeDirectory** (slot 0): Legacy compatibility, also used for CMS signing
- **SHA256 CodeDirectory** (slot 0x1000): Used by modern iOS for validation

### Special Slots

Special slots contain hashes of auxiliary signing data:

| Slot | Name | Content |
|------|------|---------|
| -1 | Info.plist | Hash of the app's Info.plist |
| -2 | Requirements | Hash of the requirements blob |
| -3 | CodeResources | Hash of `_CodeSignature/CodeResources` |
| -4 | (reserved) | Unused |
| -5 | Entitlements | Hash of XML entitlements blob |
| -6 | (reserved) | Unused |
| -7 | Entitlements DER | Hash of DER-encoded entitlements |

### CMS Signature

The CMS (Cryptographic Message Syntax) signature is a PKCS#7 detached signature that:

1. Signs the SHA1 CodeDirectory (not SHA256!)
2. Uses SHA256 as the digest algorithm
3. Includes the full certificate chain
4. Contains Apple-specific signed attributes:

**Apple Signed Attributes:**

| OID | Name | Content |
|-----|------|---------|
| 1.2.840.113635.100.9.1 | CDHashes | Plist with array of truncated CD hashes |
| 1.2.840.113635.100.9.2 | CDHashes2 | ASN.1 SEQUENCE with full SHA256 hash |

The CDHashes plist contains:
```xml
{
    cdhashes = (
        <sha1-hash-of-sha1-codedirectory>,      // 20 bytes
        <truncated-sha256-hash-of-sha256-cd>    // 20 bytes (truncated from 32)
    );
}
```

### CodeResources

The `_CodeSignature/CodeResources` file is a plist containing hashes of all non-executable resources in the app bundle:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>files</key>
    <dict>
        <!-- SHA1 hashes for legacy iOS -->
        <key>AppIcon60x60@2x.png</key>
        <data>BASE64_SHA1_HASH</data>
        <key>Info.plist</key>
        <data>BASE64_SHA1_HASH</data>
    </dict>
    <key>files2</key>
    <dict>
        <!-- Both SHA1 and SHA256 for modern iOS -->
        <key>AppIcon60x60@2x.png</key>
        <dict>
            <key>hash</key>
            <data>BASE64_SHA1_HASH</data>
            <key>hash2</key>
            <data>BASE64_SHA256_HASH</data>
        </dict>
    </dict>
    <key>rules</key>
    <dict><!-- Matching rules for files section --></dict>
    <key>rules2</key>
    <dict><!-- Matching rules for files2 section --></dict>
</dict>
</plist>
```

**Important rules:**
- `Info.plist` and `PkgInfo` appear in `files` but NOT in `files2`
- `.lproj/` directories are marked as `optional`
- `.DS_Store` files are omitted
- Nested bundles (frameworks) include their own `_CodeSignature/CodeResources`

### Entitlements

Entitlements declare capabilities and permissions the app requires. They're embedded in two formats:

**1. XML Plist (slot 5)**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>application-identifier</key>
    <string>TEAMID.com.example.app</string>
    <key>get-task-allow</key>
    <true/>
    <key>keychain-access-groups</key>
    <array>
        <string>TEAMID.com.example.app</string>
    </array>
</dict>
</plist>
```

**2. DER Encoded (slot 7)**

iOS 15+ also requires DER-encoded entitlements using a proprietary Apple format:
- Uses tag 0x30 (SEQUENCE) at the root
- Keys are context-specific tag [0] with UTF8String
- Values use context-specific tag [1]
- Booleans: 0x01 0x01 0x01 (true) or 0x01 0x01 0x00 (false)
- Strings: UTF8String (0x0C)
- Arrays: SEQUENCE of values

## Certificate Chain

A valid signing identity requires the complete certificate chain:

```
┌─────────────────────────────────────┐
│ Apple Root CA                       │
│   Subject: Apple Root CA            │
│   Issuer: Apple Root CA (self)      │
└─────────────┬───────────────────────┘
              │ signs
              ▼
┌─────────────────────────────────────┐
│ Apple WWDR G3                       │
│   Subject: Apple Worldwide Dev...   │
│   Issuer: Apple Root CA             │
└─────────────┬───────────────────────┘
              │ signs
              ▼
┌─────────────────────────────────────┐
│ Your Signing Certificate            │
│   Subject: iPhone Developer: ...    │
│   Issuer: Apple Worldwide Dev...    │
│   + Your Private Key                │
└─────────────────────────────────────┘
```

When exporting from Keychain, ensure you include the certificate chain. The P12 should contain:
1. Your signing certificate
2. Apple Worldwide Developer Relations G3
3. Apple Root CA

## Troubleshooting

### Error: "A valid provisioning profile for this executable was not found"

- The provisioning profile doesn't include the device UDID
- The bundle ID doesn't match the profile's app ID
- The profile has expired

### Error: "The signature is invalid" or AMFI errors

- Certificate chain is incomplete (missing WWDR or Root CA)
- CodeDirectory hashes don't match actual file contents
- Special slot hashes are incorrect
- CMS signature was created incorrectly

### Error: "Entitlements are not valid"

- Entitlements in the signature don't match the provisioning profile
- DER-encoded entitlements have incorrect format
- Missing required entitlements (like `application-identifier`)

### Debugging Tips

1. **Compare with a known-good signature:**
   ```bash
   codesign -d --verbose=4 GoodApp.app
   codesign -d --verbose=4 YourApp.app
   ```

2. **Extract and examine the signature:**
   ```bash
   # Extract signature blob
   codesign -d --blob=sig.bin YourApp.app

   # Parse CMS signature
   openssl asn1parse -inform DER -in sig.bin
   ```

3. **Verify CodeResources:**
   ```bash
   plutil -p YourApp.app/_CodeSignature/CodeResources
   ```

4. **Check entitlements:**
   ```bash
   codesign -d --entitlements :- YourApp.app
   ```

## References

- [Apple Code Signing Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/)
- [cs_blobs.h (XNU source)](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/kern/cs_blobs.h)
- [TN3125: Inside Code Signing: Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
- [TN3126: Inside Code Signing: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes)
