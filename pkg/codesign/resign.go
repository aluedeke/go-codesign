package codesign

import (
	"fmt"
	"os"
	"path/filepath"

	"howett.net/plist"
)

// ResignOptions contains all options for resigning a .app bundle
type ResignOptions struct {
	AppPath             string // Path to the .app bundle
	P12Data             []byte
	P12Password         string
	ProvisioningProfile []byte
	NewBundleID         string // Optional: if set, changes the bundle ID
}

// Resign resigns a .app bundle with a new signing identity (in-place)
func Resign(opts ResignOptions) error {
	// Validate options
	if opts.AppPath == "" {
		return fmt.Errorf("app path is required")
	}
	if len(opts.P12Data) == 0 {
		return fmt.Errorf("P12 certificate data is required")
	}
	if len(opts.ProvisioningProfile) == 0 {
		return fmt.Errorf("provisioning profile is required")
	}

	// Parse provisioning profile first (needed for PEM key certificate extraction)
	profile, err := ParseProvisioningProfile(opts.ProvisioningProfile)
	if err != nil {
		return fmt.Errorf("failed to parse provisioning profile: %w", err)
	}

	// Validate profile hasn't expired
	if profile.IsExpired() {
		return fmt.Errorf("provisioning profile has expired")
	}

	// Load signing identity from P12 or PEM key
	// If PEM key is provided, certificate is extracted from provisioning profile
	identity, err := LoadSigningIdentityWithProfile(opts.P12Data, opts.P12Password, profile)
	if err != nil {
		return fmt.Errorf("failed to load signing identity: %w", err)
	}

	// Validate certificate matches profile
	if !profile.MatchesCertificate(identity.Certificate) {
		return fmt.Errorf("certificate does not match provisioning profile")
	}

	// Get bundle ID
	bundleID, err := GetAppBundleID(opts.AppPath)
	if err != nil {
		return fmt.Errorf("failed to get bundle ID: %w", err)
	}

	// If new bundle ID is specified, update it
	if opts.NewBundleID != "" {
		bundleID = opts.NewBundleID
	}

	// Prepare entitlements
	// Use the entitlements from the profile as-is
	// Do NOT update wildcard entitlements - iOS handles this at runtime
	entitlements := profile.Entitlements

	entitlementsXML, err := EntitlementsToXML(entitlements)
	if err != nil {
		return fmt.Errorf("failed to generate entitlements: %w", err)
	}

	// Replace embedded.mobileprovision ONLY for .app bundles
	// Nested bundles (frameworks, xctest, etc.) should NOT have embedded.mobileprovision
	ext := filepath.Ext(opts.AppPath)
	if ext == ".app" {
		embeddedProfilePath := filepath.Join(opts.AppPath, "embedded.mobileprovision")
		if err := os.WriteFile(embeddedProfilePath, opts.ProvisioningProfile, 0644); err != nil {
			return fmt.Errorf("failed to write embedded.mobileprovision: %w", err)
		}
	}

	// Update Info.plist if bundle ID changed
	if opts.NewBundleID != "" {
		if err := updateInfoPlistBundleID(opts.AppPath, opts.NewBundleID); err != nil {
			return fmt.Errorf("failed to update Info.plist: %w", err)
		}
	}

	// Remove old _CodeSignature directory
	codeSignDir := filepath.Join(opts.AppPath, "_CodeSignature")
	if err := os.RemoveAll(codeSignDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove old _CodeSignature: %w", err)
	}

	// Sign all binaries (frameworks, extensions, main app)
	// NativeSignAppBundle handles:
	// - Signing nested bundles first (generating their CodeResources before signing)
	// - Generating main app's CodeResources AFTER nested bundles are signed
	// - Signing the main app executable last
	if err := NativeSignAppBundle(opts.AppPath, identity, entitlementsXML, bundleID); err != nil {
		return fmt.Errorf("failed to sign app bundle: %w", err)
	}

	return nil
}

// ResignApp resigns an already extracted .app bundle in place
func ResignApp(appPath string, identity *SigningIdentity, profile *ProvisioningProfile, newBundleID string) error {
	// Get current bundle ID
	bundleID, err := GetAppBundleID(appPath)
	if err != nil {
		return fmt.Errorf("failed to get bundle ID: %w", err)
	}

	// Use new bundle ID if specified
	if newBundleID != "" {
		bundleID = newBundleID
	}

	// Prepare entitlements
	// Use the entitlements from the profile as-is
	entitlements := profile.Entitlements

	entitlementsXML, err := EntitlementsToXML(entitlements)
	if err != nil {
		return fmt.Errorf("failed to generate entitlements: %w", err)
	}

	// Replace provisioning profile
	embeddedProfilePath := filepath.Join(appPath, "embedded.mobileprovision")
	profileData, err := os.ReadFile(embeddedProfilePath)
	if err == nil {
		// There was an existing profile, we need the raw bytes
		// This is a simplified path - in real usage, you'd pass the profile bytes
	}
	_ = profileData // Suppress unused warning

	// Update Info.plist if needed
	if newBundleID != "" {
		if err := updateInfoPlistBundleID(appPath, newBundleID); err != nil {
			return fmt.Errorf("failed to update Info.plist: %w", err)
		}
	}

	// Remove old signature
	codeSignDir := filepath.Join(appPath, "_CodeSignature")
	if err := os.RemoveAll(codeSignDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove old _CodeSignature: %w", err)
	}

	// Generate CodeResources (must be done before signing so we can hash it)
	if err := WriteCodeResources(appPath); err != nil {
		return fmt.Errorf("failed to generate CodeResources: %w", err)
	}

	// Sign binaries using native implementation
	if err := NativeSignAppBundle(appPath, identity, entitlementsXML, bundleID); err != nil {
		return fmt.Errorf("failed to sign app bundle: %w", err)
	}

	return nil
}

func updateInfoPlistBundleID(appPath, newBundleID string) error {
	infoPlistPath := filepath.Join(appPath, "Info.plist")

	// Read existing plist
	data, err := os.ReadFile(infoPlistPath)
	if err != nil {
		return fmt.Errorf("failed to read Info.plist: %w", err)
	}

	info, err := parseInfoPlist(data)
	if err != nil {
		return fmt.Errorf("failed to parse Info.plist: %w", err)
	}

	// Update bundle ID
	info["CFBundleIdentifier"] = newBundleID

	// Write back
	newData, err := plist.MarshalIndent(info, plist.XMLFormat, "\t")
	if err != nil {
		return fmt.Errorf("failed to marshal Info.plist: %w", err)
	}

	if err := os.WriteFile(infoPlistPath, newData, 0644); err != nil {
		return fmt.Errorf("failed to write Info.plist: %w", err)
	}

	return nil
}

func parseInfoPlist(data []byte) (map[string]interface{}, error) {
	var info map[string]interface{}
	_, err := plist.Unmarshal(data, &info)
	if err != nil {
		return nil, fmt.Errorf("failed to parse plist: %w", err)
	}
	return info, nil
}
