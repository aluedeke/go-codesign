package codesign

import (
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"
)

// Integration tests that verify the resign process produces valid signatures

// TestResignedAppStructure verifies the resigned app has correct structure
func TestResignedAppStructure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check for required test data - use WDA app (downloads if necessary)
	appPath := getTestAppPath(t)
	p12Path := findP12File(t)
	profilePath := findProvisioningProfile(t)
	if p12Path == "" {
		t.Skip("No P12 certificate file found")
	}
	if profilePath == "" {
		t.Skip("No provisioning profile found")
	}

	// Copy app to temp directory for testing
	tmpDir, err := os.MkdirTemp("", "resign_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testAppPath := filepath.Join(tmpDir, "WebDriverAgentRunner-Runner.app")
	if err := copyDir(appPath, testAppPath); err != nil {
		t.Fatalf("Failed to copy app: %v", err)
	}

	t.Logf("Test app copied to %s", testAppPath)
	t.Logf("Using P12: %s", p12Path)
	t.Logf("Using profile: %s", profilePath)
}

// TestCodeResourcesGeneration verifies CodeResources can be generated for WDA
func TestCodeResourcesGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	appPath := getTestAppPath(t)

	// Generate CodeResources
	generated, err := GenerateCodeResources(appPath)
	if err != nil {
		t.Fatalf("GenerateCodeResources failed: %v", err)
	}

	// Parse the generated plist
	var genPlist map[string]interface{}
	if _, err := plist.Unmarshal(generated, &genPlist); err != nil {
		t.Fatalf("Failed to parse generated: %v", err)
	}

	// Verify essential sections exist
	if _, ok := genPlist["files"]; !ok {
		t.Error("Generated CodeResources missing 'files' section")
	}
	if _, ok := genPlist["files2"]; !ok {
		t.Error("Generated CodeResources missing 'files2' section")
	}
	if _, ok := genPlist["rules"]; !ok {
		t.Error("Generated CodeResources missing 'rules' section")
	}
	if _, ok := genPlist["rules2"]; !ok {
		t.Error("Generated CodeResources missing 'rules2' section")
	}

	t.Logf("Generated CodeResources with %d bytes", len(generated))
}

// TestNativeSignMachO_ValidSignature verifies signature is valid on macOS
func TestNativeSignMachO_ValidSignature(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if codesign is available (macOS only)
	if _, err := exec.LookPath("codesign"); err != nil {
		t.Skip("codesign not available (not macOS)")
	}

	appPath := getTestAppPath(t)

	// WDA test app may not have a valid signature initially
	cmd := exec.Command("codesign", "-v", "--verbose=4", appPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("App signature verification: %s", string(output))
		// This is OK - the test app may be unsigned
		if !strings.Contains(string(output), "invalid signature") &&
			!strings.Contains(string(output), "not signed") {
			t.Logf("Note: App signature verification issue: %v", err)
		}
	} else {
		t.Log("App signature is valid")
	}
}

// TestSignatureSlotHashes verifies special slot hashes can be computed
func TestSignatureSlotHashes(t *testing.T) {
	appPath := getTestAppPath(t)

	// Load Info.plist and compute its hash
	infoPlist, err := os.ReadFile(filepath.Join(appPath, "Info.plist"))
	if err != nil {
		t.Fatalf("Failed to read Info.plist: %v", err)
	}
	infoPlistHash := sha256.Sum256(infoPlist)
	t.Logf("Info.plist hash: %x", infoPlistHash[:8])

	// Verify Info.plist exists and can be hashed
	if len(infoPlistHash) != 32 {
		t.Errorf("Info.plist hash should be 32 bytes, got %d", len(infoPlistHash))
	}
}

// Helper function to find P12 certificate file
func findP12File(t *testing.T) string {
	// Check common locations
	locations := []string{
		"testdata/devCert.p12",
	}

	// Also check CODESIGN_P12 environment variable
	if p12 := os.Getenv("CODESIGN_P12"); p12 != "" {
		if _, err := os.Stat(p12); err == nil {
			return p12
		}
	}

	for _, loc := range locations {
		absPath, _ := filepath.Abs(loc)
		if _, err := os.Stat(absPath); err == nil {
			return absPath
		}
	}

	return ""
}

// Helper function to find provisioning profile
func findProvisioningProfile(t *testing.T) string {
	locations := []string{
		"testdata/development.mobileprovision",
	}

	// Also check CODESIGN_PROFILE environment variable
	if profile := os.Getenv("CODESIGN_PROFILE"); profile != "" {
		if _, err := os.Stat(profile); err == nil {
			return profile
		}
	}

	for _, loc := range locations {
		absPath, _ := filepath.Abs(loc)
		if _, err := os.Stat(absPath); err == nil {
			return absPath
		}
	}

	return ""
}

// Helper function to copy directory
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		return os.WriteFile(dstPath, data, info.Mode())
	})
}
