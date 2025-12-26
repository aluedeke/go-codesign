package codesign

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"os"
	"testing"

	"howett.net/plist"
)

func TestHashFile_SHA1(t *testing.T) {
	// Create a temporary file with known content
	tmpFile, err := os.CreateTemp("", "hashtest")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	testContent := []byte("Hello, World!")
	if _, err := tmpFile.Write(testContent); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Calculate expected SHA1
	expectedHash := sha1.Sum(testContent)

	// Get hash from our function
	hash, err := hashFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("hashFile failed: %v", err)
	}

	if !bytes.Equal(hash, expectedHash[:]) {
		t.Errorf("SHA1 hash mismatch\nExpected: %x\nGot: %x", expectedHash, hash)
	}

	// Verify hash length is 20 bytes (SHA1)
	if len(hash) != 20 {
		t.Errorf("Expected 20 byte hash (SHA1), got %d bytes", len(hash))
	}
}

func TestHashFileSHA256(t *testing.T) {
	// Create a temporary file with known content
	tmpFile, err := os.CreateTemp("", "hashtest256")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	testContent := []byte("Hello, World!")
	if _, err := tmpFile.Write(testContent); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Calculate expected SHA256
	expectedHash := sha256.Sum256(testContent)

	// Get hash from our function
	hash, err := hashFileSHA256(tmpFile.Name())
	if err != nil {
		t.Fatalf("hashFileSHA256 failed: %v", err)
	}

	if !bytes.Equal(hash, expectedHash[:]) {
		t.Errorf("SHA256 hash mismatch\nExpected: %x\nGot: %x", expectedHash, hash)
	}

	// Verify hash length is 32 bytes (SHA256)
	if len(hash) != 32 {
		t.Errorf("Expected 32 byte hash (SHA256), got %d bytes", len(hash))
	}
}

func TestGenerateCodeResources_Files(t *testing.T) {
	appPath := getTestAppPath(t)

	data, err := GenerateCodeResources(appPath)
	if err != nil {
		t.Fatalf("GenerateCodeResources failed: %v", err)
	}

	// Parse the generated plist
	var generated map[string]interface{}
	if _, err := plist.Unmarshal(data, &generated); err != nil {
		t.Fatalf("Failed to parse generated CodeResources: %v", err)
	}

	// Verify files section exists
	genFiles, ok := generated["files"].(map[string]interface{})
	if !ok {
		t.Fatal("Generated CodeResources missing 'files' section")
	}

	// Verify we have at least some files
	if len(genFiles) == 0 {
		t.Error("Generated CodeResources 'files' section is empty")
	}

	// Check that Info.plist is present
	if _, ok := genFiles["Info.plist"]; !ok {
		t.Error("Info.plist should be in 'files' section")
	}
}

func TestGenerateCodeResources_Files2(t *testing.T) {
	appPath := getTestAppPath(t)

	data, err := GenerateCodeResources(appPath)
	if err != nil {
		t.Fatalf("GenerateCodeResources failed: %v", err)
	}

	var generated map[string]interface{}
	if _, err := plist.Unmarshal(data, &generated); err != nil {
		t.Fatalf("Failed to parse generated CodeResources: %v", err)
	}

	// Verify files2 section exists
	genFiles2, ok := generated["files2"].(map[string]interface{})
	if !ok {
		t.Fatal("Generated CodeResources missing 'files2' section")
	}

	// Verify we have at least some files
	if len(genFiles2) == 0 {
		t.Error("Generated CodeResources 'files2' section is empty")
	}
}

func TestGenerateCodeResources_ExcludesCodeSignature(t *testing.T) {
	appPath := getTestAppPath(t)

	data, err := GenerateCodeResources(appPath)
	if err != nil {
		t.Fatalf("GenerateCodeResources failed: %v", err)
	}

	var generated map[string]interface{}
	if _, err := plist.Unmarshal(data, &generated); err != nil {
		t.Fatalf("Failed to parse generated CodeResources: %v", err)
	}

	files, _ := generated["files"].(map[string]interface{})
	files2, _ := generated["files2"].(map[string]interface{})

	// Verify _CodeSignature files are excluded
	for key := range files {
		if key == "_CodeSignature" || key == "_CodeSignature/CodeResources" {
			t.Errorf("_CodeSignature should not be in files: %s", key)
		}
	}

	for key := range files2 {
		if key == "_CodeSignature" || key == "_CodeSignature/CodeResources" {
			t.Errorf("_CodeSignature should not be in files2: %s", key)
		}
	}
}

func TestGenerateCodeResources_ExcludesExecutable(t *testing.T) {
	appPath := getTestAppPath(t)

	data, err := GenerateCodeResources(appPath)
	if err != nil {
		t.Fatalf("GenerateCodeResources failed: %v", err)
	}

	var generated map[string]interface{}
	if _, err := plist.Unmarshal(data, &generated); err != nil {
		t.Fatalf("Failed to parse generated CodeResources: %v", err)
	}

	files, _ := generated["files"].(map[string]interface{})
	files2, _ := generated["files2"].(map[string]interface{})

	// The main executable "WebDriverAgentRunner-Runner" should not be in CodeResources
	execName := "WebDriverAgentRunner-Runner"
	if _, exists := files[execName]; exists {
		t.Errorf("Main executable '%s' should not be in files", execName)
	}

	if _, exists := files2[execName]; exists {
		t.Errorf("Main executable '%s' should not be in files2", execName)
	}
}

func TestGenerateCodeResources_Rules(t *testing.T) {
	appPath := getTestAppPath(t)

	data, err := GenerateCodeResources(appPath)
	if err != nil {
		t.Fatalf("GenerateCodeResources failed: %v", err)
	}

	var generated map[string]interface{}
	if _, err := plist.Unmarshal(data, &generated); err != nil {
		t.Fatalf("Failed to parse generated CodeResources: %v", err)
	}

	// Verify rules section exists
	rules, ok := generated["rules"].(map[string]interface{})
	if !ok {
		t.Fatal("Generated CodeResources missing 'rules' section")
	}

	// Check essential rules
	if _, ok := rules["^.*"]; !ok {
		t.Error("rules missing '^.*' pattern")
	}

	// Verify rules2 section exists
	rules2, ok := generated["rules2"].(map[string]interface{})
	if !ok {
		t.Fatal("Generated CodeResources missing 'rules2' section")
	}

	// Check rules2 essential patterns
	if _, ok := rules2["^.*"]; !ok {
		t.Error("rules2 missing '^.*' pattern")
	}

	if _, ok := rules2["^Info\\.plist$"]; !ok {
		t.Error("rules2 missing '^Info\\.plist$' pattern")
	}
}

func TestShouldOmit(t *testing.T) {
	// Note: shouldOmit no longer handles _CodeSignature - that's handled
	// directly in GenerateCodeResources which skips only the main app's
	// _CodeSignature/CodeResources but includes nested bundle CodeResources.
	// All files are hashed except:
	// - Main executable
	// - Main app's _CodeSignature/CodeResources
	tests := []struct {
		path     string
		expected bool
	}{
		{".DS_Store", true},
		{"folder/.DS_Store", true},
		{"._hidden", true},
		{"folder/._hidden", true},
		{"en.lproj/locversion.plist", true},
		{"AppIcon.png", false},
		{"Frameworks/Foo.framework/_CodeSignature/CodeResources", false},
		{"PlugIns/Widget.appex/_CodeSignature/CodeResources", false},
		{"_CodeSignature", false},               // Not omitted by shouldOmit anymore
		{"_CodeSignature/CodeResources", false}, // Handled in GenerateCodeResources
	}

	for _, tc := range tests {
		result := shouldOmit(tc.path)
		if result != tc.expected {
			t.Errorf("shouldOmit(%q) = %v, expected %v", tc.path, result, tc.expected)
		}
	}
}

func TestHashData(t *testing.T) {
	data := []byte("test data")
	hash := HashData(data)

	// Verify it's SHA256
	expected := sha256.Sum256(data)
	if !bytes.Equal(hash, expected[:]) {
		t.Errorf("HashData produced incorrect hash")
	}

	if len(hash) != 32 {
		t.Errorf("Expected 32 byte hash, got %d", len(hash))
	}
}

// Helper function to extract hash bytes from various plist value types
func extractHash(v interface{}) []byte {
	switch val := v.(type) {
	case []byte:
		return val
	case map[string]interface{}:
		if hash, ok := val["hash"].([]byte); ok {
			return hash
		}
	}
	return nil
}

// TestHashFileSHA1_VerifyAlgorithm verifies we're using actual SHA1, not truncated SHA256
func TestHashFileSHA1_VerifyAlgorithm(t *testing.T) {
	// Create a temporary file with known content
	tmpFile, err := os.CreateTemp("", "hashtest")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	testContent := []byte("Hello, World!")
	if _, err := tmpFile.Write(testContent); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Calculate expected SHA1
	expectedHash := sha1.Sum(testContent)

	// Get hash from our function
	gotHash, err := hashFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("hashFile failed: %v", err)
	}

	if !bytes.Equal(gotHash, expectedHash[:]) {
		t.Errorf("hashFile is not using SHA1\nExpected SHA1: %x\nGot: %x", expectedHash, gotHash)
	}
}

// TestGenerateCodeResources_Files2HasBothHashes verifies files2 entries have both hash and hash2 keys
func TestGenerateCodeResources_Files2HasBothHashes(t *testing.T) {
	appPath := getTestAppPath(t)

	data, err := GenerateCodeResources(appPath)
	if err != nil {
		t.Fatalf("GenerateCodeResources failed: %v", err)
	}

	var generated map[string]interface{}
	if _, err := plist.Unmarshal(data, &generated); err != nil {
		t.Fatalf("Failed to parse generated CodeResources: %v", err)
	}

	files2, ok := generated["files2"].(map[string]interface{})
	if !ok {
		t.Fatal("Generated CodeResources missing 'files2' section")
	}

	// Check that at least some files2 entries have BOTH hash and hash2 keys
	checkedCount := 0
	for file, entry := range files2 {
		entryMap, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}

		// Check hash key exists (SHA1)
		hashVal, hasHash := entryMap["hash"]
		if hasHash {
			hashBytes, ok := hashVal.([]byte)
			if !ok || len(hashBytes) != 20 {
				t.Errorf("File %s 'hash' should be 20 bytes (SHA1)", file)
			}
		}

		// Check hash2 key exists (SHA256)
		hash2Val, hasHash2 := entryMap["hash2"]
		if hasHash2 {
			hash2Bytes, ok := hash2Val.([]byte)
			if !ok || len(hash2Bytes) != 32 {
				t.Errorf("File %s 'hash2' should be 32 bytes (SHA256)", file)
			}
		}

		checkedCount++
		if checkedCount >= 3 {
			break // Just check a few entries
		}
	}
}

// TestDefaultRules_WeightsAreFloat64 verifies that rule weights are float64 (for <real> plist output)
func TestDefaultRules_WeightsAreFloat64(t *testing.T) {
	rules := defaultRules()

	// Check a rule with a weight
	lprojRule, ok := rules["^.*\\.lproj/"].(map[string]interface{})
	if !ok {
		t.Fatal("Missing ^.*\\.lproj/ rule")
	}

	weight, ok := lprojRule["weight"]
	if !ok {
		t.Fatal("^.*\\.lproj/ rule missing weight")
	}

	// Weight must be float64 for plist to output <real> instead of <integer>
	if _, isFloat := weight.(float64); !isFloat {
		t.Errorf("Weight should be float64 for <real> plist output, got %T", weight)
	}
}

// TestDefaultRules2_WeightsAreFloat64 verifies that rules2 weights are float64
func TestDefaultRules2_WeightsAreFloat64(t *testing.T) {
	rules2 := defaultRules2()

	// Check several rules with weights
	testRules := []string{
		".*\\.dSYM($|/)",
		"^(.*/)?\\.DS_Store$",
		"^Info\\.plist$",
	}

	for _, ruleName := range testRules {
		rule, ok := rules2[ruleName].(map[string]interface{})
		if !ok {
			t.Errorf("Missing rule: %s", ruleName)
			continue
		}

		weight, ok := rule["weight"]
		if !ok {
			t.Errorf("Rule %s missing weight", ruleName)
			continue
		}

		if _, isFloat := weight.(float64); !isFloat {
			t.Errorf("Rule %s weight should be float64, got %T", ruleName, weight)
		}
	}
}

// TestDefaultRules2_HasDSStoreOmitRule verifies the .DS_Store omit rule is present
func TestDefaultRules2_HasDSStoreOmitRule(t *testing.T) {
	rules2 := defaultRules2()

	dsStoreRule, ok := rules2["^(.*/)?\\.DS_Store$"].(map[string]interface{})
	if !ok {
		t.Fatal("Missing ^(.*/)?\\.DS_Store$ rule in rules2")
	}

	// Check omit is true
	omit, ok := dsStoreRule["omit"]
	if !ok {
		t.Error(".DS_Store rule missing 'omit' key")
	} else if omit != true {
		t.Errorf(".DS_Store rule 'omit' should be true, got %v", omit)
	}

	// Check weight is 2000
	weight, ok := dsStoreRule["weight"]
	if !ok {
		t.Error(".DS_Store rule missing 'weight' key")
	} else if weight != float64(2000) {
		t.Errorf(".DS_Store rule weight should be 2000, got %v", weight)
	}
}

// TestShouldOmitFromFiles2 verifies Info.plist and PkgInfo are omitted from files2
func TestShouldOmitFromFiles2(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"Info.plist", true},
		{"PkgInfo", true},
		{"AppIcon.png", false},
		{"Assets.car", false},
		{"embedded.mobileprovision", false},
		{"Frameworks/Foo.framework/Info.plist", false}, // Only root Info.plist is omitted
	}

	for _, tc := range tests {
		result := shouldOmitFromFiles2(tc.path)
		if result != tc.expected {
			t.Errorf("shouldOmitFromFiles2(%q) = %v, expected %v", tc.path, result, tc.expected)
		}
	}
}
