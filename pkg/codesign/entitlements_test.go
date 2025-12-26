package codesign

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEntitlementsToDER(t *testing.T) {
	// Test with typical iOS entitlements
	entitlements := map[string]interface{}{
		"application-identifier":              "ABCD1234.com.example.testapp",
		"com.apple.developer.team-identifier": "ABCD1234",
		"get-task-allow":                      true,
	}

	// Generate DER using our implementation
	derBytes, err := EntitlementsToDER(entitlements)
	if err != nil {
		t.Fatalf("EntitlementsToDER failed: %v", err)
	}

	// Verify the DER structure is valid
	// Should start with APPLICATION 16 tag (0x70)
	if len(derBytes) < 10 {
		t.Fatalf("DER output too short: %d bytes", len(derBytes))
	}

	if derBytes[0] != 0x70 {
		t.Errorf("Expected APPLICATION 16 tag (0x70), got 0x%02x", derBytes[0])
	}

	// Verify the entitlement keys are present in the output
	if !bytes.Contains(derBytes, []byte("application-identifier")) {
		t.Error("DER should contain 'application-identifier'")
	}
	if !bytes.Contains(derBytes, []byte("get-task-allow")) {
		t.Error("DER should contain 'get-task-allow'")
	}
}

func TestEntitlementsToDER_Structure(t *testing.T) {
	// Test basic DER structure
	entitlements := map[string]interface{}{
		"test-key": "test-value",
	}

	derBytes, err := EntitlementsToDER(entitlements)
	if err != nil {
		t.Fatalf("EntitlementsToDER failed: %v", err)
	}

	// Check APPLICATION 16 tag (0x70)
	if derBytes[0] != 0x70 {
		t.Errorf("Expected APPLICATION 16 tag (0x70), got 0x%02x", derBytes[0])
	}

	// The content should contain INTEGER 1 (version) at the start
	// After tag and length, we should find 02 01 01 (INTEGER 1)
	// Find the version integer
	found := false
	for i := 0; i < len(derBytes)-3; i++ {
		if derBytes[i] == 0x02 && derBytes[i+1] == 0x01 && derBytes[i+2] == 0x01 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DER should contain INTEGER 1 as version marker, got:\n%s", hex.Dump(derBytes))
	}
}

func TestEntitlementsToDER_UTF8String(t *testing.T) {
	// Verify strings are encoded as UTF8String (tag 0x0C), not PrintableString (tag 0x13)
	entitlements := map[string]interface{}{
		"key": "value",
	}

	derBytes, err := EntitlementsToDER(entitlements)
	if err != nil {
		t.Fatalf("EntitlementsToDER failed: %v", err)
	}

	// Check that we use UTF8String (0x0C) for string encoding
	// The key "key" should be encoded as: 0C 03 6b 65 79
	keyEncoded := []byte{0x0C, 0x03, 'k', 'e', 'y'}
	if !bytes.Contains(derBytes, keyEncoded) {
		t.Errorf("Expected UTF8String encoding for 'key', got:\n%s", hex.Dump(derBytes))
	}

	// The value "value" should be encoded as: 0C 05 76 61 6c 75 65
	valueEncoded := []byte{0x0C, 0x05, 'v', 'a', 'l', 'u', 'e'}
	if !bytes.Contains(derBytes, valueEncoded) {
		t.Errorf("Expected UTF8String encoding for 'value', got:\n%s", hex.Dump(derBytes))
	}
}

func TestEntitlementsToDER_Boolean(t *testing.T) {
	entitlements := map[string]interface{}{
		"flag": true,
	}

	derBytes, err := EntitlementsToDER(entitlements)
	if err != nil {
		t.Fatalf("EntitlementsToDER failed: %v", err)
	}

	// Boolean true should be encoded as: 01 01 ff
	boolTrue := []byte{0x01, 0x01, 0xff}
	if !bytes.Contains(derBytes, boolTrue) {
		t.Errorf("Expected BOOLEAN TRUE encoding, got:\n%s", hex.Dump(derBytes))
	}
}

func TestEntitlementsToDER_Array(t *testing.T) {
	entitlements := map[string]interface{}{
		"array-key": []interface{}{"item1", "item2"},
	}

	derBytes, err := EntitlementsToDER(entitlements)
	if err != nil {
		t.Fatalf("EntitlementsToDER failed: %v", err)
	}

	// Array should be encoded as SEQUENCE (0x30)
	// Items should be UTF8String
	if !bytes.Contains(derBytes, []byte{0x30}) {
		t.Errorf("Expected SEQUENCE tag for array, got:\n%s", hex.Dump(derBytes))
	}

	// Check array items are present
	item1 := []byte{0x0C, 0x05, 'i', 't', 'e', 'm', '1'}
	if !bytes.Contains(derBytes, item1) {
		t.Errorf("Expected 'item1' in array, got:\n%s", hex.Dump(derBytes))
	}
}

func TestEntitlementsToDER_SortedKeys(t *testing.T) {
	// Keys should be sorted alphabetically for deterministic output
	entitlements := map[string]interface{}{
		"z-key": "z-value",
		"a-key": "a-value",
		"m-key": "m-value",
	}

	derBytes, err := EntitlementsToDER(entitlements)
	if err != nil {
		t.Fatalf("EntitlementsToDER failed: %v", err)
	}

	// Find positions of each key
	aPos := bytes.Index(derBytes, []byte("a-key"))
	mPos := bytes.Index(derBytes, []byte("m-key"))
	zPos := bytes.Index(derBytes, []byte("z-key"))

	if aPos < 0 || mPos < 0 || zPos < 0 {
		t.Fatalf("Keys not found in DER output")
	}

	if aPos >= mPos || mPos >= zPos {
		t.Errorf("Keys should be sorted alphabetically: a-key at %d, m-key at %d, z-key at %d",
			aPos, mPos, zPos)
	}
}

func TestParseEntitlementsXML(t *testing.T) {
	xmlData := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>application-identifier</key>
	<string>ABCD1234.com.example.testapp</string>
	<key>get-task-allow</key>
	<true/>
</dict>
</plist>`)

	entitlements, err := ParseEntitlementsXML(xmlData)
	if err != nil {
		t.Fatalf("ParseEntitlementsXML failed: %v", err)
	}

	if entitlements["application-identifier"] != "ABCD1234.com.example.testapp" {
		t.Errorf("Expected application-identifier to be 'ABCD1234.com.example.testapp', got %v",
			entitlements["application-identifier"])
	}

	if entitlements["get-task-allow"] != true {
		t.Errorf("Expected get-task-allow to be true, got %v", entitlements["get-task-allow"])
	}
}

func TestUpdateEntitlementsForBundleID(t *testing.T) {
	entitlements := map[string]interface{}{
		"application-identifier": "OLD_TEAM.old.bundle.id",
		"keychain-access-groups": []interface{}{
			"OLD_TEAM.old.bundle.id",
		},
	}

	updated := UpdateEntitlementsForBundleID(entitlements, "NEW_TEAM", "new.bundle.id")

	if updated["application-identifier"] != "NEW_TEAM.new.bundle.id" {
		t.Errorf("Expected application-identifier to be 'NEW_TEAM.new.bundle.id', got %v",
			updated["application-identifier"])
	}

	groups, ok := updated["keychain-access-groups"].([]interface{})
	if !ok || len(groups) == 0 {
		t.Fatalf("keychain-access-groups should be a non-empty array")
	}

	if groups[0] != "NEW_TEAM.new.bundle.id" {
		t.Errorf("Expected keychain-access-groups[0] to be 'NEW_TEAM.new.bundle.id', got %v", groups[0])
	}
}

func TestUpdateEntitlementsForBundleID_WithTeamPrefix(t *testing.T) {
	// Test that we don't double-add team ID if bundle ID already has it
	entitlements := map[string]interface{}{
		"application-identifier": "OLD_TEAM.old.bundle.id",
	}

	// Pass a bundle ID that already includes the team ID
	updated := UpdateEntitlementsForBundleID(entitlements, "NEW_TEAM", "NEW_TEAM.new.bundle.id")

	// Should NOT be "NEW_TEAM.NEW_TEAM.new.bundle.id"
	if updated["application-identifier"] != "NEW_TEAM.new.bundle.id" {
		t.Errorf("Expected application-identifier to be 'NEW_TEAM.new.bundle.id', got %v",
			updated["application-identifier"])
	}
}
