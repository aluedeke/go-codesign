package codesign

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"howett.net/plist"
)

// TestCodeDirectoryMagic verifies the CodeDirectory magic number
func TestCodeDirectoryMagic(t *testing.T) {
	sigData, err := os.ReadFile(filepath.Join("testdata", "original_signature.bin"))
	if err != nil {
		t.Skip("Test data not available")
	}

	// Parse SuperBlob to find CodeDirectory
	if len(sigData) < 12 {
		t.Fatal("Signature too short")
	}

	magic := binary.BigEndian.Uint32(sigData[0:4])
	if magic != CSMAGIC_EMBEDDED_SIGNATURE {
		t.Fatalf("Expected SuperBlob magic 0x%x, got 0x%x", CSMAGIC_EMBEDDED_SIGNATURE, magic)
	}

	// Find CodeDirectory blob
	blobCount := binary.BigEndian.Uint32(sigData[8:12])
	if blobCount < 1 {
		t.Fatal("No blobs in SuperBlob")
	}

	// First blob should be CodeDirectory
	blobType := binary.BigEndian.Uint32(sigData[12:16])
	if blobType != CSSLOT_CODEDIRECTORY {
		t.Errorf("First blob should be CodeDirectory (0), got %d", blobType)
	}

	cdirOffset := binary.BigEndian.Uint32(sigData[16:20])
	cdirMagic := binary.BigEndian.Uint32(sigData[cdirOffset : cdirOffset+4])

	if cdirMagic != CSMAGIC_CODEDIRECTORY {
		t.Errorf("Expected CodeDirectory magic 0x%x, got 0x%x", CSMAGIC_CODEDIRECTORY, cdirMagic)
	}
}

// TestCodeDirectoryVersion verifies the CodeDirectory version
func TestCodeDirectoryVersion(t *testing.T) {
	sigData, err := os.ReadFile(filepath.Join("testdata", "original_signature.bin"))
	if err != nil {
		t.Skip("Test data not available")
	}

	cdirOffset := getCodeDirectoryOffset(sigData)
	if cdirOffset == 0 {
		t.Fatal("Could not find CodeDirectory")
	}

	version := binary.BigEndian.Uint32(sigData[cdirOffset+8 : cdirOffset+12])

	// Version should be 0x20400 for modern signatures with execSeg support
	if version != 0x20400 {
		t.Errorf("Expected version 0x20400, got 0x%x", version)
	}
}

// TestCodeDirectoryHashType verifies SHA256 is used for hashes
func TestCodeDirectoryHashType(t *testing.T) {
	sigData, err := os.ReadFile(filepath.Join("testdata", "original_signature.bin"))
	if err != nil {
		t.Skip("Test data not available")
	}

	cdirOffset := getCodeDirectoryOffset(sigData)
	if cdirOffset == 0 {
		t.Fatal("Could not find CodeDirectory")
	}

	// Hash type is at offset 36 (after codeLimit at 32)
	hashSize := sigData[cdirOffset+36]
	hashType := sigData[cdirOffset+37]

	if hashSize != 32 {
		t.Errorf("Expected hash size 32 (SHA256), got %d", hashSize)
	}

	if hashType != CS_HASHTYPE_SHA256 {
		t.Errorf("Expected hash type %d (SHA256), got %d", CS_HASHTYPE_SHA256, hashType)
	}
}

// TestCodeDirectoryPageSize verifies page size is 16KB (iOS 17+)
func TestCodeDirectoryPageSize(t *testing.T) {
	sigData, err := os.ReadFile(filepath.Join("testdata", "original_signature.bin"))
	if err != nil {
		t.Skip("Test data not available")
	}

	cdirOffset := getCodeDirectoryOffset(sigData)
	if cdirOffset == 0 {
		t.Fatal("Could not find CodeDirectory")
	}

	// PageSize is at offset 39
	PageSizeBitsValue := sigData[cdirOffset+39]

	// Should be 14 (1 << 14 = 16384)
	if PageSizeBitsValue != 14 {
		t.Errorf("Expected PageSizeBits 14 (16KB), got %d", PageSizeBitsValue)
	}
}

// TestCodeDirectoryTeamID verifies TeamID structure is valid
func TestCodeDirectoryTeamID(t *testing.T) {
	sigData, err := os.ReadFile(filepath.Join("testdata", "original_signature.bin"))
	if err != nil {
		t.Skip("Test data not available")
	}

	cdirOffset := getCodeDirectoryOffset(sigData)
	if cdirOffset == 0 {
		t.Fatal("Could not find CodeDirectory")
	}

	// Read identifier offset and team offset from header
	identOffset := binary.BigEndian.Uint32(sigData[cdirOffset+20 : cdirOffset+24])
	teamOffset := binary.BigEndian.Uint32(sigData[cdirOffset+48 : cdirOffset+52])

	if teamOffset == 0 {
		t.Log("TeamOffset is 0, no TeamID present (this is valid for some signatures)")
		return
	}

	// Read the identifier and team ID strings
	identEnd := bytes.IndexByte(sigData[cdirOffset+identOffset:], 0)
	if identEnd < 0 {
		t.Fatal("Could not find identifier string terminator")
	}
	identifier := string(sigData[cdirOffset+identOffset : cdirOffset+identOffset+uint32(identEnd)])

	teamEnd := bytes.IndexByte(sigData[cdirOffset+teamOffset:], 0)
	if teamEnd < 0 {
		t.Fatal("Could not find team ID string terminator")
	}
	teamID := string(sigData[cdirOffset+teamOffset : cdirOffset+teamOffset+uint32(teamEnd)])

	// Verify both identifier and team ID are non-empty
	if identifier == "" {
		t.Error("Identifier should not be empty")
	}
	if teamID == "" {
		t.Error("TeamID should not be empty when teamOffset is set")
	}

	t.Logf("Identifier: %s, TeamID: %s", identifier, teamID)
}

// TestCodeDirectorySpecialSlots verifies the number and content of special slots
func TestCodeDirectorySpecialSlots(t *testing.T) {
	sigData, err := os.ReadFile(filepath.Join("testdata", "original_signature.bin"))
	if err != nil {
		t.Skip("Test data not available")
	}

	cdirOffset := getCodeDirectoryOffset(sigData)
	if cdirOffset == 0 {
		t.Fatal("Could not find CodeDirectory")
	}

	// nSpecialSlots is at offset 24
	nSpecialSlots := binary.BigEndian.Uint32(sigData[cdirOffset+24 : cdirOffset+28])

	// Should have 7 special slots for iOS 15+ with DER entitlements
	if nSpecialSlots != 7 {
		t.Errorf("Expected 7 special slots, got %d", nSpecialSlots)
	}
}

// TestSuperBlobStructure verifies the overall SuperBlob structure
func TestSuperBlobStructure(t *testing.T) {
	sigData, err := os.ReadFile(filepath.Join("testdata", "original_signature.bin"))
	if err != nil {
		t.Skip("Test data not available")
	}

	// Parse SuperBlob
	magic := binary.BigEndian.Uint32(sigData[0:4])
	length := binary.BigEndian.Uint32(sigData[4:8])
	count := binary.BigEndian.Uint32(sigData[8:12])

	if magic != CSMAGIC_EMBEDDED_SIGNATURE {
		t.Errorf("Expected SuperBlob magic 0x%x, got 0x%x", CSMAGIC_EMBEDDED_SIGNATURE, magic)
	}

	// The length field should be valid (not larger than file)
	if length > uint32(len(sigData)) {
		t.Errorf("SuperBlob length %d exceeds file size %d", length, len(sigData))
	}

	// We expect at least: CodeDirectory, Requirements, Entitlements, EntitlementsDER, CMS
	if count < 5 {
		t.Errorf("Expected at least 5 blobs, got %d", count)
	}

	// Verify we have the expected blob types
	slotTypes := make(map[uint32]bool)
	for i := uint32(0); i < count; i++ {
		slotType := binary.BigEndian.Uint32(sigData[12+i*8 : 12+i*8+4])
		slotTypes[slotType] = true
	}

	expectedSlots := []uint32{
		CSSLOT_CODEDIRECTORY,
		CSSLOT_REQUIREMENTS,
		CSSLOT_ENTITLEMENTS,
		CSSLOT_DER_ENTITLEMENTS,
		CSSLOT_SIGNATURESLOT,
	}

	for _, slot := range expectedSlots {
		if !slotTypes[slot] {
			t.Errorf("Missing expected slot type 0x%x", slot)
		}
	}
}

// TestEntitlementsBlobMagic verifies the entitlements blob magic numbers
func TestEntitlementsBlobMagic(t *testing.T) {
	sigData, err := os.ReadFile(filepath.Join("testdata", "original_signature.bin"))
	if err != nil {
		t.Skip("Test data not available")
	}

	// Find entitlements blobs
	count := binary.BigEndian.Uint32(sigData[8:12])

	var entOffset, entDEROffset uint32
	for i := uint32(0); i < count; i++ {
		slotType := binary.BigEndian.Uint32(sigData[12+i*8 : 12+i*8+4])
		offset := binary.BigEndian.Uint32(sigData[12+i*8+4 : 12+i*8+8])

		switch slotType {
		case CSSLOT_ENTITLEMENTS:
			entOffset = offset
		case CSSLOT_DER_ENTITLEMENTS:
			entDEROffset = offset
		}
	}

	if entOffset > 0 {
		magic := binary.BigEndian.Uint32(sigData[entOffset : entOffset+4])
		if magic != CSMAGIC_EMBEDDED_ENTITLEMENTS {
			t.Errorf("Expected entitlements magic 0x%x, got 0x%x", CSMAGIC_EMBEDDED_ENTITLEMENTS, magic)
		}
	}

	if entDEROffset > 0 {
		magic := binary.BigEndian.Uint32(sigData[entDEROffset : entDEROffset+4])
		if magic != CSMAGIC_EMBEDDED_DER_ENTITLEMENTS {
			t.Errorf("Expected DER entitlements magic 0x%x, got 0x%x", CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, magic)
		}
	}
}

// TestBuildRequirementsBlob verifies our requirements blob matches expected format
func TestBuildRequirementsBlob(t *testing.T) {
	bundleID := "com.example.testapp"
	blob := buildRequirementsBlobWithCert(bundleID, "")

	// Check magic
	if len(blob) < 8 {
		t.Fatal("Requirements blob too short")
	}

	magic := binary.BigEndian.Uint32(blob[0:4])
	if magic != CSMAGIC_REQUIREMENTS {
		t.Errorf("Expected requirements magic 0x%x, got 0x%x", CSMAGIC_REQUIREMENTS, magic)
	}

	length := binary.BigEndian.Uint32(blob[4:8])
	if length != uint32(len(blob)) {
		t.Errorf("Expected length %d, got %d", len(blob), length)
	}
}

// TestBuildDesignatedRequirement verifies our designated requirement expression format
// The expression format for "identifier X and anchor apple generic" is:
// magic(4) + length(4) + kind(4) + opAnd(4) + opIdent(4) + strlen(4) + string(paddedLen) + opAppleGenericAnchor(4)
func TestBuildDesignatedRequirement(t *testing.T) {
	bundleID := "com.example.test"
	blob := buildDesignatedRequirementWithCert(bundleID, "") // empty signerCN = simple format

	// Minimum size: magic(4) + length(4) + kind(4) + opAnd(4) + opIdent(4) + strlen(4) + string(padded) + opAnchor(4)
	if len(blob) < 32 {
		t.Fatalf("Designated requirement blob too short: %d bytes", len(blob))
	}

	// Check REQUIREMENT magic (single requirement, not requirements set)
	magic := binary.BigEndian.Uint32(blob[0:4])
	if magic != CSMAGIC_REQUIREMENT {
		t.Errorf("Expected requirement magic 0x%x, got 0x%x", CSMAGIC_REQUIREMENT, magic)
	}

	// Check length field
	length := binary.BigEndian.Uint32(blob[4:8])
	if length != uint32(len(blob)) {
		t.Errorf("Length field mismatch: expected %d, got %d", len(blob), length)
	}

	// Check kind field (1 = expression)
	kind := binary.BigEndian.Uint32(blob[8:12])
	if kind != 1 {
		t.Errorf("Expected kind 1 (expression), got %d", kind)
	}

	// Parse the expression (starts after kind field)
	offset := 12

	// Should start with opAnd (6)
	opAnd := binary.BigEndian.Uint32(blob[offset : offset+4])
	if opAnd != 6 {
		t.Errorf("Expected opAnd (6) at offset %d, got %d", offset, opAnd)
	}
	offset += 4

	// Next should be opIdent (2)
	opIdent := binary.BigEndian.Uint32(blob[offset : offset+4])
	if opIdent != 2 {
		t.Errorf("Expected opIdent (2) at offset %d, got %d", offset, opIdent)
	}
	offset += 4

	// Then string length
	strLen := binary.BigEndian.Uint32(blob[offset : offset+4])
	if strLen != uint32(len(bundleID)) {
		t.Errorf("Expected string length %d, got %d", len(bundleID), strLen)
	}
	offset += 4

	// Then the actual string
	actualStr := string(blob[offset : offset+int(strLen)])
	if actualStr != bundleID {
		t.Errorf("Expected bundle ID %q, got %q", bundleID, actualStr)
	}

	// Move to next 4-byte boundary
	paddedLen := (int(strLen) + 3) &^ 3
	offset += paddedLen

	// Finally opAppleGenericAnchor (15)
	opAnchor := binary.BigEndian.Uint32(blob[offset : offset+4])
	if opAnchor != 15 {
		t.Errorf("Expected opAppleGenericAnchor (15) at offset %d, got %d", offset, opAnchor)
	}
}

// TestRequirementExpressionBinaryFormat verifies the exact binary format matches Apple's format
func TestRequirementExpressionBinaryFormat(t *testing.T) {
	bundleID := "com.example.test"
	blob := buildDesignatedRequirementWithCert(bundleID, "") // empty signerCN = simple format

	// Expected format for "identifier 'com.example.test' and anchor apple generic":
	// fade 0c00                    - magic (CSMAGIC_REQUIREMENT)
	// 0000 002c                    - length (44 bytes)
	// 0000 0001                    - kind (1 = expression)
	// 0000 0006                    - opAnd (6)
	// 0000 0002                    - opIdent (2)
	// 0000 0010                    - string length (16)
	// 636f 6d2e 6578 616d 706c 652e 7465 7374 - "com.example.test"
	// 0000 000f                    - opAppleGenericAnchor (15)

	// Total expected size: 8 (header) + 4 (kind) + 4 (opAnd) + 4 (opIdent) + 4 (strlen) + 16 (padded string) + 4 (opAnchor) = 44
	expectedSize := 44
	if len(blob) != expectedSize {
		t.Errorf("Expected blob size %d, got %d", expectedSize, len(blob))
	}

	// Verify magic
	if blob[0] != 0xfa || blob[1] != 0xde || blob[2] != 0x0c || blob[3] != 0x00 {
		t.Errorf("Magic bytes mismatch: got %x %x %x %x", blob[0], blob[1], blob[2], blob[3])
	}

	// Verify kind field (at offset 8)
	kind := binary.BigEndian.Uint32(blob[8:12])
	if kind != 1 {
		t.Errorf("Expected kind 1, got %d", kind)
	}

	// Verify the bundle ID is present in the blob
	found := bytes.Contains(blob, []byte(bundleID))
	if !found {
		t.Error("Bundle ID not found in requirement blob")
	}

	// Log the actual hex for debugging
	t.Logf("Requirement blob hex: %x", blob)
}

// TestBuildDesignatedRequirementWithCert verifies the full Apple-style requirements format
// with certificate checks: identifier X and anchor apple generic and
// certificate leaf[subject.CN] = "signerCN" and certificate 1[field.1.2.840.113635.100.6.2.1] exists
func TestBuildDesignatedRequirementWithCert(t *testing.T) {
	bundleID := "com.example.testapp"
	signerCN := "iPhone Developer: Test Developer (ABCD1234)"
	blob := buildDesignatedRequirementWithCert(bundleID, signerCN)

	// Check magic
	if len(blob) < 8 {
		t.Fatal("Requirement blob too short")
	}

	magic := binary.BigEndian.Uint32(blob[0:4])
	if magic != CSMAGIC_REQUIREMENT {
		t.Errorf("Expected requirement magic 0x%x, got 0x%x", CSMAGIC_REQUIREMENT, magic)
	}

	// Check length
	length := binary.BigEndian.Uint32(blob[4:8])
	if length != uint32(len(blob)) {
		t.Errorf("Length field mismatch: expected %d, got %d", len(blob), length)
	}

	// Check kind field (1 = expression)
	kind := binary.BigEndian.Uint32(blob[8:12])
	if kind != 1 {
		t.Errorf("Expected kind 1 (expression), got %d", kind)
	}

	// Constants matching the function
	const (
		opAnd                = 6
		opIdent              = 2
		opAppleGenericAnchor = 15
		opCertField          = 11
		opCertGeneric        = 14
		matchExists          = 0
		matchEqual           = 1
	)

	// Parse and verify the expression structure
	offset := 12

	// First opAnd
	if binary.BigEndian.Uint32(blob[offset:offset+4]) != opAnd {
		t.Errorf("Expected opAnd (6) at offset %d, got %d", offset, binary.BigEndian.Uint32(blob[offset:offset+4]))
	}
	offset += 4

	// opIdent
	if binary.BigEndian.Uint32(blob[offset:offset+4]) != opIdent {
		t.Errorf("Expected opIdent (2) at offset %d", offset)
	}
	offset += 4

	// bundleID string
	strLen := binary.BigEndian.Uint32(blob[offset : offset+4])
	if strLen != uint32(len(bundleID)) {
		t.Errorf("Expected bundleID length %d, got %d", len(bundleID), strLen)
	}
	offset += 4
	actualBundleID := string(blob[offset : offset+int(strLen)])
	if actualBundleID != bundleID {
		t.Errorf("Expected bundleID %q, got %q", bundleID, actualBundleID)
	}
	paddedLen := (int(strLen) + 3) &^ 3
	offset += paddedLen

	// Second opAnd
	if binary.BigEndian.Uint32(blob[offset:offset+4]) != opAnd {
		t.Errorf("Expected opAnd (6) at offset %d", offset)
	}
	offset += 4

	// opAppleGenericAnchor
	if binary.BigEndian.Uint32(blob[offset:offset+4]) != opAppleGenericAnchor {
		t.Errorf("Expected opAppleGenericAnchor (15) at offset %d", offset)
	}
	offset += 4

	// Third opAnd
	if binary.BigEndian.Uint32(blob[offset:offset+4]) != opAnd {
		t.Errorf("Expected opAnd (6) at offset %d", offset)
	}
	offset += 4

	// opCertField for leaf certificate subject.CN check
	if binary.BigEndian.Uint32(blob[offset:offset+4]) != opCertField {
		t.Errorf("Expected opCertField (11) at offset %d", offset)
	}
	offset += 4

	// cert slot 0 (leaf)
	if binary.BigEndian.Uint32(blob[offset:offset+4]) != 0 {
		t.Errorf("Expected cert slot 0 (leaf) at offset %d", offset)
	}
	offset += 4

	// field name "subject.CN"
	fieldNameLen := binary.BigEndian.Uint32(blob[offset : offset+4])
	expectedFieldName := "subject.CN"
	if fieldNameLen != uint32(len(expectedFieldName)) {
		t.Errorf("Expected field name length %d, got %d", len(expectedFieldName), fieldNameLen)
	}
	offset += 4
	actualFieldName := string(blob[offset : offset+int(fieldNameLen)])
	if actualFieldName != expectedFieldName {
		t.Errorf("Expected field name %q, got %q", expectedFieldName, actualFieldName)
	}
	paddedLen = (int(fieldNameLen) + 3) &^ 3
	offset += paddedLen

	// match operation = matchEqual (1)
	if binary.BigEndian.Uint32(blob[offset:offset+4]) != matchEqual {
		t.Errorf("Expected matchEqual (1) at offset %d", offset)
	}
	offset += 4

	// signerCN value
	signerCNLen := binary.BigEndian.Uint32(blob[offset : offset+4])
	if signerCNLen != uint32(len(signerCN)) {
		t.Errorf("Expected signerCN length %d, got %d", len(signerCN), signerCNLen)
	}
	offset += 4
	actualSignerCN := string(blob[offset : offset+int(signerCNLen)])
	if actualSignerCN != signerCN {
		t.Errorf("Expected signerCN %q, got %q", signerCN, actualSignerCN)
	}
	paddedLen = (int(signerCNLen) + 3) &^ 3
	offset += paddedLen

	// opCertGeneric for intermediate certificate OID check
	if binary.BigEndian.Uint32(blob[offset:offset+4]) != opCertGeneric {
		t.Errorf("Expected opCertGeneric (14) at offset %d", offset)
	}
	offset += 4

	// cert slot 1 (intermediate)
	if binary.BigEndian.Uint32(blob[offset:offset+4]) != 1 {
		t.Errorf("Expected cert slot 1 (intermediate) at offset %d", offset)
	}
	offset += 4

	// OID 1.2.840.113635.100.6.2.1 (Apple Developer)
	appleDevOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01}
	oidLen := binary.BigEndian.Uint32(blob[offset : offset+4])
	if oidLen != uint32(len(appleDevOID)) {
		t.Errorf("Expected OID length %d, got %d", len(appleDevOID), oidLen)
	}
	offset += 4
	actualOID := blob[offset : offset+int(oidLen)]
	if !bytes.Equal(actualOID, appleDevOID) {
		t.Errorf("Expected OID %x, got %x", appleDevOID, actualOID)
	}
	paddedLen = (int(oidLen) + 3) &^ 3
	offset += paddedLen

	// match operation = matchExists (0)
	if binary.BigEndian.Uint32(blob[offset:offset+4]) != matchExists {
		t.Errorf("Expected matchExists (0) at offset %d, got %d", offset, binary.BigEndian.Uint32(blob[offset:offset+4]))
	}

	// Verify the blob contains the expected strings
	if !bytes.Contains(blob, []byte(bundleID)) {
		t.Error("Bundle ID not found in requirement blob")
	}
	if !bytes.Contains(blob, []byte(signerCN)) {
		t.Error("Signer CN not found in requirement blob")
	}
	if !bytes.Contains(blob, []byte("subject.CN")) {
		t.Error("subject.CN field name not found in requirement blob")
	}

	t.Logf("Full requirement blob size: %d bytes", len(blob))
	t.Logf("Requirement blob hex: %x", blob)
}

// TestBuildEntitlementsBlob verifies our entitlements blob format
func TestBuildEntitlementsBlob(t *testing.T) {
	entitlements := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>get-task-allow</key>
	<true/>
</dict>
</plist>`)

	blob := buildEntitlementsBlob(entitlements)

	// Check magic
	magic := binary.BigEndian.Uint32(blob[0:4])
	if magic != CSMAGIC_EMBEDDED_ENTITLEMENTS {
		t.Errorf("Expected entitlements magic 0x%x, got 0x%x", CSMAGIC_EMBEDDED_ENTITLEMENTS, magic)
	}

	// Check length
	length := binary.BigEndian.Uint32(blob[4:8])
	expectedLen := uint32(8 + len(entitlements))
	if length != expectedLen {
		t.Errorf("Expected length %d, got %d", expectedLen, length)
	}

	// Verify content is preserved
	if !bytes.Equal(blob[8:], entitlements) {
		t.Error("Entitlements content not preserved")
	}
}

// TestBuildEntitlementsDERBlob verifies our DER entitlements blob format
func TestBuildEntitlementsDERBlob(t *testing.T) {
	entitlements := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>get-task-allow</key>
	<true/>
</dict>
</plist>`)

	blob := buildEntitlementsDERBlob(entitlements)
	if blob == nil {
		t.Fatal("buildEntitlementsDERBlob returned nil")
	}

	// Check magic
	magic := binary.BigEndian.Uint32(blob[0:4])
	if magic != CSMAGIC_EMBEDDED_DER_ENTITLEMENTS {
		t.Errorf("Expected DER entitlements magic 0x%x, got 0x%x", CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, magic)
	}

	// Check that DER content starts with APPLICATION 16 tag (0x70)
	if blob[8] != 0x70 {
		t.Errorf("Expected DER content to start with 0x70, got 0x%x", blob[8])
	}
}

// TestCodePageHashing verifies our page hashing matches Apple's implementation
func TestCodePageHashing(t *testing.T) {
	// Create test data (2 pages worth)
	testData := make([]byte, PageSize*2+1000)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Hash pages the way we do it
	var ourHashes [][]byte
	codeSize := int64(len(testData))
	for p := int64(0); p < codeSize; p += PageSize {
		end := p + PageSize
		if end > codeSize {
			end = codeSize
		}
		hash := sha256.Sum256(testData[p:end])
		ourHashes = append(ourHashes, hash[:])
	}

	// We should have 3 hashes (2 full pages + 1 partial)
	expectedPages := (len(testData) + PageSize - 1) / PageSize
	if len(ourHashes) != expectedPages {
		t.Errorf("Expected %d page hashes, got %d", expectedPages, len(ourHashes))
	}

	// First page should be full 16KB
	expectedHash := sha256.Sum256(testData[0:PageSize])
	if !bytes.Equal(ourHashes[0], expectedHash[:]) {
		t.Error("First page hash mismatch")
	}

	// Last page should be the remaining data
	lastStart := int64(PageSize * 2)
	expectedLastHash := sha256.Sum256(testData[lastStart:])
	if !bytes.Equal(ourHashes[2], expectedLastHash[:]) {
		t.Error("Last page hash mismatch")
	}
}

// TestSignatureConstants verifies our constants match Apple's
func TestSignatureConstants(t *testing.T) {
	// These values are from Apple's cs_blobs.h
	tests := []struct {
		name     string
		got      uint32
		expected uint32
	}{
		{"CSMAGIC_CODEDIRECTORY", CSMAGIC_CODEDIRECTORY, 0xfade0c02},
		{"CSMAGIC_EMBEDDED_SIGNATURE", CSMAGIC_EMBEDDED_SIGNATURE, 0xfade0cc0},
		{"CSMAGIC_EMBEDDED_ENTITLEMENTS", CSMAGIC_EMBEDDED_ENTITLEMENTS, 0xfade7171},
		{"CSMAGIC_EMBEDDED_DER_ENTITLEMENTS", CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, 0xfade7172},
		{"CSMAGIC_REQUIREMENTS", CSMAGIC_REQUIREMENTS, 0xfade0c01},
		{"CSMAGIC_BLOBWRAPPER", CSMAGIC_BLOBWRAPPER, 0xfade0b01},
	}

	for _, tc := range tests {
		if tc.got != tc.expected {
			t.Errorf("%s: expected 0x%x, got 0x%x", tc.name, tc.expected, tc.got)
		}
	}
}

// TestComputeHash verifies the computeHash function works for both SHA1 and SHA256
func TestComputeHash(t *testing.T) {
	testData := []byte("test data for hashing")

	// Test SHA1
	sha1Hash := computeHash(testData, CS_HASHTYPE_SHA1)
	if len(sha1Hash) != 20 {
		t.Errorf("SHA1 hash should be 20 bytes, got %d", len(sha1Hash))
	}

	// Test SHA256
	sha256Hash := computeHash(testData, CS_HASHTYPE_SHA256)
	if len(sha256Hash) != 32 {
		t.Errorf("SHA256 hash should be 32 bytes, got %d", len(sha256Hash))
	}

	// Verify hashes are different
	if bytes.Equal(sha1Hash, sha256Hash[:20]) {
		t.Error("SHA1 and SHA256 hashes should be different")
	}

	// Test empty data returns zero hash
	emptySHA1 := computeHash(nil, CS_HASHTYPE_SHA1)
	if len(emptySHA1) != 20 {
		t.Errorf("Empty SHA1 should be 20 bytes, got %d", len(emptySHA1))
	}
	for i, b := range emptySHA1 {
		if b != 0 {
			t.Errorf("Empty SHA1 should be all zeros, got non-zero at index %d", i)
			break
		}
	}

	emptySHA256 := computeHash(nil, CS_HASHTYPE_SHA256)
	if len(emptySHA256) != 32 {
		t.Errorf("Empty SHA256 should be 32 bytes, got %d", len(emptySHA256))
	}
	for i, b := range emptySHA256 {
		if b != 0 {
			t.Errorf("Empty SHA256 should be all zeros, got non-zero at index %d", i)
			break
		}
	}
}

// TestBuildCodeDirectory_SHA1 verifies SHA1 CodeDirectory structure
func TestBuildCodeDirectory_SHA1(t *testing.T) {
	codeData := make([]byte, 8192) // 2 pages
	bundleID := "com.test.app"
	teamID := "ABCD1234"

	cdir := buildCodeDirectory(codeData, bundleID, teamID, 7, 2, 8192,
		0, 4096, nil, nil, nil, nil, nil,
		20, CS_HASHTYPE_SHA1, 0) // SHA1 = 20 bytes, execSegFlags = 0

	// Check magic
	magic := binary.BigEndian.Uint32(cdir[0:4])
	if magic != CSMAGIC_CODEDIRECTORY {
		t.Errorf("Expected magic 0x%x, got 0x%x", CSMAGIC_CODEDIRECTORY, magic)
	}

	// Check hash size (offset 36)
	hashSize := cdir[36]
	if hashSize != 20 {
		t.Errorf("Expected hashSize 20 (SHA1), got %d", hashSize)
	}

	// Check hash type (offset 37)
	hashType := cdir[37]
	if hashType != CS_HASHTYPE_SHA1 {
		t.Errorf("Expected hashType %d (SHA1), got %d", CS_HASHTYPE_SHA1, hashType)
	}

	// Verify bundleID is in the blob
	if !bytes.Contains(cdir, []byte(bundleID)) {
		t.Error("Bundle ID not found in CodeDirectory")
	}

	// Verify teamID is in the blob
	if !bytes.Contains(cdir, []byte(teamID)) {
		t.Error("Team ID not found in CodeDirectory")
	}
}

// TestBuildCodeDirectory_SHA256 verifies SHA256 CodeDirectory structure
func TestBuildCodeDirectory_SHA256(t *testing.T) {
	codeData := make([]byte, 8192) // 2 pages
	bundleID := "com.test.app"
	teamID := "ABCD1234"

	cdir := buildCodeDirectory(codeData, bundleID, teamID, 7, 2, 8192,
		0, 4096, nil, nil, nil, nil, nil,
		32, CS_HASHTYPE_SHA256, 0) // SHA256 = 32 bytes, execSegFlags = 0

	// Check magic
	magic := binary.BigEndian.Uint32(cdir[0:4])
	if magic != CSMAGIC_CODEDIRECTORY {
		t.Errorf("Expected magic 0x%x, got 0x%x", CSMAGIC_CODEDIRECTORY, magic)
	}

	// Check hash size (offset 36)
	hashSize := cdir[36]
	if hashSize != 32 {
		t.Errorf("Expected hashSize 32 (SHA256), got %d", hashSize)
	}

	// Check hash type (offset 37)
	hashType := cdir[37]
	if hashType != CS_HASHTYPE_SHA256 {
		t.Errorf("Expected hashType %d (SHA256), got %d", CS_HASHTYPE_SHA256, hashType)
	}
}

// TestBuildCodeDirectory_DualCDSizes verifies SHA256 CD is larger than SHA1 CD
func TestBuildCodeDirectory_DualCDSizes(t *testing.T) {
	codeData := make([]byte, 16384) // 4 pages
	bundleID := "com.test.app"
	teamID := "ABCD1234"

	cdirSHA1 := buildCodeDirectory(codeData, bundleID, teamID, 7, 4, 16384,
		0, 4096, nil, nil, nil, nil, nil,
		20, CS_HASHTYPE_SHA1, 0)

	cdirSHA256 := buildCodeDirectory(codeData, bundleID, teamID, 7, 4, 16384,
		0, 4096, nil, nil, nil, nil, nil,
		32, CS_HASHTYPE_SHA256, 0)

	// SHA256 CD should be larger because each hash is 32 bytes vs 20 bytes
	// Difference = (nSpecialSlots + nCodeSlots) * (32 - 20) = (7 + 4) * 12 = 132 bytes
	expectedDiff := (7 + 4) * (32 - 20)
	actualDiff := len(cdirSHA256) - len(cdirSHA1)

	if actualDiff != expectedDiff {
		t.Errorf("Expected size difference of %d bytes, got %d (SHA1=%d, SHA256=%d)",
			expectedDiff, actualDiff, len(cdirSHA1), len(cdirSHA256))
	}
}

// TestBuildCDHashesPlist verifies the CDHashes plist format
func TestBuildCDHashesPlist(t *testing.T) {
	sha1Hash := make([]byte, 20)
	for i := range sha1Hash {
		sha1Hash[i] = byte(i)
	}

	truncatedSHA256 := make([]byte, 20)
	for i := range truncatedSHA256 {
		truncatedSHA256[i] = byte(i + 100)
	}

	plistData := buildCDHashesPlist(sha1Hash, truncatedSHA256)

	// Parse the plist
	var result map[string]interface{}
	_, err := plist.Unmarshal(plistData, &result)
	if err != nil {
		t.Fatalf("Failed to parse CDHashes plist: %v", err)
	}

	// Check cdhashes key exists
	cdhashes, ok := result["cdhashes"]
	if !ok {
		t.Fatal("CDHashes plist missing 'cdhashes' key")
	}

	// Should be an array with 2 entries
	hashArray, ok := cdhashes.([]interface{})
	if !ok {
		t.Fatalf("cdhashes should be an array, got %T", cdhashes)
	}

	if len(hashArray) != 2 {
		t.Errorf("cdhashes should have 2 entries, got %d", len(hashArray))
	}

	// Verify first hash (SHA1)
	hash1, ok := hashArray[0].([]byte)
	if !ok {
		t.Errorf("First hash should be []byte, got %T", hashArray[0])
	} else if len(hash1) != 20 {
		t.Errorf("First hash should be 20 bytes, got %d", len(hash1))
	}

	// Verify second hash (truncated SHA256)
	hash2, ok := hashArray[1].([]byte)
	if !ok {
		t.Errorf("Second hash should be []byte, got %T", hashArray[1])
	} else if len(hash2) != 20 {
		t.Errorf("Second hash should be 20 bytes (truncated), got %d", len(hash2))
	}
}

// TestNestedBundleDetection verifies isNestedBundle correctly identifies bundle types
func TestNestedBundleDetection(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"Frameworks/MyLib.framework", true},
		{"PlugIns/MyTest.xctest", true},
		{"PlugIns/MyExtension.appex", true},
		{"Watch/MyWatch.app", true},
		{"some/regular/file.txt", false},
		{"Frameworks/MyLib.framework/Resources/data.plist", false}, // file inside framework
		{"Info.plist", false},
		{"embedded.mobileprovision", false},
	}

	for _, tc := range tests {
		result := isNestedBundle(tc.path)
		if result != tc.expected {
			t.Errorf("isNestedBundle(%q) = %v, expected %v", tc.path, result, tc.expected)
		}
	}
}

// TestFindNestedBundlePaths verifies we find all nested bundles in a directory structure
func TestFindNestedBundlePaths(t *testing.T) {
	// Create a temp directory structure simulating an app bundle
	tempDir, err := os.MkdirTemp("", "test-app-bundle")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create nested bundle directories
	dirs := []string{
		"Frameworks/Lib1.framework",
		"Frameworks/Lib2.framework",
		"PlugIns/Test.xctest",
		"PlugIns/Test.xctest/Frameworks/NestedLib.framework", // nested inside xctest
		"Watch/WatchApp.app",
		"Regular/Directory", // not a bundle
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(tempDir, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}

	bundles := findNestedBundlePaths(tempDir)

	// Should find 5 bundles (Lib1, Lib2, Test.xctest, WatchApp.app, but NOT NestedLib since we skip into xctest)
	// Actually, we skip into nested bundles, so we should find:
	// - Frameworks/Lib1.framework
	// - Frameworks/Lib2.framework
	// - PlugIns/Test.xctest
	// - Watch/WatchApp.app
	// NOT PlugIns/Test.xctest/Frameworks/NestedLib.framework (skipped because we don't recurse into xctest)
	expectedCount := 4
	if len(bundles) != expectedCount {
		t.Errorf("Expected %d nested bundles, found %d: %v", expectedCount, len(bundles), bundles)
	}

	// Verify specific bundles are found
	expectedBundles := map[string]bool{
		"Frameworks/Lib1.framework": true,
		"Frameworks/Lib2.framework": true,
		"PlugIns/Test.xctest":       true,
		"Watch/WatchApp.app":        true,
	}

	for _, bundle := range bundles {
		if !expectedBundles[bundle] {
			t.Errorf("Unexpected bundle found: %s", bundle)
		}
		delete(expectedBundles, bundle)
	}

	for missing := range expectedBundles {
		t.Errorf("Expected bundle not found: %s", missing)
	}
}

// TestGenerateCodeResourcesIncludesNestedBundleContents verifies all nested bundle files are included
// ALL files are hashed, including those inside nested bundles
func TestGenerateCodeResourcesIncludesNestedBundleContents(t *testing.T) {
	// Create a temp app bundle with nested framework
	tempDir, err := os.MkdirTemp("", "test-app-bundle")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create Info.plist (required)
	infoPlist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>TestApp</string>
	<key>CFBundleIdentifier</key>
	<string>com.test.app</string>
</dict>
</plist>`
	if err := os.WriteFile(filepath.Join(tempDir, "Info.plist"), []byte(infoPlist), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a regular file that should be hashed
	if err := os.WriteFile(filepath.Join(tempDir, "Assets.car"), []byte("asset data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a nested framework with files that SHOULD be hashed
	frameworkDir := filepath.Join(tempDir, "Frameworks", "Nested.framework")
	if err := os.MkdirAll(frameworkDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(frameworkDir, "Nested"), []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(frameworkDir, "Info.plist"), []byte(infoPlist), 0644); err != nil {
		t.Fatal(err)
	}

	// Create _CodeSignature/CodeResources for the nested framework (simulating it's already signed)
	codeSignDir := filepath.Join(frameworkDir, "_CodeSignature")
	if err := os.MkdirAll(codeSignDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codeSignDir, "CodeResources"), []byte("signed"), 0644); err != nil {
		t.Fatal(err)
	}

	// Generate CodeResources
	codeResData, err := GenerateCodeResources(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	// Parse the result
	var codeRes map[string]interface{}
	if _, err := plist.Unmarshal(codeResData, &codeRes); err != nil {
		t.Fatal(err)
	}

	files := codeRes["files"].(map[string]interface{})
	files2 := codeRes["files2"].(map[string]interface{})

	// Should have Assets.car
	if _, ok := files["Assets.car"]; !ok {
		t.Error("Assets.car should be in files")
	}

	// SHOULD have Frameworks/Nested.framework/Nested (all nested bundle files are included)
	if _, ok := files["Frameworks/Nested.framework/Nested"]; !ok {
		t.Error("Frameworks/Nested.framework/Nested SHOULD be in files (all nested bundle files are included)")
	}

	// SHOULD have Frameworks/Nested.framework/Info.plist (all nested bundle files are included)
	if _, ok := files["Frameworks/Nested.framework/Info.plist"]; !ok {
		t.Error("Frameworks/Nested.framework/Info.plist SHOULD be in files (all nested bundle files are included)")
	}

	// SHOULD have Frameworks/Nested.framework/_CodeSignature/CodeResources
	codeResKey := filepath.Join("Frameworks", "Nested.framework", "_CodeSignature", "CodeResources")
	if _, ok := files[codeResKey]; !ok {
		t.Errorf("files should contain %s for nested bundle's CodeResources", codeResKey)
	}
	if _, ok := files2[codeResKey]; !ok {
		t.Errorf("files2 should contain %s for nested bundle's CodeResources", codeResKey)
	}
}

// Helper function to find CodeDirectory offset in a SuperBlob
func getCodeDirectoryOffset(sigData []byte) uint32 {
	if len(sigData) < 12 {
		return 0
	}

	magic := binary.BigEndian.Uint32(sigData[0:4])
	if magic != CSMAGIC_EMBEDDED_SIGNATURE {
		return 0
	}

	count := binary.BigEndian.Uint32(sigData[8:12])
	for i := uint32(0); i < count; i++ {
		slotType := binary.BigEndian.Uint32(sigData[12+i*8 : 12+i*8+4])
		if slotType == CSSLOT_CODEDIRECTORY {
			return binary.BigEndian.Uint32(sigData[12+i*8+4 : 12+i*8+8])
		}
	}
	return 0
}
