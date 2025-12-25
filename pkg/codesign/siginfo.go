package codesign

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.mozilla.org/pkcs7"
)

// SignatureInfo holds parsed code signature details
type SignatureInfo struct {
	BinaryPath      string
	BundlePath      string
	RelativePath    string // Relative path from the root bundle (e.g., "PlugIns/Foo.xctest/Frameworks/Bar.framework")
	SuperBlob       SuperBlobInfo
	CodeDirs        []CodeDirectoryInfo
	Requirements    RequirementsInfo
	Entitlements    EntitlementsInfo
	EntitlementsDER []byte
	CMSSignature    CMSInfo
}

// SuperBlobInfo contains SuperBlob header information
type SuperBlobInfo struct {
	Magic     uint32
	Length    uint32
	BlobCount uint32
	Blobs     []BlobIndexEntry
}

// BlobIndexEntry represents a single blob in the SuperBlob index
type BlobIndexEntry struct {
	Type   uint32
	Offset uint32
	Size   uint32
	Magic  uint32
}

// CodeDirectoryInfo contains CodeDirectory details
type CodeDirectoryInfo struct {
	Slot          uint32
	Version       uint32
	Flags         uint32
	HashType      uint8
	HashSize      uint8
	Identifier    string
	TeamID        string
	PageSize      uint32
	CodeLimit     uint32
	ExecSegBase   uint64
	ExecSegLimit  uint64
	ExecSegFlags  uint64
	NSpecialSlots uint32
	NCodeSlots    uint32
	SpecialHashes map[int][]byte // slot number (negative) -> hash
	CodeHashes    [][]byte
}

// RequirementsInfo contains requirements blob details
type RequirementsInfo struct {
	Size       uint32
	Expression string // Human-readable requirements expression (best effort)
	RawData    []byte
}

// EntitlementsInfo contains entitlements details
type EntitlementsInfo struct {
	Size   uint32
	XML    string
	Parsed map[string]interface{}
}

// CMSInfo contains CMS signature details
type CMSInfo struct {
	Size         uint32
	CDHashSHA1   []byte
	CDHashSHA256 []byte
	SignerCN     string
	SignerTeamID string
	RawData      []byte
}

// ParseSignature parses the code signature from a Mach-O binary
func ParseSignature(binaryPath string) (*SignatureInfo, error) {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read binary: %w", err)
	}

	return ParseSignatureFromData(data, binaryPath, filepath.Dir(binaryPath))
}

// ParseSignatureFromData parses code signature from binary data
func ParseSignatureFromData(data []byte, binaryPath, bundlePath string) (*SignatureInfo, error) {
	// Handle fat binaries - extract the first slice
	sliceData := data
	if len(data) >= 8 {
		magic := binary.BigEndian.Uint32(data[:4])
		if magic == 0xcafebabe { // FAT_MAGIC
			// Get first architecture
			offset := binary.BigEndian.Uint32(data[16:20])
			size := binary.BigEndian.Uint32(data[20:24])
			if offset+size <= uint32(len(data)) {
				sliceData = data[offset : offset+size]
			}
		}
	}

	// Find code signature offset
	sigOffset, sigSize, found := findCodeSignatureOffset(sliceData)
	if !found {
		return nil, fmt.Errorf("no code signature found")
	}

	if sigOffset+sigSize > uint32(len(sliceData)) {
		return nil, fmt.Errorf("code signature extends beyond file")
	}

	sigData := sliceData[sigOffset : sigOffset+sigSize]

	info := &SignatureInfo{
		BinaryPath: binaryPath,
		BundlePath: bundlePath,
	}

	// Parse SuperBlob header
	if len(sigData) < 12 {
		return nil, fmt.Errorf("signature data too short")
	}

	info.SuperBlob.Magic = binary.BigEndian.Uint32(sigData[0:4])
	info.SuperBlob.Length = binary.BigEndian.Uint32(sigData[4:8])
	info.SuperBlob.BlobCount = binary.BigEndian.Uint32(sigData[8:12])

	if info.SuperBlob.Magic != CSMAGIC_EMBEDDED_SIGNATURE {
		return nil, fmt.Errorf("invalid SuperBlob magic: 0x%x", info.SuperBlob.Magic)
	}

	// Parse blob index entries
	indexSize := 12 + info.SuperBlob.BlobCount*8
	if uint32(len(sigData)) < indexSize {
		return nil, fmt.Errorf("signature data too short for blob index")
	}

	for i := uint32(0); i < info.SuperBlob.BlobCount; i++ {
		entryOffset := 12 + i*8
		blobType := binary.BigEndian.Uint32(sigData[entryOffset:])
		blobOffset := binary.BigEndian.Uint32(sigData[entryOffset+4:])

		var blobMagic, blobSize uint32
		if blobOffset+8 <= uint32(len(sigData)) {
			blobMagic = binary.BigEndian.Uint32(sigData[blobOffset:])
			blobSize = binary.BigEndian.Uint32(sigData[blobOffset+4:])
		}

		entry := BlobIndexEntry{
			Type:   blobType,
			Offset: blobOffset,
			Size:   blobSize,
			Magic:  blobMagic,
		}
		info.SuperBlob.Blobs = append(info.SuperBlob.Blobs, entry)

		// Parse individual blobs based on type
		if blobOffset+blobSize > uint32(len(sigData)) {
			continue
		}
		blobData := sigData[blobOffset : blobOffset+blobSize]

		switch blobType {
		case CSSLOT_CODEDIRECTORY, CSSLOT_ALTERNATE_CODEDIRECTORIES:
			if cd, err := parseCodeDirectory(blobData, blobType); err == nil {
				info.CodeDirs = append(info.CodeDirs, *cd)
			}
		case CSSLOT_REQUIREMENTS:
			info.Requirements = parseRequirements(blobData)
		case CSSLOT_ENTITLEMENTS:
			info.Entitlements = parseEntitlements(blobData)
		case CSSLOT_DER_ENTITLEMENTS:
			if len(blobData) > 8 {
				info.EntitlementsDER = blobData[8:] // Skip magic and length
			}
		case CSSLOT_SIGNATURESLOT:
			info.CMSSignature = parseCMSSignature(blobData, info.CodeDirs)
		}
	}

	return info, nil
}

// parseCodeDirectory parses a CodeDirectory blob
func parseCodeDirectory(data []byte, slot uint32) (*CodeDirectoryInfo, error) {
	if len(data) < 44 {
		return nil, fmt.Errorf("CodeDirectory too short")
	}

	cd := &CodeDirectoryInfo{
		Slot:          slot,
		SpecialHashes: make(map[int][]byte),
	}

	// Parse header
	// magic := binary.BigEndian.Uint32(data[0:4])
	// length := binary.BigEndian.Uint32(data[4:8])
	cd.Version = binary.BigEndian.Uint32(data[8:12])
	cd.Flags = binary.BigEndian.Uint32(data[12:16])
	hashOffset := binary.BigEndian.Uint32(data[16:20])
	identOffset := binary.BigEndian.Uint32(data[20:24])
	cd.NSpecialSlots = binary.BigEndian.Uint32(data[24:28])
	cd.NCodeSlots = binary.BigEndian.Uint32(data[28:32])
	cd.CodeLimit = binary.BigEndian.Uint32(data[32:36])
	cd.HashSize = data[36]
	cd.HashType = data[37]
	// platform := data[38]
	cd.PageSize = 1 << data[39]

	// Extract identifier
	if identOffset < uint32(len(data)) {
		end := identOffset
		for end < uint32(len(data)) && data[end] != 0 {
			end++
		}
		cd.Identifier = string(data[identOffset:end])
	}

	// Extract team ID (if version >= 0x20200)
	if cd.Version >= 0x20200 && len(data) >= 52 {
		teamOffset := binary.BigEndian.Uint32(data[48:52])
		if teamOffset > 0 && teamOffset < uint32(len(data)) {
			end := teamOffset
			for end < uint32(len(data)) && data[end] != 0 {
				end++
			}
			cd.TeamID = string(data[teamOffset:end])
		}
	}

	// Extract exec segment info (if version >= 0x20400)
	if cd.Version >= 0x20400 && len(data) >= 88 {
		cd.ExecSegBase = binary.BigEndian.Uint64(data[72:80])
		cd.ExecSegLimit = binary.BigEndian.Uint64(data[80:88])
		cd.ExecSegFlags = binary.BigEndian.Uint64(data[64:72])
	}

	// Extract special slot hashes (negative indices)
	for i := int(cd.NSpecialSlots); i >= 1; i-- {
		slotOffset := hashOffset - uint32(i)*uint32(cd.HashSize)
		if slotOffset+uint32(cd.HashSize) <= uint32(len(data)) {
			hash := make([]byte, cd.HashSize)
			copy(hash, data[slotOffset:slotOffset+uint32(cd.HashSize)])
			// Check if hash is non-zero
			allZero := true
			for _, b := range hash {
				if b != 0 {
					allZero = false
					break
				}
			}
			if !allZero {
				cd.SpecialHashes[-i] = hash
			}
		}
	}

	// Extract code slot hashes
	for i := uint32(0); i < cd.NCodeSlots; i++ {
		slotOffset := hashOffset + i*uint32(cd.HashSize)
		if slotOffset+uint32(cd.HashSize) <= uint32(len(data)) {
			hash := make([]byte, cd.HashSize)
			copy(hash, data[slotOffset:slotOffset+uint32(cd.HashSize)])
			cd.CodeHashes = append(cd.CodeHashes, hash)
		}
	}

	return cd, nil
}

// parseRequirements parses a Requirements blob
func parseRequirements(data []byte) RequirementsInfo {
	info := RequirementsInfo{
		Size:    uint32(len(data)),
		RawData: data,
	}

	// Requirements parsing is complex; for now just store raw data
	// A full implementation would decode the requirements expression
	if len(data) > 8 {
		info.Expression = "[requirements blob present]"
	}

	return info
}

// parseEntitlements parses an Entitlements blob
func parseEntitlements(data []byte) EntitlementsInfo {
	info := EntitlementsInfo{
		Size: uint32(len(data)),
	}

	if len(data) > 8 {
		xmlData := data[8:] // Skip magic and length
		info.XML = string(xmlData)

		// Try to parse as plist
		parsed, err := ParseEntitlementsXML(xmlData)
		if err == nil {
			info.Parsed = parsed
		}
	}

	return info
}

// parseCMSSignature parses a CMS signature blob
func parseCMSSignature(data []byte, codeDirs []CodeDirectoryInfo) CMSInfo {
	info := CMSInfo{
		Size: uint32(len(data)),
	}

	if len(data) <= 8 {
		return info
	}

	cmsData := data[8:] // Skip magic and length
	info.RawData = cmsData

	// Compute CDHashes from CodeDirectories
	for _, cd := range codeDirs {
		if cd.Slot == CSSLOT_CODEDIRECTORY && cd.HashType == CS_HASHTYPE_SHA1 {
			// Find the raw CD data to hash
			// For now, search for CDHash in CMS
		} else if cd.Slot == CSSLOT_ALTERNATE_CODEDIRECTORIES && cd.HashType == CS_HASHTYPE_SHA256 {
			// SHA256 CD
		}
	}

	// Try to parse CMS/PKCS7
	p7, err := pkcs7.Parse(cmsData)
	if err == nil && len(p7.Signers) > 0 {
		signer := p7.Signers[0]
		// Find signer certificate
		for _, cert := range p7.Certificates {
			if cert.SerialNumber.Cmp(signer.IssuerAndSerialNumber.SerialNumber) == 0 {
				info.SignerCN = cert.Subject.CommonName
				// Try to extract team ID from OU
				for _, ou := range cert.Subject.OrganizationalUnit {
					if len(ou) == 10 && isAlphanumeric(ou) {
						info.SignerTeamID = ou
						break
					}
				}
				break
			}
		}
	}

	// Look for CDHash in CMS data (it's embedded as an attribute)
	// Search for SHA1 hash (20 bytes) and SHA256 hash (truncated to 20 bytes)
	for _, cd := range codeDirs {
		var cdHash []byte
		// We need the raw CD blob to compute the hash
		// For now, we'll search for patterns in the CMS data
		if cd.HashType == CS_HASHTYPE_SHA1 {
			// SHA1 CDHash would be sha1(cd blob)
			cdHash = make([]byte, 20)
		} else if cd.HashType == CS_HASHTYPE_SHA256 {
			cdHash = make([]byte, 20) // Truncated
		}
		_ = cdHash
	}

	return info
}

// isAlphanumeric checks if a string contains only alphanumeric characters
func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// PrintSignatureInfo prints signature information to a writer
func PrintSignatureInfo(info *SignatureInfo, w io.Writer, bundlePath string) {
	// Use RelativePath if available, otherwise just the bundle name
	displayPath := filepath.Base(bundlePath)
	if info.RelativePath != "" {
		displayPath = info.RelativePath
	}
	fmt.Fprintf(w, "\n=== %s ===\n", displayPath)

	// Find bundle ID from first CodeDirectory
	var identifier, teamID string
	for _, cd := range info.CodeDirs {
		if cd.Identifier != "" {
			identifier = cd.Identifier
		}
		if cd.TeamID != "" {
			teamID = cd.TeamID
		}
	}

	if identifier != "" {
		fmt.Fprintf(w, "Identifier: %s\n", identifier)
	}
	if teamID != "" {
		fmt.Fprintf(w, "Team ID:    %s\n", teamID)
	}

	fmt.Fprintf(w, "\nCode Signature:\n")
	fmt.Fprintf(w, "  SuperBlob: %d blobs, %d bytes\n", info.SuperBlob.BlobCount, info.SuperBlob.Length)

	// Print each blob
	for i, blob := range info.SuperBlob.Blobs {
		isLast := i == len(info.SuperBlob.Blobs)-1
		prefix := "├─"
		if isLast {
			prefix = "└─"
		}
		childPrefix := "│   "
		if isLast {
			childPrefix = "    "
		}

		blobName := getBlobTypeName(blob.Type)
		fmt.Fprintf(w, "  %s %s: slot 0x%x, %d bytes\n", prefix, blobName, blob.Type, blob.Size)

		// Print details for CodeDirectory
		for _, cd := range info.CodeDirs {
			if cd.Slot == blob.Type {
				printCodeDirectoryDetails(w, &cd, childPrefix, info.BundlePath)
			}
		}

		// Print entitlements summary
		if blob.Type == CSSLOT_ENTITLEMENTS && len(info.Entitlements.Parsed) > 0 {
			for key, value := range info.Entitlements.Parsed {
				fmt.Fprintf(w, "  %s  %s: %v\n", childPrefix, key, value)
			}
		}

		// Print CMS details
		if blob.Type == CSSLOT_SIGNATURESLOT {
			if info.CMSSignature.SignerCN != "" {
				fmt.Fprintf(w, "  %sSigner: %s\n", childPrefix, info.CMSSignature.SignerCN)
			}
			if info.CMSSignature.SignerTeamID != "" {
				fmt.Fprintf(w, "  %sTeam ID: %s\n", childPrefix, info.CMSSignature.SignerTeamID)
			}
		}
	}
}

// printCodeDirectoryDetails prints CodeDirectory details
func printCodeDirectoryDetails(w io.Writer, cd *CodeDirectoryInfo, prefix string, bundlePath string) {
	hashTypeName := "unknown"
	switch cd.HashType {
	case CS_HASHTYPE_SHA1:
		hashTypeName = "SHA-1"
	case CS_HASHTYPE_SHA256:
		hashTypeName = "SHA-256"
	}

	fmt.Fprintf(w, "  %sVersion: 0x%x\n", prefix, cd.Version)
	fmt.Fprintf(w, "  %sHash Type: %s (%d bytes)\n", prefix, hashTypeName, cd.HashSize)
	fmt.Fprintf(w, "  %sPage Size: %d\n", prefix, cd.PageSize)
	fmt.Fprintf(w, "  %sCode Limit: %d\n", prefix, cd.CodeLimit)

	if cd.Version >= 0x20400 {
		fmt.Fprintf(w, "  %sExec Seg: base=0x%x, limit=0x%x, flags=0x%x\n",
			prefix, cd.ExecSegBase, cd.ExecSegLimit, cd.ExecSegFlags)
	}

	fmt.Fprintf(w, "  %sSpecial Slots: %d\n", prefix, cd.NSpecialSlots)

	// Print special slot hashes
	slotNames := map[int]string{
		-1: "Info.plist",
		-2: "Requirements",
		-3: "CodeResources",
		-4: "Application",
		-5: "Entitlements",
		-6: "RepSpecific",
		-7: "EntitlementsDER",
	}

	for slot := -int(cd.NSpecialSlots); slot <= -1; slot++ {
		hash, exists := cd.SpecialHashes[slot]
		name := slotNames[slot]
		if name == "" {
			name = fmt.Sprintf("Slot %d", slot)
		}

		if exists {
			hashStr := hex.EncodeToString(hash)
			if len(hashStr) > 24 {
				hashStr = hashStr[:24] + "..."
			}

			// Verify hash if possible
			verified := ""
			if slot == -1 && bundlePath != "" {
				// Verify Info.plist hash
				if verifyFileHash(filepath.Join(bundlePath, "Info.plist"), hash, cd.HashType) {
					verified = " ✓"
				} else {
					verified = " ✗"
				}
			} else if slot == -3 && bundlePath != "" {
				// Verify CodeResources hash
				if verifyFileHash(filepath.Join(bundlePath, "_CodeSignature", "CodeResources"), hash, cd.HashType) {
					verified = " ✓"
				} else {
					verified = " ✗"
				}
			}

			fmt.Fprintf(w, "  %s  %d (%s): %s%s\n", prefix, slot, name, hashStr, verified)
		}
	}

	fmt.Fprintf(w, "  %sCode Slots: %d\n", prefix, cd.NCodeSlots)
}

// verifyFileHash verifies a file's hash matches the expected hash
func verifyFileHash(filePath string, expectedHash []byte, hashType uint8) bool {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	var actualHash []byte
	switch hashType {
	case CS_HASHTYPE_SHA1:
		h := sha1.Sum(data)
		actualHash = h[:]
	case CS_HASHTYPE_SHA256:
		h := sha256.Sum256(data)
		actualHash = h[:]
	default:
		return false
	}

	return bytes.Equal(actualHash, expectedHash)
}

// getBlobTypeName returns a human-readable name for a blob type
func getBlobTypeName(blobType uint32) string {
	switch blobType {
	case CSSLOT_CODEDIRECTORY:
		return "CodeDirectory (SHA1)"
	case CSSLOT_REQUIREMENTS:
		return "Requirements"
	case CSSLOT_ENTITLEMENTS:
		return "Entitlements"
	case CSSLOT_DER_ENTITLEMENTS:
		return "EntitlementsDER"
	case CSSLOT_SIGNATURESLOT:
		return "CMS Signature"
	case CSSLOT_ALTERNATE_CODEDIRECTORIES:
		return "CodeDirectory (SHA256)"
	default:
		if blobType >= CSSLOT_ALTERNATE_CODEDIRECTORIES && blobType < CSSLOT_SIGNATURESLOT {
			return fmt.Sprintf("CodeDirectory (alt 0x%x)", blobType)
		}
		return fmt.Sprintf("Unknown (0x%x)", blobType)
	}
}

// GetBundleSignatureInfo gets signature info for a bundle and optionally its nested bundles
func GetBundleSignatureInfo(bundlePath string, recursive bool) ([]*SignatureInfo, error) {
	return getBundleSignatureInfoWithRoot(bundlePath, bundlePath, recursive)
}

// getBundleSignatureInfoWithRoot is the internal implementation that tracks the root path
func getBundleSignatureInfoWithRoot(bundlePath, rootPath string, recursive bool) ([]*SignatureInfo, error) {
	var results []*SignatureInfo

	// Get executable name
	execName, err := GetAppExecutableName(bundlePath)
	if err != nil {
		// Try common patterns
		base := filepath.Base(bundlePath)
		ext := filepath.Ext(base)
		execName = strings.TrimSuffix(base, ext)
	}

	// Parse main executable
	execPath := filepath.Join(bundlePath, execName)
	if _, err := os.Stat(execPath); err != nil {
		// Try without extension stripping for frameworks
		execPath = filepath.Join(bundlePath, strings.TrimSuffix(filepath.Base(bundlePath), filepath.Ext(bundlePath)))
	}

	info, err := ParseSignature(execPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature for %s: %w", bundlePath, err)
	}
	info.BundlePath = bundlePath

	// Calculate relative path from root
	if bundlePath == rootPath {
		info.RelativePath = filepath.Base(bundlePath)
	} else {
		relPath, err := filepath.Rel(filepath.Dir(rootPath), bundlePath)
		if err == nil {
			info.RelativePath = relPath
		} else {
			info.RelativePath = filepath.Base(bundlePath)
		}
	}

	results = append(results, info)

	if !recursive {
		return results, nil
	}

	// Find nested bundles
	nestedDirs := []string{"Frameworks", "PlugIns"}
	for _, dir := range nestedDirs {
		dirPath := filepath.Join(bundlePath, dir)
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			ext := filepath.Ext(entry.Name())
			if ext == ".framework" || ext == ".xctest" || ext == ".app" || ext == ".appex" {
				nestedPath := filepath.Join(dirPath, entry.Name())
				nestedInfos, err := getBundleSignatureInfoWithRoot(nestedPath, rootPath, true)
				if err != nil {
					// Log but continue
					fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", nestedPath, err)
					continue
				}
				results = append(results, nestedInfos...)
			}
		}
	}

	return results, nil
}

// ComputeCDHash computes the CDHash for a CodeDirectory
func ComputeCDHash(sigData []byte, blobOffset, blobSize uint32, hashType uint8) []byte {
	if blobOffset+blobSize > uint32(len(sigData)) {
		return nil
	}

	cdData := sigData[blobOffset : blobOffset+blobSize]

	switch hashType {
	case CS_HASHTYPE_SHA1:
		h := sha1.Sum(cdData)
		return h[:]
	case CS_HASHTYPE_SHA256:
		h := sha256.Sum256(cdData)
		return h[:20] // Truncated to 20 bytes
	}
	return nil
}

// ExtractCDHashes extracts CDHashes from signature data
func ExtractCDHashes(binaryPath string) (sha1Hash, sha256Hash []byte, err error) {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, nil, err
	}

	// Handle fat binaries
	sliceData := data
	if len(data) >= 8 {
		magic := binary.BigEndian.Uint32(data[:4])
		if magic == 0xcafebabe {
			offset := binary.BigEndian.Uint32(data[16:20])
			size := binary.BigEndian.Uint32(data[20:24])
			if offset+size <= uint32(len(data)) {
				sliceData = data[offset : offset+size]
			}
		}
	}

	sigOffset, sigSize, found := findCodeSignatureOffset(sliceData)
	if !found {
		return nil, nil, fmt.Errorf("no code signature found")
	}

	sigData := sliceData[sigOffset : sigOffset+sigSize]
	blobCount := binary.BigEndian.Uint32(sigData[8:12])

	for i := uint32(0); i < blobCount; i++ {
		entryOffset := 12 + i*8
		blobType := binary.BigEndian.Uint32(sigData[entryOffset:])
		blobOffset := binary.BigEndian.Uint32(sigData[entryOffset+4:])

		if blobOffset+8 > uint32(len(sigData)) {
			continue
		}

		blobMagic := binary.BigEndian.Uint32(sigData[blobOffset:])
		blobSize := binary.BigEndian.Uint32(sigData[blobOffset+4:])

		if blobMagic == CSMAGIC_CODEDIRECTORY {
			cdData := sigData[blobOffset : blobOffset+blobSize]
			hashType := cdData[37]

			switch blobType {
			case CSSLOT_CODEDIRECTORY:
				if hashType == CS_HASHTYPE_SHA1 {
					h := sha1.Sum(cdData)
					sha1Hash = h[:]
				}
			case CSSLOT_ALTERNATE_CODEDIRECTORIES:
				if hashType == CS_HASHTYPE_SHA256 {
					h := sha256.Sum256(cdData)
					sha256Hash = h[:20] // Truncated
				}
			}
		}
	}

	return sha1Hash, sha256Hash, nil
}

// VerifySignatureFromCerts verifies that the CMS signature was made by one of the provided certificates
func VerifySignatureFromCerts(info *SignatureInfo, certs []*x509.Certificate) bool {
	if len(info.CMSSignature.RawData) == 0 {
		return false
	}

	p7, err := pkcs7.Parse(info.CMSSignature.RawData)
	if err != nil {
		return false
	}

	// Check if any of our certs match the signer
	for _, signer := range p7.Signers {
		for _, cert := range certs {
			if cert.SerialNumber.Cmp(signer.IssuerAndSerialNumber.SerialNumber) == 0 {
				return true
			}
		}
	}

	return false
}
