package codesign

// Native code signing implementation based on Go's cmd/internal/codesign
// This provides a clean implementation without the bugs in go-macho library

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"go.mozilla.org/pkcs7"
	"howett.net/plist"
)

// Code signature constants from Apple's cs_blobs.h
const (
	pageSizeBits   = 12               // 4KB pages like zsign for compatibility
	pageSize       = 1 << pageSizeBits // 4096 bytes

	CSMAGIC_REQUIREMENT         = 0xfade0c00
	CSMAGIC_REQUIREMENTS        = 0xfade0c01
	CSMAGIC_CODEDIRECTORY       = 0xfade0c02
	CSMAGIC_EMBEDDED_SIGNATURE  = 0xfade0cc0
	CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171
	CSMAGIC_BLOBWRAPPER         = 0xfade0b01

	CSSLOT_CODEDIRECTORY        = 0
	CSSLOT_INFOSLOT             = 1
	CSSLOT_REQUIREMENTS         = 2
	CSSLOT_RESOURCEDIR          = 3
	CSSLOT_APPLICATION          = 4
	CSSLOT_ENTITLEMENTS         = 5
	CSSLOT_ENTITLEMENTS_DER     = 7  // DER-encoded entitlements for iOS 15+
	CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000 // Alternate CodeDirectory slots start here
	CSSLOT_CMS_SIGNATURE        = 0x10000

	CSMAGIC_EMBEDDED_ENTITLEMENTS_DER = 0xfade7172

	CS_HASHTYPE_SHA1   = 1
	CS_HASHTYPE_SHA256 = 2

	CS_EXECSEG_MAIN_BINARY    = 0x1
	CS_EXECSEG_ALLOW_UNSIGNED = 0x10

	LC_CODE_SIGNATURE      = 0x1d // Load command for code signature
	LC_CODE_SIGNATURE_SIZE = 16   // Size of LC_CODE_SIGNATURE load command
)

// put32be writes a big-endian uint32
func put32be(b []byte, x uint32) []byte {
	binary.BigEndian.PutUint32(b, x)
	return b[4:]
}

// put64be writes a big-endian uint64
func put64be(b []byte, x uint64) []byte {
	binary.BigEndian.PutUint64(b, x)
	return b[8:]
}

// put8 writes a single byte
func put8(b []byte, x uint8) []byte {
	b[0] = x
	return b[1:]
}

// puts copies bytes
func puts(b, s []byte) []byte {
	n := copy(b, s)
	return b[n:]
}

// signatureSize computes the size of the code signature
func signatureSize(codeSize int64, id string, hasEntitlements bool, cmsSize int) int64 {
	nhashes := (codeSize + pageSize - 1) / pageSize
	nSpecialSlots := int64(2) // Requirements + InfoPlist
	if hasEntitlements {
		nSpecialSlots = 5 // Add Entitlements, ResourceDir, Application
	}

	// CodeDirectory size
	idOff := int64(88) // v0x20400 header size
	hashOff := idOff + int64(len(id)+1) + nSpecialSlots*sha256.Size
	cdirSz := hashOff + nhashes*sha256.Size

	// SuperBlob header + blob index entries
	blobCount := 2 // CodeDirectory + CMS
	if hasEntitlements {
		blobCount = 4 // CodeDirectory + Requirements + Entitlements + CMS
	}
	headerSz := int64(12 + blobCount*8) // SuperBlob header + index entries

	// Total size
	total := headerSz + cdirSz
	if hasEntitlements {
		total += 8 + 12 // Requirements blob (minimal empty)
		// Entitlements blob size will be added by caller
	}
	total += int64(8 + cmsSize) // CMS wrapper

	return total
}

// findCodeSignatureOffset finds the LC_CODE_SIGNATURE offset and size without full parsing
// This is used to truncate data before parsing with go-macho (which chokes on some signatures)
func findCodeSignatureOffset(data []byte) (offset, size uint32, found bool) {
	if len(data) < 32 {
		return 0, 0, false
	}

	// Check magic
	magic := binary.LittleEndian.Uint32(data[:4])
	var is64Bit bool
	var headerSize uint32

	switch magic {
	case 0xfeedfacf: // MH_MAGIC_64
		is64Bit = true
		headerSize = 32
	case 0xfeedface: // MH_MAGIC
		is64Bit = false
		headerSize = 28
	default:
		return 0, 0, false
	}

	var ncmds, sizeofcmds uint32
	if is64Bit {
		ncmds = binary.LittleEndian.Uint32(data[16:20])
		sizeofcmds = binary.LittleEndian.Uint32(data[20:24])
	} else {
		ncmds = binary.LittleEndian.Uint32(data[12:16])
		sizeofcmds = binary.LittleEndian.Uint32(data[16:20])
	}

	// Make sure we have enough data
	if uint32(len(data)) < headerSize+sizeofcmds {
		return 0, 0, false
	}

	cmdOffset := headerSize
	for i := uint32(0); i < ncmds; i++ {
		if cmdOffset+8 > headerSize+sizeofcmds {
			break
		}
		cmd := binary.LittleEndian.Uint32(data[cmdOffset:])
		cmdSize := binary.LittleEndian.Uint32(data[cmdOffset+4:])

		if cmd == LC_CODE_SIGNATURE && cmdSize >= 16 {
			sigOffset := binary.LittleEndian.Uint32(data[cmdOffset+8:])
			sigSize := binary.LittleEndian.Uint32(data[cmdOffset+12:])
			return sigOffset, sigSize, true
		}
		cmdOffset += cmdSize
	}

	return 0, 0, false
}

// NativeSignMachO signs a Mach-O binary using our native implementation
func NativeSignMachO(path string, identity *SigningIdentity, entitlements []byte, bundleID string) error {
	return NativeSignMachOWithContext(path, identity, entitlements, bundleID, nil)
}

func nativeSignThinMachOWithContext(data []byte, m *macho.File, identity *SigningIdentity, entitlements []byte, bundleID string, bundleCtx *BundleSigningContext) ([]byte, error) {
	// Determine if 64-bit
	is64Bit := m.Magic == types.Magic64

	// Find text segment info and __LINKEDIT segment
	var textOffset, textSize uint64
	var linkeditSegOffset uint32
	var linkeditFileoff uint64

	headerSize := uint32(32) // Mach-O 64-bit header
	if m.Magic == types.Magic32 {
		headerSize = 28
	}

	cmdOffset := headerSize
	for _, load := range m.Loads {
		if seg, ok := load.(*macho.Segment); ok {
			if seg.Name == "__TEXT" {
				textOffset = seg.Offset
				textSize = seg.Filesz
			} else if seg.Name == "__LINKEDIT" {
				linkeditSegOffset = cmdOffset
				linkeditFileoff = seg.Offset
			}
		}
		cmdOffset += load.LoadSize()
	}

	// Find existing signature and calculate code size
	codeSize := uint64(len(data))
	var csLoadCmdOffset uint32

	cmdOffset = headerSize
	for _, load := range m.Loads {
		if cs, ok := load.(*macho.CodeSignature); ok {
			codeSize = uint64(cs.Offset)
			csLoadCmdOffset = cmdOffset
			break
		}
		cmdOffset += load.LoadSize()
	}

	if csLoadCmdOffset == 0 {
		// No existing signature - need to add LC_CODE_SIGNATURE load command
		return addSignatureToUnsignedWithContext(data, m, identity, entitlements, bundleID, textOffset, textSize, bundleCtx)
	}

	// Calculate new signature size like zsign does:
	// newLength = codeLength + align((codePages + 1) * 52, 4096) + 16384
	// This ensures enough space for both SHA1 (20 bytes) and SHA256 (32 bytes) hashes per page
	codePages := (codeSize + pageSize - 1) / pageSize
	hashSpaceNeeded := (codePages + 1) * 52 // 20 + 32 bytes per page
	alignedHashSpace := ((hashSpaceNeeded + 4095) / 4096) * 4096
	finalSigSize := uint32(alignedHashSpace + 16384) // Add 16KB padding like zsign

	// Create a copy of data for hashing with updated load commands
	dataForHashing := make([]byte, codeSize)
	copy(dataForHashing, data[:codeSize])

	// Update LC_CODE_SIGNATURE: dataoff and datasize
	binary.LittleEndian.PutUint32(dataForHashing[csLoadCmdOffset+8:], uint32(codeSize))
	binary.LittleEndian.PutUint32(dataForHashing[csLoadCmdOffset+12:], finalSigSize)

	// Update __LINKEDIT segment to reflect new file size
	// This is critical for iOS signature verification
	if linkeditSegOffset > 0 {
		newFileSize := codeSize + uint64(finalSigSize)
		newLinkeditFilesize := newFileSize - linkeditFileoff
		// vmsize should be page-aligned (4096)
		newLinkeditVmsize := ((newLinkeditFilesize + 4095) / 4096) * 4096

		if is64Bit {
			// segment_command_64 layout:
			// cmd(4) + cmdsize(4) + segname(16) + vmaddr(8) + vmsize(8) + fileoff(8) + filesize(8) + ...
			// vmsize is at offset 32, filesize is at offset 48
			binary.LittleEndian.PutUint64(dataForHashing[linkeditSegOffset+32:], newLinkeditVmsize)
			binary.LittleEndian.PutUint64(dataForHashing[linkeditSegOffset+48:], newLinkeditFilesize)
		} else {
			// segment_command layout (32-bit):
			// cmd(4) + cmdsize(4) + segname(16) + vmaddr(4) + vmsize(4) + fileoff(4) + filesize(4) + ...
			// vmsize is at offset 28, filesize is at offset 36
			binary.LittleEndian.PutUint32(dataForHashing[linkeditSegOffset+28:], uint32(newLinkeditVmsize))
			binary.LittleEndian.PutUint32(dataForHashing[linkeditSegOffset+36:], uint32(newLinkeditFilesize))
		}
	}

	// Generate signature with correct hashes (including updated load commands)
	sig, err := createSignatureWithContext(dataForHashing, identity, entitlements, bundleID, textOffset, textSize, bundleCtx)
	if err != nil {
		return nil, err
	}

	// Pad the signature to the calculated size
	paddedSig := make([]byte, finalSigSize)
	copy(paddedSig, sig)
	// Rest is zeros (padding)

	// Create result with padded signature appended
	result := make([]byte, codeSize+uint64(finalSigSize))
	copy(result, dataForHashing)
	copy(result[codeSize:], paddedSig)

	return result, nil
}

// addSignatureToUnsignedWithContext adds code signing to a Mach-O that doesn't have LC_CODE_SIGNATURE
func addSignatureToUnsignedWithContext(data []byte, m *macho.File, identity *SigningIdentity, entitlements []byte, bundleID string, textOffset, textSize uint64, bundleCtx *BundleSigningContext) ([]byte, error) {
	// Determine header size based on architecture
	is64Bit := m.Magic == types.Magic64
	headerSize := uint32(28) // 32-bit
	if is64Bit {
		headerSize = 32
	}

	// Read current ncmds and sizeofcmds from header
	var ncmds, sizeofcmds uint32
	if is64Bit {
		ncmds = binary.LittleEndian.Uint32(data[16:20])
		sizeofcmds = binary.LittleEndian.Uint32(data[20:24])
	} else {
		ncmds = binary.LittleEndian.Uint32(data[12:16])
		sizeofcmds = binary.LittleEndian.Uint32(data[16:20])
	}

	// Position where we'll add LC_CODE_SIGNATURE (after existing load commands)
	loadCmdsEnd := headerSize + sizeofcmds

	// Check if there's room for a new load command
	// We need 16 bytes for LC_CODE_SIGNATURE
	// The load commands area should end before __TEXT segment data starts
	if textOffset > 0 && uint64(loadCmdsEnd+LC_CODE_SIGNATURE_SIZE) > textOffset {
		return nil, fmt.Errorf("no room to add LC_CODE_SIGNATURE load command (need %d bytes, only %d available)",
			LC_CODE_SIGNATURE_SIZE, textOffset-uint64(loadCmdsEnd))
	}

	// Find __LINKEDIT segment to update its size
	var linkeditOffset uint32
	var linkeditFileoff, linkeditFilesize, linkeditVmsize uint64
	cmdOffset := headerSize
	for _, load := range m.Loads {
		if seg, ok := load.(*macho.Segment); ok && seg.Name == "__LINKEDIT" {
			linkeditOffset = cmdOffset
			linkeditFileoff = seg.Offset
			linkeditFilesize = seg.Filesz
			linkeditVmsize = seg.Memsz
			break
		}
		cmdOffset += load.LoadSize()
	}

	// Code size is the current file size (signature will be appended)
	codeSize := uint64(len(data))

	// Align code size to 16 bytes (Apple requirement)
	alignedCodeSize := (codeSize + 15) &^ 15

	// Calculate signature size using zsign's formula:
	// newLength = codeLength + align(((codeLength / 4096) + 1) * (20 + 32), 4096) + 16384
	// This ensures enough space for both SHA1 (20 bytes) and SHA256 (32 bytes) hashes per page
	codePages := (alignedCodeSize / pageSize) + 1
	hashSpaceNeeded := codePages * 52 // 20 + 32 bytes per page
	alignedHashSpace := ((hashSpaceNeeded + 4095) / 4096) * 4096
	finalSigSize := uint32(alignedHashSpace + 16384) // Add 16KB padding like zsign

	// Create a copy of data with updated header to get correct hashes
	dataWithNewCmd := make([]byte, alignedCodeSize)
	copy(dataWithNewCmd, data)

	// Zero-fill padding
	for i := len(data); i < int(alignedCodeSize); i++ {
		dataWithNewCmd[i] = 0
	}

	// Update ncmds and sizeofcmds in header
	if is64Bit {
		binary.LittleEndian.PutUint32(dataWithNewCmd[16:20], ncmds+1)
		binary.LittleEndian.PutUint32(dataWithNewCmd[20:24], sizeofcmds+LC_CODE_SIGNATURE_SIZE)
	} else {
		binary.LittleEndian.PutUint32(dataWithNewCmd[12:16], ncmds+1)
		binary.LittleEndian.PutUint32(dataWithNewCmd[16:20], sizeofcmds+LC_CODE_SIGNATURE_SIZE)
	}

	// Write LC_CODE_SIGNATURE load command at end of existing commands
	csLoadCmdOffset := loadCmdsEnd
	binary.LittleEndian.PutUint32(dataWithNewCmd[csLoadCmdOffset:], LC_CODE_SIGNATURE)        // cmd
	binary.LittleEndian.PutUint32(dataWithNewCmd[csLoadCmdOffset+4:], LC_CODE_SIGNATURE_SIZE) // cmdsize
	binary.LittleEndian.PutUint32(dataWithNewCmd[csLoadCmdOffset+8:], uint32(alignedCodeSize)) // dataoff
	binary.LittleEndian.PutUint32(dataWithNewCmd[csLoadCmdOffset+12:], finalSigSize)          // datasize

	// Update __LINKEDIT segment size to include the signature
	// zsign formula: vmsize = align(old_vmsize + size_increase, 4096)
	// where size_increase = newLength - oldLength
	if linkeditOffset > 0 {
		newLinkeditFilesize := linkeditFilesize + (alignedCodeSize - codeSize) + uint64(finalSigSize)
		// Calculate size increase (new total file size - original file size)
		sizeIncrease := (alignedCodeSize + uint64(finalSigSize)) - codeSize
		// vmsize = align(old_vmsize + size_increase, 4096) - matching zsign behavior
		newLinkeditVmsize := ((linkeditVmsize + sizeIncrease + 4095) / 4096) * 4096
		if is64Bit {
			// 64-bit segment: vmsize is at offset 32, filesize is at offset 48
			binary.LittleEndian.PutUint64(dataWithNewCmd[linkeditOffset+32:], newLinkeditVmsize)    // vmsize
			binary.LittleEndian.PutUint64(dataWithNewCmd[linkeditOffset+48:], newLinkeditFilesize) // filesize
		} else {
			// 32-bit segment: vmsize is at offset 28, filesize is at offset 36
			binary.LittleEndian.PutUint32(dataWithNewCmd[linkeditOffset+28:], uint32(newLinkeditVmsize))    // vmsize
			binary.LittleEndian.PutUint32(dataWithNewCmd[linkeditOffset+36:], uint32(newLinkeditFilesize)) // filesize
		}
		_ = linkeditFileoff // Used for verification if needed
	}

	// Now generate signature with correct hashes (including the new load command)
	sig, err := createSignatureWithContext(dataWithNewCmd, identity, entitlements, bundleID, textOffset, textSize, bundleCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	// Pad the signature to the calculated size
	paddedSig := make([]byte, finalSigSize)
	copy(paddedSig, sig)
	// Rest is zeros (padding)

	// Create final result: data + padded signature
	result := make([]byte, alignedCodeSize+uint64(finalSigSize))
	copy(result, dataWithNewCmd)
	copy(result[alignedCodeSize:], paddedSig)

	return result, nil
}

func createSignatureWithContext(codeData []byte, identity *SigningIdentity, entitlements []byte, bundleID string, textOffset, textSize uint64, bundleCtx *BundleSigningContext) ([]byte, error) {
	codeSize := int64(len(codeData))
	nhashes := (codeSize + pageSize - 1) / pageSize
	hasEntitlements := len(entitlements) > 0

	// Get TeamID for the CodeDirectory
	var teamID string
	if bundleCtx != nil && bundleCtx.TeamID != "" {
		teamID = bundleCtx.TeamID
	}

	// Read Info.plist and CodeResources for special slot hashes
	var infoPlistData, codeResourcesData []byte
	if bundleCtx != nil {
		if bundleCtx.InfoPlistPath != "" {
			if data, err := os.ReadFile(bundleCtx.InfoPlistPath); err == nil {
				infoPlistData = data
			}
		}
		if bundleCtx.CodeResourcesPath != "" {
			if data, err := os.ReadFile(bundleCtx.CodeResourcesPath); err == nil {
				codeResourcesData = data
			}
		}
	}

	// Build blobs first so we can compute hashes
	// Use the signer's common name for strict validation requirements
	signerCN := ""
	if identity != nil && identity.Certificate != nil {
		signerCN = identity.Certificate.Subject.CommonName
	}
	reqBlob := buildRequirementsBlobWithCert(bundleID, signerCN)

	// Check if entitlements are "empty" (just <dict/>) - zsign treats these specially
	// Empty entitlements get 5 slots and no EntitlementsDER, while real entitlements get 7 slots
	isEmptyEntitlements := hasEntitlements && isEmptyEntitlementsXML(string(entitlements))

	var entBlob, entDERBlob []byte
	if hasEntitlements {
		entBlob = buildEntitlementsBlob(entitlements)
		// Only generate DER-encoded entitlements for non-empty entitlements (like zsign does)
		if !isEmptyEntitlements {
			entDERBlob = buildEntitlementsDERBlob(entitlements)
		}
	}

	// Determine number of special slots
	// We need at least 5 slots even without entitlements to include Resources (slot 3)
	// This is critical for nested bundles (xctest, frameworks) that have CodeResources but no entitlements
	hasCodeResources := len(codeResourcesData) > 0
	nSpecialSlots := uint32(2) // Requirements + InfoPlist (minimum)
	if hasEntitlements && !isEmptyEntitlements {
		nSpecialSlots = 7 // 1=InfoPlist, 2=Requirements, 3=ResourceDir, 4=Application, 5=Entitlements, 6=reserved, 7=EntitlementsDER
	} else if hasEntitlements || hasCodeResources {
		nSpecialSlots = 5 // 1=InfoPlist, 2=Requirements, 3=ResourceDir, 4=Application, 5=Entitlements
	}

	// Determine execSegFlags based on entitlements (matching zsign behavior)
	// execSegFlags = 0 by default for nested bundles (frameworks, xctest)
	// Only set CS_EXECSEG_MAIN_BINARY | CS_EXECSEG_ALLOW_UNSIGNED if get-task-allow is in entitlements
	var execSegFlags uint64 = 0
	if hasEntitlements && strings.Contains(string(entitlements), "get-task-allow") {
		execSegFlags = CS_EXECSEG_MAIN_BINARY | CS_EXECSEG_ALLOW_UNSIGNED
	}

	// Build BOTH CodeDirectories: SHA1 (primary) and SHA256 (alternate)
	// zsign puts SHA1 first at slot 0, SHA256 at slot 0x1000
	cdirSHA1 := buildCodeDirectory(codeData, bundleID, teamID, nSpecialSlots, nhashes, codeSize,
		textOffset, textSize, reqBlob, entBlob, entDERBlob, infoPlistData, codeResourcesData,
		sha1.Size, CS_HASHTYPE_SHA1, execSegFlags)

	cdirSHA256 := buildCodeDirectory(codeData, bundleID, teamID, nSpecialSlots, nhashes, codeSize,
		textOffset, textSize, reqBlob, entBlob, entDERBlob, infoPlistData, codeResourcesData,
		sha256.Size, CS_HASHTYPE_SHA256, execSegFlags)

	// Build CMS signature - zsign signs the SHA1 CodeDirectory (not SHA256!)
	// The CMS messageDigest is SHA256(SHA1_CodeDirectory)
	// CDHashes plist contains: SHA1 hash of SHA1 CD, truncated SHA256 hash of SHA256 CD
	cmsBlob, err := buildCMSSignatureWithDualCD(cdirSHA1, cdirSHA256, identity)
	if err != nil {
		return nil, fmt.Errorf("failed to create CMS signature: %w", err)
	}

	// Calculate SuperBlob size - now with 2 CodeDirectories
	// zsign order: CD SHA1, Requirements, Entitlements (if any), EntDER (if non-empty ent), CD SHA256, CMS
	blobCount := 4 // CodeDirectory SHA1 + Requirements + CodeDirectory SHA256 + CMS
	if hasEntitlements && !isEmptyEntitlements {
		blobCount = 6 // + Entitlements + EntitlementsDER (only for non-empty entitlements)
	} else if hasEntitlements {
		blobCount = 5 // + Entitlements only (empty entitlements don't get EntitlementsDER)
	}

	// Calculate offsets - zsign order: SHA1 CD, Requirements, Entitlements, [EntDER], SHA256 CD, CMS
	headerSize := 12 + blobCount*8 // SuperBlob header + index entries
	cdirSHA1Offset := headerSize
	reqOffset := cdirSHA1Offset + len(cdirSHA1)
	entOffset := reqOffset + len(reqBlob)
	entDEROffset := entOffset
	cdirSHA256Offset := entOffset
	if hasEntitlements && !isEmptyEntitlements {
		// Non-empty entitlements: include both Entitlements and EntitlementsDER
		entDEROffset = entOffset + len(entBlob)
		cdirSHA256Offset = entDEROffset + len(entDERBlob)
	} else if hasEntitlements {
		// Empty entitlements: only Entitlements blob, no EntitlementsDER
		cdirSHA256Offset = entOffset + len(entBlob)
	}
	cmsOffset := cdirSHA256Offset + len(cdirSHA256)

	totalSize := cmsOffset + len(cmsBlob)

	// Build SuperBlob
	superBlob := make([]byte, totalSize)
	outp := superBlob

	// SuperBlob header
	outp = put32be(outp, CSMAGIC_EMBEDDED_SIGNATURE)
	outp = put32be(outp, uint32(totalSize))
	outp = put32be(outp, uint32(blobCount))

	// Blob index entries - zsign order: CD SHA1, Requirements, Entitlements, EntDER, CD SHA256, CMS
	outp = put32be(outp, CSSLOT_CODEDIRECTORY)          // slot 0 = SHA1 CodeDirectory
	outp = put32be(outp, uint32(cdirSHA1Offset))

	outp = put32be(outp, CSSLOT_REQUIREMENTS)
	outp = put32be(outp, uint32(reqOffset))

	if hasEntitlements {
		outp = put32be(outp, CSSLOT_ENTITLEMENTS)
		outp = put32be(outp, uint32(entOffset))

		// Only write EntitlementsDER slot for non-empty entitlements (like zsign)
		if !isEmptyEntitlements {
			outp = put32be(outp, CSSLOT_ENTITLEMENTS_DER)
			outp = put32be(outp, uint32(entDEROffset))
		}
	}

	outp = put32be(outp, CSSLOT_ALTERNATE_CODEDIRECTORIES) // slot 0x1000 = SHA256 CodeDirectory
	outp = put32be(outp, uint32(cdirSHA256Offset))

	outp = put32be(outp, CSSLOT_CMS_SIGNATURE)
	outp = put32be(outp, uint32(cmsOffset))

	// Blob data - in layout order (not index order)
	copy(superBlob[cdirSHA1Offset:], cdirSHA1)
	copy(superBlob[reqOffset:], reqBlob)
	if hasEntitlements {
		copy(superBlob[entOffset:], entBlob)
		// Only copy EntitlementsDER blob for non-empty entitlements
		if !isEmptyEntitlements && len(entDERBlob) > 0 {
			copy(superBlob[entDEROffset:], entDERBlob)
		}
	}
	copy(superBlob[cdirSHA256Offset:], cdirSHA256)
	copy(superBlob[cmsOffset:], cmsBlob)

	return superBlob, nil
}

// buildCodeDirectory creates a CodeDirectory blob with the specified hash algorithm
func buildCodeDirectory(codeData []byte, bundleID, teamID string, nSpecialSlots uint32, nhashes, codeSize int64,
	textOffset, textSize uint64, reqBlob, entBlob, entDERBlob, infoPlistData, codeResourcesData []byte,
	hashSize int, hashType uint8, execSegFlags uint64) []byte {

	// Calculate CodeDirectory layout
	// Header is 88 bytes for v0x20400, then identifier, then teamID (if present), then hashes
	idOff := uint32(88) // CodeDirectory header size for v0x20400
	teamOff := uint32(0)
	hashOff := idOff + uint32(len(bundleID)+1)

	if teamID != "" {
		teamOff = hashOff
		hashOff = teamOff + uint32(len(teamID)+1)
	}

	hashOff += nSpecialSlots * uint32(hashSize)

	cdirLen := hashOff + uint32(nhashes)*uint32(hashSize)

	// Build CodeDirectory
	cdir := make([]byte, cdirLen)
	outp := cdir

	// CodeDirectory header
	outp = put32be(outp, CSMAGIC_CODEDIRECTORY)
	outp = put32be(outp, cdirLen)
	outp = put32be(outp, 0x20400)                    // version
	outp = put32be(outp, 0)                          // flags (not adhoc since we have cert)
	outp = put32be(outp, hashOff)                    // hashOffset
	outp = put32be(outp, idOff)                      // identOffset
	outp = put32be(outp, nSpecialSlots)              // nSpecialSlots
	outp = put32be(outp, uint32(nhashes))            // nCodeSlots
	outp = put32be(outp, uint32(codeSize))           // codeLimit
	outp = put8(outp, uint8(hashSize))               // hashSize
	outp = put8(outp, hashType)                      // hashType
	outp = put8(outp, 0)                             // pad1
	outp = put8(outp, pageSizeBits)                  // pageSize
	outp = put32be(outp, 0)                          // pad2
	outp = put32be(outp, 0)                          // scatterOffset
	outp = put32be(outp, teamOff)                    // teamOffset
	outp = put32be(outp, 0)                          // pad3
	outp = put64be(outp, 0)                          // codeLimit64
	outp = put64be(outp, textOffset)                 // execSegBase
	outp = put64be(outp, textSize)                   // execSegLimit
	outp = put64be(outp, execSegFlags) // execSegFlags

	// Identifier string
	outp = puts(outp, []byte(bundleID+"\x00"))

	// Team ID string (if present)
	if teamID != "" {
		outp = puts(outp, []byte(teamID+"\x00"))
	}

	// Special slot hashes (written in reverse order: slot -nSpecialSlots to slot -1)
	for i := int(nSpecialSlots); i >= 1; i-- {
		var hash []byte
		switch i {
		case 1: // Info.plist
			hash = computeHash(infoPlistData, hashType)
		case 2: // Requirements
			hash = computeHash(reqBlob, hashType)
		case 3: // CodeResources
			hash = computeHash(codeResourcesData, hashType)
		case 5: // Entitlements XML
			hash = computeHash(entBlob, hashType)
		case 7: // Entitlements DER
			hash = computeHash(entDERBlob, hashType)
		default:
			// Empty hash for unused slots (4, 6)
			hash = make([]byte, hashSize)
		}
		outp = puts(outp, hash)
	}

	// Code page hashes
	for p := int64(0); p < codeSize; p += pageSize {
		end := p + pageSize
		if end > codeSize {
			end = codeSize
		}
		hash := computeHash(codeData[p:end], hashType)
		outp = puts(outp, hash)
	}

	return cdir
}

// computeHash computes a hash using the specified algorithm
func computeHash(data []byte, hashType uint8) []byte {
	if len(data) == 0 {
		if hashType == CS_HASHTYPE_SHA1 {
			return make([]byte, sha1.Size)
		}
		return make([]byte, sha256.Size)
	}

	switch hashType {
	case CS_HASHTYPE_SHA1:
		h := sha1.Sum(data)
		return h[:]
	case CS_HASHTYPE_SHA256:
		h := sha256.Sum256(data)
		return h[:]
	default:
		return nil
	}
}

// isEmptyEntitlementsXML checks if the entitlements XML is "empty" (just an empty dict)
// zsign treats empty entitlements specially: 5 slots and no EntitlementsDER
func isEmptyEntitlementsXML(entitlements string) bool {
	// Check for common empty entitlements patterns
	// Pattern 1: <dict></dict>
	// Pattern 2: <dict/>
	if strings.Contains(entitlements, "<dict></dict>") || strings.Contains(entitlements, "<dict/>") {
		// Make sure there's nothing else meaningful in the dict
		// Count occurrences of <key> - if there are none, it's empty
		return !strings.Contains(entitlements, "<key>")
	}
	return false
}

func buildRequirementsBlob(bundleID string) []byte {
	return buildRequirementsBlobWithCert(bundleID, "")
}

// buildRequirementsBlobWithCert builds a requirements blob with the signer's common name for strict validation
func buildRequirementsBlobWithCert(bundleID string, signerCN string) []byte {
	// Build internal requirements: just the designated requirement
	// designated requirement: identifier "bundleID" and anchor apple generic
	// (plus certificate checks if signerCN is provided)
	reqExpr := buildDesignatedRequirementWithCert(bundleID, signerCN)

	// Requirements blob: magic + length + count + (type + offset for each)
	reqCount := uint32(1) // Just designated requirement
	headerSize := 12 + reqCount*8
	totalSize := headerSize + uint32(len(reqExpr))

	blob := make([]byte, totalSize)
	outp := blob

	outp = put32be(outp, CSMAGIC_REQUIREMENTS)
	outp = put32be(outp, totalSize)
	outp = put32be(outp, reqCount)

	// Requirement entry: type (3 = designated) + offset
	outp = put32be(outp, 3) // kSecDesignatedRequirementType
	outp = put32be(outp, headerSize)

	copy(blob[headerSize:], reqExpr)

	return blob
}

func buildDesignatedRequirement(bundleID string) []byte {
	return buildDesignatedRequirementWithCert(bundleID, "")
}

// buildDesignatedRequirementWithCert builds a designated requirement expression matching Apple's format:
// identifier "bundleID" and anchor apple generic and certificate leaf[subject.CN] = "signerCN"
// and certificate 1[field.1.2.840.113635.100.6.2.1] exists
//
// If signerCN is empty, falls back to the simpler format without certificate checks.
func buildDesignatedRequirementWithCert(bundleID string, signerCN string) []byte {
	// Apple's requirement opcodes (from cscdefs.h):
	// opAnd = 6, opIdent = 2, opAppleGenericAnchor = 15, opCertField = 11, opCertGeneric = 14
	// Match operations: matchEqual = 1, matchExists = 0

	const (
		opAnd                 = 6
		opIdent               = 2
		opAppleGenericAnchor  = 15
		opCertField           = 11
		opCertGeneric         = 14
		matchExists           = 0
		matchEqual            = 1
	)

	var exprData bytes.Buffer

	// Helper to write a padded string
	writeString := func(s string) {
		data := []byte(s)
		strLen := len(data)
		paddedLen := (strLen + 3) &^ 3
		binary.Write(&exprData, binary.BigEndian, uint32(strLen))
		exprData.Write(data)
		// Pad to 4-byte boundary
		for i := strLen; i < paddedLen; i++ {
			exprData.WriteByte(0)
		}
	}

	if signerCN == "" {
		// Simple format: identifier "bundleID" and anchor apple generic
		binary.Write(&exprData, binary.BigEndian, uint32(opAnd))
		binary.Write(&exprData, binary.BigEndian, uint32(opIdent))
		writeString(bundleID)
		binary.Write(&exprData, binary.BigEndian, uint32(opAppleGenericAnchor))
	} else {
		// Full Apple format:
		// and(identifier, and(anchor, and(certField, certGeneric)))
		//
		// Structure: opAnd -> opIdent -> string -> opAnd -> opAppleGenericAnchor ->
		//            opAnd -> opCertField -> ... -> opCertGeneric -> ...

		// First AND: identifier and (rest)
		binary.Write(&exprData, binary.BigEndian, uint32(opAnd))
		binary.Write(&exprData, binary.BigEndian, uint32(opIdent))
		writeString(bundleID)

		// Second AND: anchor apple generic and (certificate checks)
		binary.Write(&exprData, binary.BigEndian, uint32(opAnd))
		binary.Write(&exprData, binary.BigEndian, uint32(opAppleGenericAnchor))

		// Third AND: cert_field and cert_generic
		binary.Write(&exprData, binary.BigEndian, uint32(opAnd))

		// opCertField(leaf, "subject.CN") = signerCN
		// Format: opCertField(4) + certSlot(4) + fieldNameLen(4) + fieldName(padded) + matchOp(4) + valueLen(4) + value(padded)
		binary.Write(&exprData, binary.BigEndian, uint32(opCertField))
		binary.Write(&exprData, binary.BigEndian, uint32(0)) // cert slot 0 = leaf
		writeString("subject.CN")
		binary.Write(&exprData, binary.BigEndian, uint32(matchEqual))
		writeString(signerCN)

		// opCertGeneric(1, OID) exists
		// OID 1.2.840.113635.100.6.2.1 = Apple Developer ID
		// Encoded as: 2a 86 48 86 f7 63 64 06 02 01
		appleDevOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01}
		binary.Write(&exprData, binary.BigEndian, uint32(opCertGeneric))
		binary.Write(&exprData, binary.BigEndian, uint32(1)) // cert slot 1 = intermediate
		oidLen := len(appleDevOID)
		paddedOIDLen := (oidLen + 3) &^ 3
		binary.Write(&exprData, binary.BigEndian, uint32(oidLen))
		exprData.Write(appleDevOID)
		for i := oidLen; i < paddedOIDLen; i++ {
			exprData.WriteByte(0)
		}
		binary.Write(&exprData, binary.BigEndian, uint32(matchExists))
	}

	// Wrap in requirement blob with kind field
	// Format: magic(4) + length(4) + kind(4) + expression
	expr := exprData.Bytes()
	totalSize := 8 + 4 + len(expr)
	blob := make([]byte, totalSize)
	binary.BigEndian.PutUint32(blob[0:], CSMAGIC_REQUIREMENT)
	binary.BigEndian.PutUint32(blob[4:], uint32(totalSize))
	binary.BigEndian.PutUint32(blob[8:], 1) // kind = 1 (expression)
	copy(blob[12:], expr)

	return blob
}

func buildEntitlementsBlob(entitlements []byte) []byte {
	// Entitlements blob: magic(4) + length(4) + plist data
	totalSize := 8 + len(entitlements)
	blob := make([]byte, totalSize)

	binary.BigEndian.PutUint32(blob[0:], CSMAGIC_EMBEDDED_ENTITLEMENTS)
	binary.BigEndian.PutUint32(blob[4:], uint32(totalSize))
	copy(blob[8:], entitlements)

	return blob
}

func buildEntitlementsDERBlob(entitlements []byte) []byte {
	// Parse the XML entitlements and convert to DER format
	entMap, err := ParseEntitlementsXML(entitlements)
	if err != nil {
		// If parsing fails, return empty blob
		return nil
	}

	derData, err := EntitlementsToDER(entMap)
	if err != nil {
		return nil
	}

	// DER Entitlements blob: magic(4) + length(4) + DER data
	totalSize := 8 + len(derData)
	blob := make([]byte, totalSize)

	binary.BigEndian.PutUint32(blob[0:], CSMAGIC_EMBEDDED_ENTITLEMENTS_DER)
	binary.BigEndian.PutUint32(blob[4:], uint32(totalSize))
	copy(blob[8:], derData)

	return blob
}

func buildCMSSignature(codeDirectory []byte, identity *SigningIdentity) ([]byte, error) {
	// For backward compatibility, use single-CD version
	return buildCMSSignatureWithDualCD(codeDirectory, codeDirectory, identity)
}

// buildCMSSignatureWithDualCD creates a CMS signature with CDHashes from both CodeDirectories
// zsign signs the SHA1 CodeDirectory (the CMS messageDigest is SHA256 of the SHA1 CD)
// but includes hashes from both CDs in the CDHashes plist
func buildCMSSignatureWithDualCD(cdirSHA1, cdirSHA256 []byte, identity *SigningIdentity) ([]byte, error) {
	// DEBUG: If ZSIGN_CMS_BLOB env var is set, use that pre-built CMS blob instead
	if cmsPath := os.Getenv("ZSIGN_CMS_BLOB"); cmsPath != "" {
		cmsBlob, err := os.ReadFile(cmsPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read ZSIGN_CMS_BLOB: %w", err)
		}
		fmt.Printf("DEBUG: Using pre-built CMS blob from %s (%d bytes)\n", cmsPath, len(cmsBlob))
		return cmsBlob, nil
	}

	// Create PKCS#7 signed data for the SHA1 CodeDirectory (zsign signs SHA1 CD!)
	// The pkcs7 library will compute SHA256 of this content for the messageDigest
	signedData, err := pkcs7.NewSignedData(cdirSHA1)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed data: %w", err)
	}

	// Use SHA256 for the digest algorithm (required for modern iOS)
	signedData.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	// Add signer with certificate chain
	rsaKey, ok := identity.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("only RSA keys are supported")
	}

	// Build Apple-specific signed attributes for CDHashes
	// CDHashes plist contains: SHA1 hash of SHA1 CD, truncated SHA256 hash of SHA256 CD
	cdHashesAttrs, err := buildCDHashesAttributesWithDualCD(cdirSHA1, cdirSHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to build CDHashes attributes: %w", err)
	}

	// Use AddSignerChain to add the signer with proper certificate chain
	// The library adds certs as: [signing cert, parents...] which gives us [signing, WWDR, Root]
	// CertChain is: [signing cert, WWDR G3, Root CA]
	var parents []*x509.Certificate
	if len(identity.CertChain) > 1 {
		parents = identity.CertChain[1:]
	}

	signerConfig := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: cdHashesAttrs,
	}
	if err := signedData.AddSignerChain(identity.Certificate, rsaKey, parents, signerConfig); err != nil {
		return nil, fmt.Errorf("failed to add signer chain: %w", err)
	}

	// Create a detached signature - the content (CodeDirectory) is not embedded
	// in the CMS structure, only a signature over it
	signedData.Detach()

	// Finish signing
	der, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("failed to finish signing: %w", err)
	}

	// zsign uses DER encoding (no BER conversion)
	// Do NOT call fixDetachedContentInfo - zsign outputs definite-length DER

	// Skip certificate reordering for now - it breaks the CMS structure
	// The pkcs7 library outputs [Signing Cert, WWDR G3, Root CA]
	// zsign uses [WWDR G3, Root CA, Signing Cert]
	// TODO: Fix reorderCMSCertificates or switch to a different pkcs7 library
	// For now, let's test if cert order actually matters by skipping reordering
	_ = identity.CertChain // unused but needed for signature

	// Wrap in blob
	totalSize := 8 + len(der)
	blob := make([]byte, totalSize)
	binary.BigEndian.PutUint32(blob[0:], CSMAGIC_BLOBWRAPPER)
	binary.BigEndian.PutUint32(blob[4:], uint32(totalSize))
	copy(blob[8:], der)

	return blob, nil
}

// buildCDHashesAttributes builds the Apple-specific signed attributes for code signing:
// - OID 1.2.840.113635.100.9.1: CDHashes plist (contains array of truncated hashes)
// - OID 1.2.840.113635.100.9.2: CDHashes2 (SHA256 hash as ASN.1 SEQUENCE)
func buildCDHashesAttributes(codeDirectory []byte) ([]pkcs7.Attribute, error) {
	// For single CodeDirectory, use same CD for both
	return buildCDHashesAttributesWithDualCD(codeDirectory, codeDirectory)
}

// buildCDHashesAttributesWithDualCD builds Apple-specific signed attributes with hashes from both CodeDirectories
// This matches zsign's behavior:
// - CDHashes plist contains: SHA1 hash of SHA1 CD, truncated SHA256 hash of SHA256 CD
// - CDHashes2 contains: full SHA256 hash of the SHA256 CD
func buildCDHashesAttributesWithDualCD(cdirSHA1, cdirSHA256 []byte) ([]pkcs7.Attribute, error) {
	// Apple OIDs for code signing attributes
	oidCDHashesPlist := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}
	oidCDHashes2 := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}

	// Compute hashes of each CodeDirectory
	// SHA1 hash of the SHA1 CodeDirectory
	sha1CDHash := sha1.Sum(cdirSHA1)
	// SHA256 hash of the SHA256 CodeDirectory (truncated to 20 bytes for plist)
	sha256CDHash := sha256.Sum256(cdirSHA256)

	// Build CDHashes plist - contains truncated hashes (20 bytes each)
	// zsign format: { "cdhashes" = ( <sha1-of-sha1-cd>, <truncated-sha256-of-sha256-cd> ) }
	cdHashesPlist := buildCDHashesPlist(sha1CDHash[:], sha256CDHash[:20])

	// Build CDHashes2 attribute value - ASN.1 SEQUENCE containing OID + full hash
	// This contains the full SHA256 hash of the SHA256 CodeDirectory
	cdHashes2Value, err := buildCDHashes2ASN1(sha256CDHash[:])
	if err != nil {
		return nil, err
	}

	return []pkcs7.Attribute{
		{
			Type:  oidCDHashesPlist,
			Value: cdHashesPlist,
		},
		{
			Type:  oidCDHashes2,
			Value: cdHashes2Value,
		},
	}, nil
}

// buildCDHashesPlist creates the CDHashes plist containing truncated code directory hashes
func buildCDHashesPlist(sha1Hash, truncatedSHA256 []byte) []byte {
	// Create a plist with cdhashes array
	cdHashes := map[string]interface{}{
		"cdhashes": [][]byte{sha1Hash, truncatedSHA256},
	}

	data, err := plist.Marshal(cdHashes, plist.XMLFormat)
	if err != nil {
		// Fallback to empty if marshal fails
		return []byte{}
	}
	return data
}

// buildCDHashes2ASN1 creates the ASN.1 SEQUENCE for CDHashes2 attribute
// Format: SEQUENCE { OBJECT sha256, OCTET_STRING hash }
func buildCDHashes2ASN1(sha256Hash []byte) (asn1.RawValue, error) {
	// OID for SHA-256: 2.16.840.1.101.3.4.2.1
	sha256OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	// Build the inner SEQUENCE: { OID, OCTET_STRING }
	type hashSeq struct {
		Algorithm asn1.ObjectIdentifier
		Hash      []byte
	}

	seq := hashSeq{
		Algorithm: sha256OID,
		Hash:      sha256Hash,
	}

	encoded, err := asn1.Marshal(seq)
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Return as RawValue so it's included as-is
	return asn1.RawValue{
		FullBytes: encoded,
	}, nil
}

// reorderCMSCertificates reorders the certificates in a CMS SignedData structure
// to match zsign's order: [WWDR G3, Root CA, Signing Cert]
// The pkcs7 library outputs: [Signing Cert, WWDR G3, Root CA]
func reorderCMSCertificates(der []byte, certChain []*x509.Certificate) ([]byte, error) {
	if len(certChain) < 3 {
		// Not enough certs to reorder, return as-is
		return der, nil
	}

	// Parse the outer ContentInfo
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	rest, err := asn1.Unmarshal(der, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after ContentInfo")
	}

	// Parse the SignedData
	var signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue `asn1:"set"`
		EncapContentInfo asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		CRLs             asn1.RawValue `asn1:"optional,tag:1"`
		SignerInfos      asn1.RawValue `asn1:"set"`
	}
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SignedData: %w", err)
	}

	// Build new certificates in zsign order: [WWDR G3, Root CA, Signing Cert]
	// certChain is [Signing, WWDR, Root], so we want [WWDR, Root, Signing]
	var newCertsBytes []byte
	// Add WWDR G3 (index 1)
	newCertsBytes = append(newCertsBytes, certChain[1].Raw...)
	// Add Root CA (index 2)
	newCertsBytes = append(newCertsBytes, certChain[2].Raw...)
	// Add Signing Cert (index 0)
	newCertsBytes = append(newCertsBytes, certChain[0].Raw...)

	// Wrap in context-specific [0] tag
	newCertsRaw := asn1.RawValue{
		Class:      2, // Context-specific
		Tag:        0,
		IsCompound: true,
		Bytes:      newCertsBytes,
	}

	// Rebuild SignedData with new certificate order
	type rebuiltSignedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue `asn1:"set"`
		EncapContentInfo asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		SignerInfos      asn1.RawValue `asn1:"set"`
	}

	rebuilt := rebuiltSignedData{
		Version:          signedData.Version,
		DigestAlgorithms: signedData.DigestAlgorithms,
		EncapContentInfo: signedData.EncapContentInfo,
		Certificates: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      newCertsRaw.Bytes,
		},
		SignerInfos: signedData.SignerInfos,
	}

	newSignedDataBytes, err := asn1.Marshal(rebuilt)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal rebuilt SignedData: %w", err)
	}

	// Rebuild ContentInfo with proper explicit tag [0] around the SignedData SEQUENCE
	// The CMS ContentInfo structure is:
	// SEQUENCE {
	//   contentType OBJECT IDENTIFIER,
	//   content [0] EXPLICIT ANY DEFINED BY contentType
	// }
	// The content must be wrapped in context-specific tag [0]

	// Build the OID bytes
	oidBytes, err := asn1.Marshal(contentInfo.ContentType)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OID: %w", err)
	}

	// Build the [0] context wrapper around SignedData
	// newSignedDataBytes already contains the full SEQUENCE encoding (30 82 XX XX ...)
	// We need to wrap this in [0] (a0 82 XX XX ...)
	// To do this, we use FullBytes which tells Marshal to use this as-is inside the wrapper
	wrapped := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      newSignedDataBytes, // The SEQUENCE bytes go inside [0]
	}
	wrappedBytes, err := asn1.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal [0] wrapper: %w", err)
	}

	// Combine OID + [0]wrapped into the inner content of the outer SEQUENCE
	innerBytes := append(oidBytes, wrappedBytes...)

	// Build outer SEQUENCE manually
	result, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      innerBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ContentInfo: %w", err)
	}

	return result, nil
}

// fixDetachedContentInfo converts a DER-encoded CMS SignedData to use BER indefinite-length
// encoding for the detached ContentInfo, matching Apple's codesign format.
// Apple's AMFI/CT validation requires this specific encoding.
//
// The DER format from go.mozilla.org/pkcs7 uses definite-length encoding.
// Apple requires BER indefinite-length encoding:
//
//	SEQUENCE (indefinite: 30 80)
//	  OID signedData
//	  [0] (indefinite: a0 80)
//	    SEQUENCE (SignedData, indefinite: 30 80)
//	      INTEGER version
//	      SET digestAlgorithms  (with NULL param: 30 0d 06 09 ... 05 00)
//	      SEQUENCE (encapContentInfo, indefinite: 30 80)
//	        OID data
//	        EOC (00 00)  <- empty content for detached
//	      [0] certificates
//	      SET signerInfos
//	      EOC (00 00)
//	    EOC (00 00)
//	  EOC (00 00)
func fixDetachedContentInfo(der []byte) []byte {
	// Parse the DER structure and rebuild with BER indefinite-length encoding
	// for the outer wrappers and a properly detached encapContentInfo.

	// OIDs we need to recognize
	signedDataOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}
	dataOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01}
	sha256OID := []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}

	// Find signedData OID to verify this is the right structure
	signedDataIdx := bytes.Index(der, signedDataOID)
	if signedDataIdx < 0 {
		return der
	}

	// Find the data OID (encapContentInfo)
	dataOIDIdx := bytes.Index(der, dataOID)
	if dataOIDIdx < 0 {
		return der
	}

	// Find the encapContentInfo SEQUENCE start (before the data OID)
	encapStart := -1
	for i := dataOIDIdx - 1; i >= dataOIDIdx-4 && i >= 0; i-- {
		if der[i] == 0x30 {
			encapStart = i
			break
		}
	}
	if encapStart < 0 {
		return der
	}

	// Parse the encapContentInfo SEQUENCE length
	encapLen, encapLenBytes := parseASN1Length(der[encapStart+1:])
	if encapLen < 0 {
		return der
	}
	encapEnd := encapStart + 1 + encapLenBytes + encapLen

	// Find the SignedData SEQUENCE start (after [0] context tag)
	// The [0] comes after signedData OID
	contextStart := signedDataIdx + len(signedDataOID)
	if der[contextStart] != 0xa0 {
		return der
	}

	// Parse [0] length
	contextLen, contextLenBytes := parseASN1Length(der[contextStart+1:])
	if contextLen < 0 {
		return der
	}

	// SignedData SEQUENCE is inside the [0]
	signedDataStart := contextStart + 1 + contextLenBytes
	if der[signedDataStart] != 0x30 {
		return der
	}

	// Find where digestAlgorithms SET ends (before encapContentInfo)
	// Structure: version (3 bytes: 02 01 01) + digestAlgorithms SET
	versionEnd := signedDataStart + 1 // After SEQUENCE tag
	// Skip SignedData length
	_, sdLenBytes := parseASN1Length(der[versionEnd:])
	versionEnd += sdLenBytes

	// Skip version INTEGER
	if der[versionEnd] != 0x02 {
		return der
	}
	versionLen, vLenBytes := parseASN1Length(der[versionEnd+1:])
	digestAlgStart := versionEnd + 1 + vLenBytes + versionLen

	// Parse digestAlgorithms SET
	if der[digestAlgStart] != 0x31 {
		return der
	}
	digestAlgLen, daLenBytes := parseASN1Length(der[digestAlgStart+1:])

	// Everything after encapContentInfo (certificates and signerInfos)
	afterEncap := der[encapEnd:]

	// Now build the new CMS structure with BER indefinite-length encoding
	var result bytes.Buffer

	// 1. ContentInfo SEQUENCE (indefinite)
	result.Write([]byte{0x30, 0x80})
	// signedData OID
	result.Write(signedDataOID)

	// 2. [0] context tag (indefinite)
	result.Write([]byte{0xa0, 0x80})

	// 3. SignedData SEQUENCE (indefinite)
	result.Write([]byte{0x30, 0x80})

	// 4. version INTEGER (unchanged)
	result.Write(der[versionEnd : versionEnd+1+vLenBytes+versionLen])

	// 5. digestAlgorithms SET - need to add NULL parameter if missing
	// The pkcs7 library may produce SHA256 AlgorithmIdentifier without the NULL parameter:
	//   31 0d 30 0b 06 09 60 86 48 01 65 03 04 02 01
	// Apple requires the NULL parameter:
	//   31 0f 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
	digestAlgData := der[digestAlgStart : digestAlgStart+1+daLenBytes+digestAlgLen]
	sha256InDigest := bytes.Index(digestAlgData, sha256OID)
	if sha256InDigest >= 0 {
		afterSHA := sha256InDigest + len(sha256OID)
		// Check if NULL (05 00) follows - if not present or no bytes after OID, insert it
		hasNull := afterSHA+1 < len(digestAlgData) && digestAlgData[afterSHA] == 0x05 && digestAlgData[afterSHA+1] == 0x00
		if !hasNull {
			// Need to insert NULL - rebuild the digestAlgorithms SET
			// New structure: 31 0f 30 0d 06 09 ... 05 00
			newDigestAlg := []byte{0x31, 0x0f, 0x30, 0x0d}
			newDigestAlg = append(newDigestAlg, sha256OID...)
			newDigestAlg = append(newDigestAlg, 0x05, 0x00)
			result.Write(newDigestAlg)
		} else {
			result.Write(digestAlgData)
		}
	} else {
		result.Write(digestAlgData)
	}

	// 6. encapContentInfo SEQUENCE (indefinite) with just OID and EOC
	result.Write([]byte{0x30, 0x80})
	result.Write(dataOID)
	result.Write([]byte{0x00, 0x00}) // EOC for encapContentInfo

	// 7. Everything else (certificates [0] and signerInfos SET)
	result.Write(afterEncap)

	// 8. EOC for SignedData SEQUENCE
	result.Write([]byte{0x00, 0x00})

	// 9. EOC for [0] context tag
	result.Write([]byte{0x00, 0x00})

	// 10. EOC for ContentInfo SEQUENCE
	result.Write([]byte{0x00, 0x00})

	return result.Bytes()
}

// parseASN1Length parses a DER/BER length field and returns the length value and number of bytes consumed
func parseASN1Length(data []byte) (length int, bytesConsumed int) {
	if len(data) == 0 {
		return -1, 0
	}

	if data[0] < 0x80 {
		// Short form: single byte length
		return int(data[0]), 1
	}

	if data[0] == 0x80 {
		// Indefinite length (BER only)
		return -1, 1
	}

	// Long form: first byte is 0x80 | number of length bytes
	numBytes := int(data[0] & 0x7f)
	if numBytes > 4 || len(data) < 1+numBytes {
		return -1, 0
	}

	length = 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}

	return length, 1 + numBytes
}

func nativeSignFatMachOWithContext(path string, data []byte, identity *SigningIdentity, entitlements []byte, bundleID string, bundleCtx *BundleSigningContext) error {
	fat, err := macho.NewFatFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to parse fat binary: %w", err)
	}
	defer fat.Close()

	// Sign each architecture
	signedArches := make([][]byte, len(fat.Arches))
	for i, arch := range fat.Arches {
		archData := data[arch.Offset : uint64(arch.Offset)+uint64(arch.Size)]

		// Zero out existing signature data before parsing - go-macho chokes on some signature formats
		archDataForParsing := make([]byte, len(archData))
		copy(archDataForParsing, archData)
		if sigOffset, sigSize, found := findCodeSignatureOffset(archData); found && sigOffset > 0 && sigOffset < uint32(len(archData)) {
			end := sigOffset + sigSize
			if end > uint32(len(archData)) {
				end = uint32(len(archData))
			}
			for i := sigOffset; i < end; i++ {
				archDataForParsing[i] = 0
			}
		}

		m, err := macho.NewFile(bytes.NewReader(archDataForParsing))
		if err != nil {
			return fmt.Errorf("failed to parse arch %d: %w", i, err)
		}

		signedArch, err := nativeSignThinMachOWithContext(archData, m, identity, entitlements, bundleID, bundleCtx)
		m.Close()
		if err != nil {
			return fmt.Errorf("failed to sign arch %d: %w", i, err)
		}

		signedArches[i] = signedArch
	}

	// Rebuild fat binary
	const alignment = 0x4000
	headerSize := 8 + len(fat.Arches)*20

	offsets := make([]uint32, len(fat.Arches))
	currentOffset := uint32(headerSize)

	for i := range signedArches {
		if currentOffset%alignment != 0 {
			currentOffset = ((currentOffset / alignment) + 1) * alignment
		}
		offsets[i] = currentOffset
		currentOffset += uint32(len(signedArches[i]))
	}

	result := make([]byte, currentOffset)

	// Fat header (big-endian)
	result[0] = 0xca
	result[1] = 0xfe
	result[2] = 0xba
	result[3] = 0xbe
	binary.BigEndian.PutUint32(result[4:], uint32(len(fat.Arches)))

	// Fat arch entries
	for i, arch := range fat.Arches {
		base := 8 + i*20
		binary.BigEndian.PutUint32(result[base:], uint32(arch.CPU))
		binary.BigEndian.PutUint32(result[base+4:], uint32(arch.SubCPU))
		binary.BigEndian.PutUint32(result[base+8:], offsets[i])
		binary.BigEndian.PutUint32(result[base+12:], uint32(len(signedArches[i])))
		binary.BigEndian.PutUint32(result[base+16:], arch.Align)
	}

	// Copy arch data
	for i, archData := range signedArches {
		copy(result[offsets[i]:], archData)
	}

	return os.WriteFile(path, result, 0755)
}

// BundleSigningContext contains context needed for signing a bundle's main executable
type BundleSigningContext struct {
	InfoPlistPath     string // Path to Info.plist (for special slot 1)
	CodeResourcesPath string // Path to CodeResources (for special slot 3)
	TeamID            string // Team ID to embed in CodeDirectory
}

// NativeSignAppBundle signs all Mach-O binaries in an app bundle using our native implementation
// This properly handles nested bundles by signing them from deepest to shallowest,
// generating CodeResources for each bundle before signing its binary.
func NativeSignAppBundle(appPath string, identity *SigningIdentity, entitlements []byte, bundleID string) error {
	// Find all nested bundles (frameworks, plugins, etc.)
	nestedBundles, err := findNestedBundles(appPath)
	if err != nil {
		return fmt.Errorf("failed to find nested bundles: %w", err)
	}

	// Sort by depth (deepest first)
	sort.Slice(nestedBundles, func(i, j int) bool {
		depthI := strings.Count(nestedBundles[i], string(os.PathSeparator))
		depthJ := strings.Count(nestedBundles[j], string(os.PathSeparator))
		return depthI > depthJ
	})

	// Sign each nested bundle
	for _, bundle := range nestedBundles {
		if err := signNestedBundle(bundle, identity); err != nil {
			return fmt.Errorf("failed to sign nested bundle %s: %w", bundle, err)
		}
	}

	// Generate CodeResources for the main app AFTER nested bundles are signed
	// This ensures the CodeResources includes the signatures of nested bundles
	if err := WriteCodeResources(appPath); err != nil {
		return fmt.Errorf("failed to generate CodeResources: %w", err)
	}

	// Now sign the main app
	execName, err := GetAppExecutableName(appPath)
	if err != nil {
		return fmt.Errorf("failed to get executable name: %w", err)
	}
	mainExecPath := filepath.Join(appPath, execName)

	bundleCtx := &BundleSigningContext{
		InfoPlistPath:     filepath.Join(appPath, "Info.plist"),
		CodeResourcesPath: filepath.Join(appPath, "_CodeSignature", "CodeResources"),
		TeamID:            identity.TeamID,
	}

	if err := NativeSignMachOWithContext(mainExecPath, identity, entitlements, bundleID, bundleCtx); err != nil {
		return fmt.Errorf("failed to sign main executable: %w", err)
	}

	return nil
}

// findNestedBundles finds all .framework and .appex bundles within an app
func findNestedBundles(appPath string) ([]string, error) {
	var bundles []string

	err := filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return nil
		}

		// Check for bundle extensions
		ext := filepath.Ext(path)
		if ext == ".framework" || ext == ".appex" || ext == ".xctest" {
			bundles = append(bundles, path)
			// Don't descend into this bundle for more bundles at this level
			// but we still want nested bundles within (handled by the recursion)
		}

		return nil
	})

	return bundles, err
}

// signNestedBundle signs a framework, plugin, or test bundle
func signNestedBundle(bundlePath string, identity *SigningIdentity) error {
	// Find the main binary in this bundle
	bundleName := filepath.Base(bundlePath)
	ext := filepath.Ext(bundleName)
	binaryName := strings.TrimSuffix(bundleName, ext)

	binaryPath := filepath.Join(bundlePath, binaryName)
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		// Some bundles might not have binaries (e.g., resource-only frameworks)
		return nil
	}

	// Remove old signature
	codeSignDir := filepath.Join(bundlePath, "_CodeSignature")
	if err := os.RemoveAll(codeSignDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove old _CodeSignature: %w", err)
	}

	// Generate CodeResources for this bundle
	if err := WriteCodeResources(bundlePath); err != nil {
		return fmt.Errorf("failed to generate CodeResources: %w", err)
	}

	// Create bundle context for signing
	bundleCtx := &BundleSigningContext{
		InfoPlistPath:     filepath.Join(bundlePath, "Info.plist"),
		CodeResourcesPath: filepath.Join(bundlePath, "_CodeSignature", "CodeResources"),
		TeamID:            identity.TeamID,
	}

	// Get bundle ID from Info.plist if available
	bundleID := binaryName
	if plistPath := filepath.Join(bundlePath, "Info.plist"); fileExists(plistPath) {
		if bid, err := GetBundleIDFromPlist(plistPath); err == nil && bid != "" {
			bundleID = bid
		}
	}

	// Use empty entitlements plist for nested bundles (like zsign does)
	// This ensures proper slot hashing and is required for XCTest bundles
	emptyEntitlements := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict/>
</plist>
`)

	// Sign the binary with empty entitlements
	return NativeSignMachOWithContext(binaryPath, identity, emptyEntitlements, bundleID, bundleCtx)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetBundleIDFromPlist reads CFBundleIdentifier from an Info.plist
func GetBundleIDFromPlist(plistPath string) (string, error) {
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return "", err
	}

	var info map[string]interface{}
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return "", err
	}

	if bid, ok := info["CFBundleIdentifier"].(string); ok {
		return bid, nil
	}
	return "", fmt.Errorf("CFBundleIdentifier not found")
}

// NativeSignMachOWithContext signs a Mach-O binary with optional bundle context
func NativeSignMachOWithContext(path string, identity *SigningIdentity, entitlements []byte, bundleID string, bundleCtx *BundleSigningContext) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Check if it's a fat binary
	if len(data) >= 4 && data[0] == 0xca && data[1] == 0xfe && data[2] == 0xba && data[3] == 0xbe {
		return nativeSignFatMachOWithContext(path, data, identity, entitlements, bundleID, bundleCtx)
	}

	// Zero out existing signature data before parsing - go-macho chokes on some signature formats
	// (e.g., when slot 7 EntitlementsDER is missing but referenced in SuperBlob)
	// We keep the data length intact but zero the signature area so parsing skips it
	dataForParsing := make([]byte, len(data))
	copy(dataForParsing, data)
	if sigOffset, sigSize, found := findCodeSignatureOffset(data); found && sigOffset > 0 && sigOffset < uint32(len(data)) {
		// Zero out the signature data so go-macho won't try to parse it
		end := sigOffset + sigSize
		if end > uint32(len(data)) {
			end = uint32(len(data))
		}
		for i := sigOffset; i < end; i++ {
			dataForParsing[i] = 0
		}
	}

	// Parse as thin Mach-O
	m, err := macho.NewFile(bytes.NewReader(dataForParsing))
	if err != nil {
		return fmt.Errorf("failed to parse Mach-O: %w", err)
	}
	defer m.Close()

	signedData, err := nativeSignThinMachOWithContext(data, m, identity, entitlements, bundleID, bundleCtx)
	if err != nil {
		return err
	}

	return os.WriteFile(path, signedData, 0755)
}
