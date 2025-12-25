package codesign

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/codesign"
	ctypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/go-macho/types"
	"go.mozilla.org/pkcs7"
	gop12 "software.sslmate.com/src/go-pkcs12"
)

// Apple Root CA certificate (DER-encoded, base64)
// This is the root certificate for all Apple code signing certificates
const appleRootCABase64 = `MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg++FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9wtj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IWq6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKMaLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAEggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBcNplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQPy3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4FgxhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oPIQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AXUKqK1drk/NAJBzewdXUh`

// Apple Worldwide Developer Relations Certification Authority - G3 certificate (DER-encoded, base64)
// This intermediate CA signs all iOS developer certificates
const appleWWDRG3Base64 = `MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZC4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbWBpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LSVpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsGAQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhMC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3JsMB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYwEAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJHQr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qAHXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETKXXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTCNwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVzaUDSdlTs=`

// getAppleCACertificates returns the Apple Root CA and WWDR G3 certificates
func getAppleCACertificates() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	// Decode and parse Apple Root CA
	rootCADER, err := base64.StdEncoding.DecodeString(appleRootCABase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Apple Root CA: %w", err)
	}
	rootCA, err := x509.ParseCertificate(rootCADER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Apple Root CA: %w", err)
	}

	// Decode and parse Apple WWDR G3
	wwdrDER, err := base64.StdEncoding.DecodeString(appleWWDRG3Base64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Apple WWDR G3: %w", err)
	}
	wwdr, err := x509.ParseCertificate(wwdrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Apple WWDR G3: %w", err)
	}

	// Return in order: WWDR G3 (intermediate), Root CA
	certs = append(certs, wwdr, rootCA)
	return certs, nil
}

// buildCertificateChain ensures the certificate chain includes Apple CA certificates
func buildCertificateChain(identity *SigningIdentity) error {
	// If we already have a full chain (3+ certs), assume it's complete
	if len(identity.CertChain) >= 3 {
		return nil
	}

	// Get Apple CA certificates
	appleCerts, err := getAppleCACertificates()
	if err != nil {
		return err
	}

	// Build the chain: [signing cert, WWDR G3, Root CA]
	chain := []*x509.Certificate{identity.Certificate}
	chain = append(chain, appleCerts...)
	identity.CertChain = chain

	return nil
}

// SigningIdentity represents a code signing identity (certificate + private key)
type SigningIdentity struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
	CertChain   []*x509.Certificate
	TeamID      string
}

// LoadSigningIdentity loads a signing identity from a PKCS#12 file or PEM key
// If the data is PEM-encoded, it extracts the private key and uses the certificate
// from the provisioning profile
func LoadSigningIdentity(p12Data []byte, password string) (*SigningIdentity, error) {
	// Check if this is PEM data
	if bytes.HasPrefix(p12Data, []byte("-----BEGIN")) {
		return loadPEMIdentity(p12Data)
	}

	// Try to decode as PKCS#12
	privateKey, cert, caCerts, err := gop12.DecodeChain(p12Data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode P12: %w", err)
	}

	// Build certificate chain from P12
	chain := []*x509.Certificate{cert}
	chain = append(chain, caCerts...)

	// Extract team ID from certificate
	teamID := extractTeamID(cert)

	identity := &SigningIdentity{
		Certificate: cert,
		PrivateKey:  privateKey,
		CertChain:   chain,
		TeamID:      teamID,
	}

	// Ensure we have the full Apple CA chain for CMS signature
	if err := buildCertificateChain(identity); err != nil {
		return nil, fmt.Errorf("failed to build certificate chain: %w", err)
	}

	return identity, nil
}

// loadPEMIdentity loads a signing identity from PEM-encoded private key
// Note: Certificate must be set separately from provisioning profile
func loadPEMIdentity(pemData []byte) (*SigningIdentity, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var privateKey crypto.PrivateKey
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Certificate will be set from provisioning profile
	return &SigningIdentity{
		PrivateKey: privateKey,
	}, nil
}

// LoadSigningIdentityWithProfile loads a signing identity using a PEM key and
// extracts the matching certificate from the provisioning profile
func LoadSigningIdentityWithProfile(keyData []byte, password string, profile *ProvisioningProfile) (*SigningIdentity, error) {
	identity, err := LoadSigningIdentity(keyData, password)
	if err != nil {
		return nil, err
	}

	// If we already have a certificate (from P12), we're done
	if identity.Certificate != nil {
		return identity, nil
	}

	// Extract certificate from provisioning profile that matches our key
	certs, err := profile.GetCertificates()
	if err != nil {
		return nil, fmt.Errorf("failed to get certificates from profile: %w", err)
	}

	// Find a certificate that matches our private key
	for _, cert := range certs {
		if keyMatchesCert(identity.PrivateKey, cert) {
			identity.Certificate = cert
			identity.CertChain = []*x509.Certificate{cert}
			identity.TeamID = extractTeamID(cert)

			// Ensure we have the full Apple CA chain for CMS signature
			if err := buildCertificateChain(identity); err != nil {
				return nil, fmt.Errorf("failed to build certificate chain: %w", err)
			}

			return identity, nil
		}
	}

	return nil, fmt.Errorf("no certificate in provisioning profile matches the provided private key")
}

// keyMatchesCert checks if a private key matches a certificate's public key
func keyMatchesCert(privateKey crypto.PrivateKey, cert *x509.Certificate) bool {
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return priv.N.Cmp(pub.N) == 0 && priv.E == pub.E
		}
	}
	return false
}

func extractTeamID(cert *x509.Certificate) string {
	// Team ID is typically in the Organizational Unit field
	for _, ou := range cert.Subject.OrganizationalUnit {
		if len(ou) == 10 { // Apple Team IDs are 10 characters
			return ou
		}
	}
	// Fall back to checking the common name or other fields
	return ""
}

// SignMachO signs a single Mach-O binary file
func SignMachO(path string, identity *SigningIdentity, entitlements []byte, bundleID string) error {
	// Read the file
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Parse the Mach-O
	m, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		// Try as fat binary
		return signFatMachO(path, data, identity, entitlements, bundleID)
	}
	defer m.Close()

	// Sign the thin binary
	signedData, err := signThinMachO(data, m, identity, entitlements, bundleID)
	if err != nil {
		return err
	}

	// Write back
	return os.WriteFile(path, signedData, 0755)
}

func signThinMachO(data []byte, m *macho.File, identity *SigningIdentity, entitlements []byte, bundleID string) ([]byte, error) {
	// Find code segment info and __LINKEDIT segment
	var textOffset, textSize uint64
	var linkeditSegOffset uint32 // Offset of __LINKEDIT segment command in file
	var linkeditFileoff uint64   // Original fileoff of __LINKEDIT
	is64Bit := m.Magic == types.Magic64

	headerSize := uint32(32) // Mach-O 64-bit header size
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

	// Calculate code size (everything before the signature)
	codeSize := uint64(len(data))

	// Find LC_CODE_SIGNATURE command offset for later update
	var csLoadCmdOffset uint32
	cmdOffset = headerSize
	hasExistingCS := false
	var originalCSDataoff uint32
	var originalCSDatasize uint32

	// Check for existing signature and strip it
	for _, load := range m.Loads {
		if cs, ok := load.(*macho.CodeSignature); ok {
			codeSize = uint64(cs.Offset)
			csLoadCmdOffset = cmdOffset
			hasExistingCS = true
			originalCSDataoff = cs.Offset
			originalCSDatasize = cs.Size
			break
		}
		cmdOffset += load.LoadSize()
	}

	if !hasExistingCS {
		return nil, fmt.Errorf("no existing LC_CODE_SIGNATURE load command found - adding new commands not yet supported")
	}

	// Create signer function using the identity
	signerFunc := createSignerFunction(identity)

	// Determine flags - use ADHOC only if we don't have a certificate
	flags := ctypes.NONE
	if len(identity.CertChain) == 0 {
		flags = ctypes.ADHOC
	}

	// Generate DER-encoded entitlements if XML entitlements are provided
	// This is required to ensure NSpecialSlots=7 and correct hash offset calculation
	var entitlementsDER []byte
	if len(entitlements) > 0 {
		entMap, err := ParseEntitlementsXML(entitlements)
		if err == nil {
			entitlementsDER, _ = EntitlementsToDER(entMap)
		}
	}

	// Create config for signing
	config := &codesign.Config{
		ID:              bundleID,
		TeamID:          identity.TeamID,
		IsMain:          true,
		Flags:           flags,
		CodeSize:        codeSize,
		TextOffset:      textOffset,
		TextSize:        textSize,
		Entitlements:    entitlements,
		EntitlementsDER: entitlementsDER,
		CertChain:       identity.CertChain,
		SignerFunction:  signerFunc,
	}
	config.InitSlotHashes()

	// Initialize SpecialSlots with empty entries to avoid index out of range
	// when the library checks for previous entitlement hashes
	if len(entitlements) > 0 {
		config.SpecialSlots = make([]ctypes.SpecialSlot, 7)
	}

	// Estimate signature size and pre-update LC_CODE_SIGNATURE before computing hashes
	// This is critical: the page hashes must be computed on the final binary content,
	// including the updated LC_CODE_SIGNATURE load command
	estimatedSigSize := codesign.EstimateCodeSignatureSize(config)
	// Round up to 16KB alignment for safety (matching zsign's approach)
	estimatedSigSize = ((estimatedSigSize + 0x3fff) / 0x4000) * 0x4000

	// Create a copy of data with updated LC_CODE_SIGNATURE values
	dataForHashing := make([]byte, codeSize)
	copy(dataForHashing, data[:codeSize])

	// Update LC_CODE_SIGNATURE in the copy: dataoff and datasize
	copy(dataForHashing[csLoadCmdOffset+8:csLoadCmdOffset+12], uint32ToBytes(uint32(codeSize)))
	copy(dataForHashing[csLoadCmdOffset+12:csLoadCmdOffset+16], uint32ToBytes(uint32(estimatedSigSize)))

	// Update __LINKEDIT segment to reflect new signature size
	// This is critical for iOS signature verification - the segment must accurately
	// describe the file layout including the new signature
	if linkeditSegOffset > 0 {
		// Calculate how much the file size changed
		newFileSize := codeSize + estimatedSigSize
		// The new __LINKEDIT filesize = newFileSize - linkeditFileoff
		newLinkeditFilesize := newFileSize - linkeditFileoff
		// vmsize should be page-aligned (4096)
		newLinkeditVmsize := ((newLinkeditFilesize + 0xfff) / 0x1000) * 0x1000

		if is64Bit {
			// segment_command_64 layout:
			// cmd(4) + cmdsize(4) + segname(16) + vmaddr(8) + vmsize(8) + fileoff(8) + filesize(8) + ...
			// vmsize is at offset 24, filesize is at offset 40
			copy(dataForHashing[linkeditSegOffset+24:linkeditSegOffset+32], uint64ToBytes(newLinkeditVmsize))
			copy(dataForHashing[linkeditSegOffset+40:linkeditSegOffset+48], uint64ToBytes(newLinkeditFilesize))
		} else {
			// segment_command layout:
			// cmd(4) + cmdsize(4) + segname(16) + vmaddr(4) + vmsize(4) + fileoff(4) + filesize(4) + ...
			// vmsize is at offset 28, filesize is at offset 36
			copy(dataForHashing[linkeditSegOffset+28:linkeditSegOffset+32], uint32ToBytes(uint32(newLinkeditVmsize)))
			copy(dataForHashing[linkeditSegOffset+36:linkeditSegOffset+40], uint32ToBytes(uint32(newLinkeditFilesize)))
		}

		_ = originalCSDataoff   // Used for reference
		_ = originalCSDatasize  // Used for reference
	}

	// Generate the signature using the pre-updated data
	signature, err := codesign.Sign(bytes.NewReader(dataForHashing), config)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Pad signature to match estimated size
	if uint64(len(signature)) < estimatedSigSize {
		padded := make([]byte, estimatedSigSize)
		copy(padded, signature)
		signature = padded
	}

	// Fix SuperBlob length to match padded size
	if len(signature) >= 8 {
		actualLen := uint32(len(signature))
		signature[4] = byte(actualLen >> 24)
		signature[5] = byte(actualLen >> 16)
		signature[6] = byte(actualLen >> 8)
		signature[7] = byte(actualLen)
	}

	// Create new binary with signature appended
	result := make([]byte, codeSize+uint64(len(signature)))
	copy(result, dataForHashing)
	copy(result[codeSize:], signature)

	return result, nil
}

func signFatMachO(path string, data []byte, identity *SigningIdentity, entitlements []byte, bundleID string) error {
	fat, err := macho.NewFatFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to parse as fat binary: %w", err)
	}
	defer fat.Close()

	// Sign each architecture and collect results
	signedArches := make([][]byte, len(fat.Arches))
	for i, arch := range fat.Arches {
		archData := data[arch.Offset : uint64(arch.Offset)+uint64(arch.Size)]

		m, err := macho.NewFile(bytes.NewReader(archData))
		if err != nil {
			return fmt.Errorf("failed to parse arch %d: %w", i, err)
		}

		signedArch, err := signThinMachO(archData, m, identity, entitlements, bundleID)
		m.Close()
		if err != nil {
			return fmt.Errorf("failed to sign arch %d: %w", i, err)
		}

		signedArches[i] = signedArch
	}

	// Rebuild the fat binary with new arch sizes
	// Fat header: magic(4) + nfat_arch(4) = 8 bytes
	// Each fat_arch: cpu_type(4) + cpu_subtype(4) + offset(4) + size(4) + align(4) = 20 bytes
	headerSize := 8 + len(fat.Arches)*20

	// Calculate offsets - each arch must be aligned
	// Standard alignment is 16KB (0x4000) for arm64
	const alignment = 0x4000
	offsets := make([]uint32, len(fat.Arches))
	currentOffset := uint32(headerSize)

	for i := range signedArches {
		// Align offset
		if currentOffset%alignment != 0 {
			currentOffset = ((currentOffset / alignment) + 1) * alignment
		}
		offsets[i] = currentOffset
		currentOffset += uint32(len(signedArches[i]))
	}

	// Build the new fat binary
	result := make([]byte, currentOffset)

	// Write fat header (big-endian)
	result[0] = 0xca
	result[1] = 0xfe
	result[2] = 0xba
	result[3] = 0xbe
	result[4] = 0
	result[5] = 0
	result[6] = 0
	result[7] = byte(len(fat.Arches))

	// Write fat_arch entries (big-endian)
	for i, arch := range fat.Arches {
		base := 8 + i*20
		// cpu_type
		result[base+0] = byte(arch.CPU >> 24)
		result[base+1] = byte(arch.CPU >> 16)
		result[base+2] = byte(arch.CPU >> 8)
		result[base+3] = byte(arch.CPU)
		// cpu_subtype
		result[base+4] = byte(arch.SubCPU >> 24)
		result[base+5] = byte(arch.SubCPU >> 16)
		result[base+6] = byte(arch.SubCPU >> 8)
		result[base+7] = byte(arch.SubCPU)
		// offset
		result[base+8] = byte(offsets[i] >> 24)
		result[base+9] = byte(offsets[i] >> 16)
		result[base+10] = byte(offsets[i] >> 8)
		result[base+11] = byte(offsets[i])
		// size
		size := uint32(len(signedArches[i]))
		result[base+12] = byte(size >> 24)
		result[base+13] = byte(size >> 16)
		result[base+14] = byte(size >> 8)
		result[base+15] = byte(size)
		// align (keep original)
		result[base+16] = byte(arch.Align >> 24)
		result[base+17] = byte(arch.Align >> 16)
		result[base+18] = byte(arch.Align >> 8)
		result[base+19] = byte(arch.Align)
	}

	// Write arch data at their offsets
	for i, archData := range signedArches {
		copy(result[offsets[i]:], archData)
	}

	return os.WriteFile(path, result, 0755)
}

func createSignerFunction(identity *SigningIdentity) func([]byte) ([]byte, error) {
	return func(codeDirectoryData []byte) ([]byte, error) {
		// Create a PKCS#7 signed data structure
		signedData, err := pkcs7.NewSignedData(codeDirectoryData)
		if err != nil {
			return nil, fmt.Errorf("failed to create signed data: %w", err)
		}

		// Add the signer
		if err := signedData.AddSigner(identity.Certificate, identity.PrivateKey.(*rsa.PrivateKey), pkcs7.SignerInfoConfig{}); err != nil {
			return nil, fmt.Errorf("failed to add signer: %w", err)
		}

		// Finish and return the DER-encoded signature
		return signedData.Finish()
	}
}

func uint32ToBytes(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func uint64ToBytes(v uint64) []byte {
	return []byte{
		byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
		byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56),
	}
}

// SignAppBundle signs all Mach-O binaries in an app bundle
// It signs in the correct order: deepest binaries first, main executable last
func SignAppBundle(appPath string, identity *SigningIdentity, entitlements []byte, bundleID string) error {
	// Find all Mach-O binaries
	binaries, err := findMachOBinaries(appPath)
	if err != nil {
		return fmt.Errorf("failed to find binaries: %w", err)
	}

	// Sort by depth (deepest first) to sign frameworks before main app
	sort.Slice(binaries, func(i, j int) bool {
		depthI := strings.Count(binaries[i], string(os.PathSeparator))
		depthJ := strings.Count(binaries[j], string(os.PathSeparator))
		return depthI > depthJ
	})

	// Get the main executable name
	execName, err := GetAppExecutableName(appPath)
	if err != nil {
		return fmt.Errorf("failed to get executable name: %w", err)
	}
	mainExecPath := filepath.Join(appPath, execName)

	// Sign each binary
	for _, binary := range binaries {
		// Only use entitlements for the main executable
		var binaryEntitlements []byte
		if binary == mainExecPath {
			binaryEntitlements = entitlements
		}

		// Get bundle ID for this binary
		binaryBundleID := bundleID
		if binary != mainExecPath {
			// For frameworks/extensions, try to get their bundle ID
			binaryBundleID = getBundleIDForBinary(binary, bundleID)
		}

		if err := SignMachO(binary, identity, binaryEntitlements, binaryBundleID); err != nil {
			return fmt.Errorf("failed to sign %s: %w", binary, err)
		}
	}

	return nil
}

func findMachOBinaries(appPath string) ([]string, error) {
	var binaries []string

	err := filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip non-executable files (simple heuristic)
		if info.Mode()&0111 == 0 {
			// Check if it might be a framework binary (no extension, in a .framework)
			if !strings.Contains(path, ".framework") {
				return nil
			}
		}

		// Check if it's a Mach-O file
		if isMachO(path) {
			binaries = append(binaries, path)
		}

		return nil
	})

	return binaries, err
}

func isMachO(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	// Read magic number
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return false
	}

	// Check for Mach-O magic numbers
	// MH_MAGIC_64 = 0xfeedfacf (little endian: cf fa ed fe)
	// MH_MAGIC    = 0xfeedface (little endian: ce fa ed fe)
	// FAT_MAGIC   = 0xcafebabe (big endian: ca fe ba be)
	// FAT_MAGIC_64 = 0xcafebabf (big endian: ca fe ba bf)
	return (magic[0] == 0xcf && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe) || // MH_MAGIC_64
		(magic[0] == 0xce && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe) || // MH_MAGIC
		(magic[0] == 0xca && magic[1] == 0xfe && magic[2] == 0xba && magic[3] == 0xbe) || // FAT_MAGIC
		(magic[0] == 0xca && magic[1] == 0xfe && magic[2] == 0xba && magic[3] == 0xbf) // FAT_MAGIC_64
}

func getBundleIDForBinary(binaryPath, fallbackBundleID string) string {
	// Try to find Info.plist in parent directories
	dir := filepath.Dir(binaryPath)
	for i := 0; i < 5; i++ { // Look up to 5 levels
		infoPlist := filepath.Join(dir, "Info.plist")
		if data, err := os.ReadFile(infoPlist); err == nil {
			if info, err := parseInfoPlist(data); err == nil {
				if bundleID, ok := info["CFBundleIdentifier"].(string); ok {
					return bundleID
				}
			}
		}
		dir = filepath.Dir(dir)
	}
	return fallbackBundleID
}
