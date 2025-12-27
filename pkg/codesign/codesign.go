package codesign

// Native code signing implementation for iOS apps
// This provides a clean implementation without the bugs in go-macho library

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"go.mozilla.org/pkcs7"
	"howett.net/plist"
	gop12 "software.sslmate.com/src/go-pkcs12"
)

// Mach-O header sizes
const (
	MachOHeader32Size = 28
	MachOHeader64Size = 32
)

// Mach-O magic numbers
const (
	MH_MAGIC     = 0xfeedface // 32-bit little-endian
	MH_MAGIC_64  = 0xfeedfacf // 64-bit little-endian
	FAT_MAGIC    = 0xcafebabe // Fat binary (big-endian)
	FAT_MAGIC_64 = 0xcafebabf // Fat binary 64 (big-endian)
)

// Page size for code signing (4KB)
const (
	PageSizeBits = 12
	PageSize     = 1 << PageSizeBits // 4096 bytes
)

// Code signature magic numbers (from Apple's cs_blobs.h)
const (
	CSMAGIC_REQUIREMENT               = 0xfade0c00
	CSMAGIC_REQUIREMENTS              = 0xfade0c01
	CSMAGIC_CODEDIRECTORY             = 0xfade0c02
	CSMAGIC_EMBEDDED_SIGNATURE        = 0xfade0cc0
	CSMAGIC_EMBEDDED_ENTITLEMENTS     = 0xfade7171
	CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xfade7172
	CSMAGIC_BLOBWRAPPER               = 0xfade0b01
)

// Code signature slot indices
const (
	CSSLOT_CODEDIRECTORY             = 0
	CSSLOT_INFOSLOT                  = 1
	CSSLOT_REQUIREMENTS              = 2
	CSSLOT_RESOURCEDIR               = 3
	CSSLOT_APPLICATION               = 4
	CSSLOT_ENTITLEMENTS              = 5
	CSSLOT_DER_ENTITLEMENTS          = 7
	CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
	CSSLOT_SIGNATURESLOT             = 0x10000
)

// Code directory hash types
const (
	CS_HASHTYPE_SHA1   = 1
	CS_HASHTYPE_SHA256 = 2
)

// Hash sizes
const (
	CS_SHA1_LEN   = 20
	CS_SHA256_LEN = 32
	CS_CDHASH_LEN = 20 // Truncated hash length for CDHashes
)

// Executable segment flags
const (
	CS_EXECSEG_MAIN_BINARY    = 0x1
	CS_EXECSEG_ALLOW_UNSIGNED = 0x10
)

// Load commands
const (
	LC_CODE_SIGNATURE      = 0x1d
	LC_CODE_SIGNATURE_SIZE = 16
)

// Fat binary alignment
const FatArchAlignment = 0x4000 // 16KB

// Apple certificate URLs
const (
	AppleRootCAURL = "https://www.apple.com/appleca/AppleIncRootCertificate.cer"
	AppleWWDRG3URL = "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer"
)

// Apple Root CA certificate (DER-encoded, base64) - fallback if download fails
const appleRootCABase64 = `MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg++FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9wtj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IWq6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKMaLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAEggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBcNplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQPy3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4FgxhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oPIQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AXUKqK1drk/NAJBzewdXUh`

// Apple Worldwide Developer Relations Certification Authority - G3 certificate (DER-encoded, base64) - fallback
const appleWWDRG3Base64 = `MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZC4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbWBpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LSVpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsGAQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhMC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3JsMB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYwEAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJHQr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qAHXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETKXXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTCNwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVzaUDSdlTs=`

var (
	appleCertsOnce sync.Once
	appleCerts     []*x509.Certificate
	appleCertsErr  error
)

// getAppleCACertificates returns the Apple Root CA and WWDR G3 certificates
// It first tries to download from Apple's servers, then falls back to embedded certs
func getAppleCACertificates() ([]*x509.Certificate, error) {
	appleCertsOnce.Do(func() {
		var certs []*x509.Certificate

		// Try to download from Apple
		rootCA, err := downloadCertificate(AppleRootCAURL)
		if err != nil {
			// Fall back to embedded cert
			rootCADER, _ := base64.StdEncoding.DecodeString(appleRootCABase64)
			rootCA, err = x509.ParseCertificate(rootCADER)
			if err != nil {
				appleCertsErr = fmt.Errorf("failed to parse embedded Apple Root CA: %w", err)
				return
			}
		}

		wwdr, err := downloadCertificate(AppleWWDRG3URL)
		if err != nil {
			// Fall back to embedded cert
			wwdrDER, _ := base64.StdEncoding.DecodeString(appleWWDRG3Base64)
			wwdr, err = x509.ParseCertificate(wwdrDER)
			if err != nil {
				appleCertsErr = fmt.Errorf("failed to parse embedded Apple WWDR G3: %w", err)
				return
			}
		}

		// Return in order: WWDR G3 (intermediate), Root CA
		certs = append(certs, wwdr, rootCA)
		appleCerts = certs
	})

	return appleCerts, appleCertsErr
}

// downloadCertificate downloads a DER-encoded certificate from a URL
func downloadCertificate(url string) (*x509.Certificate, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download certificate: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(data)
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
	return ""
}

// BundleSigningContext contains context needed for signing a bundle's main executable
type BundleSigningContext struct {
	InfoPlistPath     string // Path to Info.plist (for special slot 1)
	CodeResourcesPath string // Path to CodeResources (for special slot 3)
	TeamID            string // Team ID to embed in CodeDirectory
}

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

// findCodeSignatureOffset finds the LC_CODE_SIGNATURE offset and size without full parsing
func findCodeSignatureOffset(data []byte) (offset, size uint32, found bool) {
	if len(data) < MachOHeader64Size {
		return 0, 0, false
	}

	magic := binary.LittleEndian.Uint32(data[:4])
	var is64Bit bool
	var headerSize uint32

	switch magic {
	case MH_MAGIC_64:
		is64Bit = true
		headerSize = MachOHeader64Size
	case MH_MAGIC:
		is64Bit = false
		headerSize = MachOHeader32Size
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

		if cmd == LC_CODE_SIGNATURE && cmdSize >= LC_CODE_SIGNATURE_SIZE {
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

// NativeSignMachOWithContext signs a Mach-O binary with optional bundle context
func NativeSignMachOWithContext(path string, identity *SigningIdentity, entitlements []byte, bundleID string, bundleCtx *BundleSigningContext) error {
	// Validate path exists
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory, expected file: %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Check if it's a fat binary
	if len(data) >= 4 && data[0] == 0xca && data[1] == 0xfe && data[2] == 0xba && data[3] == 0xbe {
		return nativeSignFatMachOWithContext(path, data, identity, entitlements, bundleID, bundleCtx)
	}

	// Zero out existing signature data before parsing - go-macho chokes on some signature formats
	dataForParsing := make([]byte, len(data))
	copy(dataForParsing, data)
	if sigOffset, sigSize, found := findCodeSignatureOffset(data); found && sigOffset > 0 && sigOffset < uint32(len(data)) {
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
	defer func() { _ = m.Close() }()

	signedData, err := nativeSignThinMachOWithContext(data, m, identity, entitlements, bundleID, bundleCtx)
	if err != nil {
		return err
	}

	return os.WriteFile(path, signedData, 0755)
}

func nativeSignThinMachOWithContext(data []byte, m *macho.File, identity *SigningIdentity, entitlements []byte, bundleID string, bundleCtx *BundleSigningContext) ([]byte, error) {
	is64Bit := m.Magic == types.Magic64

	var textOffset, textSize uint64
	var linkeditSegOffset uint32
	var linkeditFileoff uint64

	headerSize := uint32(MachOHeader64Size)
	if m.Magic == types.Magic32 {
		headerSize = MachOHeader32Size
	}

	cmdOffset := headerSize
	for _, load := range m.Loads {
		if seg, ok := load.(*macho.Segment); ok {
			switch seg.Name {
			case "__TEXT":
				textOffset = seg.Offset
				textSize = seg.Filesz
			case "__LINKEDIT":
				linkeditSegOffset = cmdOffset
				linkeditFileoff = seg.Offset
			}
		}
		cmdOffset += load.LoadSize()
	}

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
		return addSignatureToUnsignedWithContext(data, m, identity, entitlements, bundleID, textOffset, textSize, bundleCtx)
	}

	// Calculate new signature size
	codePages := (codeSize + PageSize - 1) / PageSize
	hashSpaceNeeded := (codePages + 1) * 52 // 20 + 32 bytes per page
	alignedHashSpace := ((hashSpaceNeeded + 4095) / 4096) * 4096
	finalSigSize := uint32(alignedHashSpace + 16384)

	dataForHashing := make([]byte, codeSize)
	copy(dataForHashing, data[:codeSize])

	binary.LittleEndian.PutUint32(dataForHashing[csLoadCmdOffset+8:], uint32(codeSize))
	binary.LittleEndian.PutUint32(dataForHashing[csLoadCmdOffset+12:], finalSigSize)

	if linkeditSegOffset > 0 {
		newFileSize := codeSize + uint64(finalSigSize)
		newLinkeditFilesize := newFileSize - linkeditFileoff
		newLinkeditVmsize := ((newLinkeditFilesize + 4095) / 4096) * 4096

		if is64Bit {
			binary.LittleEndian.PutUint64(dataForHashing[linkeditSegOffset+32:], newLinkeditVmsize)
			binary.LittleEndian.PutUint64(dataForHashing[linkeditSegOffset+48:], newLinkeditFilesize)
		} else {
			binary.LittleEndian.PutUint32(dataForHashing[linkeditSegOffset+28:], uint32(newLinkeditVmsize))
			binary.LittleEndian.PutUint32(dataForHashing[linkeditSegOffset+36:], uint32(newLinkeditFilesize))
		}
	}

	sig, err := createSignatureWithContext(dataForHashing, identity, entitlements, bundleID, textOffset, textSize, bundleCtx)
	if err != nil {
		return nil, err
	}

	paddedSig := make([]byte, finalSigSize)
	copy(paddedSig, sig)

	result := make([]byte, codeSize+uint64(finalSigSize))
	copy(result, dataForHashing)
	copy(result[codeSize:], paddedSig)

	return result, nil
}

func addSignatureToUnsignedWithContext(data []byte, m *macho.File, identity *SigningIdentity, entitlements []byte, bundleID string, textOffset, textSize uint64, bundleCtx *BundleSigningContext) ([]byte, error) {
	is64Bit := m.Magic == types.Magic64
	headerSize := uint32(MachOHeader32Size)
	if is64Bit {
		headerSize = MachOHeader64Size
	}

	var ncmds, sizeofcmds uint32
	if is64Bit {
		ncmds = binary.LittleEndian.Uint32(data[16:20])
		sizeofcmds = binary.LittleEndian.Uint32(data[20:24])
	} else {
		ncmds = binary.LittleEndian.Uint32(data[12:16])
		sizeofcmds = binary.LittleEndian.Uint32(data[16:20])
	}

	loadCmdsEnd := headerSize + sizeofcmds

	if textOffset > 0 && uint64(loadCmdsEnd+LC_CODE_SIGNATURE_SIZE) > textOffset {
		return nil, fmt.Errorf("no room to add LC_CODE_SIGNATURE load command")
	}

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

	codeSize := uint64(len(data))
	alignedCodeSize := (codeSize + 15) &^ 15

	codePages := (alignedCodeSize / PageSize) + 1
	hashSpaceNeeded := codePages * 52
	alignedHashSpace := ((hashSpaceNeeded + 4095) / 4096) * 4096
	finalSigSize := uint32(alignedHashSpace + 16384)

	dataWithNewCmd := make([]byte, alignedCodeSize)
	copy(dataWithNewCmd, data)

	for i := len(data); i < int(alignedCodeSize); i++ {
		dataWithNewCmd[i] = 0
	}

	if is64Bit {
		binary.LittleEndian.PutUint32(dataWithNewCmd[16:20], ncmds+1)
		binary.LittleEndian.PutUint32(dataWithNewCmd[20:24], sizeofcmds+LC_CODE_SIGNATURE_SIZE)
	} else {
		binary.LittleEndian.PutUint32(dataWithNewCmd[12:16], ncmds+1)
		binary.LittleEndian.PutUint32(dataWithNewCmd[16:20], sizeofcmds+LC_CODE_SIGNATURE_SIZE)
	}

	csLoadCmdOffset := loadCmdsEnd
	binary.LittleEndian.PutUint32(dataWithNewCmd[csLoadCmdOffset:], LC_CODE_SIGNATURE)
	binary.LittleEndian.PutUint32(dataWithNewCmd[csLoadCmdOffset+4:], LC_CODE_SIGNATURE_SIZE)
	binary.LittleEndian.PutUint32(dataWithNewCmd[csLoadCmdOffset+8:], uint32(alignedCodeSize))
	binary.LittleEndian.PutUint32(dataWithNewCmd[csLoadCmdOffset+12:], finalSigSize)

	if linkeditOffset > 0 {
		newLinkeditFilesize := linkeditFilesize + (alignedCodeSize - codeSize) + uint64(finalSigSize)
		sizeIncrease := (alignedCodeSize + uint64(finalSigSize)) - codeSize
		newLinkeditVmsize := ((linkeditVmsize + sizeIncrease + 4095) / 4096) * 4096
		if is64Bit {
			binary.LittleEndian.PutUint64(dataWithNewCmd[linkeditOffset+32:], newLinkeditVmsize)
			binary.LittleEndian.PutUint64(dataWithNewCmd[linkeditOffset+48:], newLinkeditFilesize)
		} else {
			binary.LittleEndian.PutUint32(dataWithNewCmd[linkeditOffset+28:], uint32(newLinkeditVmsize))
			binary.LittleEndian.PutUint32(dataWithNewCmd[linkeditOffset+36:], uint32(newLinkeditFilesize))
		}
		_ = linkeditFileoff
	}

	sig, err := createSignatureWithContext(dataWithNewCmd, identity, entitlements, bundleID, textOffset, textSize, bundleCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	paddedSig := make([]byte, finalSigSize)
	copy(paddedSig, sig)

	result := make([]byte, alignedCodeSize+uint64(finalSigSize))
	copy(result, dataWithNewCmd)
	copy(result[alignedCodeSize:], paddedSig)

	return result, nil
}

func createSignatureWithContext(codeData []byte, identity *SigningIdentity, entitlements []byte, bundleID string, textOffset, textSize uint64, bundleCtx *BundleSigningContext) ([]byte, error) {
	codeSize := int64(len(codeData))
	nhashes := (codeSize + PageSize - 1) / PageSize
	hasEntitlements := len(entitlements) > 0

	var teamID string
	if bundleCtx != nil && bundleCtx.TeamID != "" {
		teamID = bundleCtx.TeamID
	}

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

	signerCN := ""
	if identity != nil && identity.Certificate != nil {
		signerCN = identity.Certificate.Subject.CommonName
	}
	reqBlob := buildRequirementsBlobWithCert(bundleID, signerCN)

	isEmptyEntitlements := hasEntitlements && isEmptyEntitlementsXML(string(entitlements))

	var entBlob, entDERBlob []byte
	if hasEntitlements {
		entBlob = buildEntitlementsBlob(entitlements)
		if !isEmptyEntitlements {
			entDERBlob = buildEntitlementsDERBlob(entitlements)
		}
	}

	hasCodeResources := len(codeResourcesData) > 0
	nSpecialSlots := uint32(2)
	if hasEntitlements && !isEmptyEntitlements {
		nSpecialSlots = 7
	} else if hasEntitlements || hasCodeResources {
		nSpecialSlots = 5
	}

	var execSegFlags uint64 = 0
	if hasEntitlements && strings.Contains(string(entitlements), "get-task-allow") {
		execSegFlags = CS_EXECSEG_MAIN_BINARY | CS_EXECSEG_ALLOW_UNSIGNED
	}

	cdirSHA1 := buildCodeDirectory(codeData, bundleID, teamID, nSpecialSlots, nhashes, codeSize,
		textOffset, textSize, reqBlob, entBlob, entDERBlob, infoPlistData, codeResourcesData,
		sha1.Size, CS_HASHTYPE_SHA1, execSegFlags)

	cdirSHA256 := buildCodeDirectory(codeData, bundleID, teamID, nSpecialSlots, nhashes, codeSize,
		textOffset, textSize, reqBlob, entBlob, entDERBlob, infoPlistData, codeResourcesData,
		sha256.Size, CS_HASHTYPE_SHA256, execSegFlags)

	cmsBlob, err := buildCMSSignatureWithDualCD(cdirSHA1, cdirSHA256, identity)
	if err != nil {
		return nil, fmt.Errorf("failed to create CMS signature: %w", err)
	}

	blobCount := 4
	if hasEntitlements && !isEmptyEntitlements {
		blobCount = 6
	} else if hasEntitlements {
		blobCount = 5
	}

	headerSize := 12 + blobCount*8
	cdirSHA1Offset := headerSize
	reqOffset := cdirSHA1Offset + len(cdirSHA1)
	entOffset := reqOffset + len(reqBlob)
	entDEROffset := entOffset
	cdirSHA256Offset := entOffset
	if hasEntitlements && !isEmptyEntitlements {
		entDEROffset = entOffset + len(entBlob)
		cdirSHA256Offset = entDEROffset + len(entDERBlob)
	} else if hasEntitlements {
		cdirSHA256Offset = entOffset + len(entBlob)
	}
	cmsOffset := cdirSHA256Offset + len(cdirSHA256)

	totalSize := cmsOffset + len(cmsBlob)

	superBlob := make([]byte, totalSize)
	outp := superBlob

	outp = put32be(outp, CSMAGIC_EMBEDDED_SIGNATURE)
	outp = put32be(outp, uint32(totalSize))
	outp = put32be(outp, uint32(blobCount))

	outp = put32be(outp, CSSLOT_CODEDIRECTORY)
	outp = put32be(outp, uint32(cdirSHA1Offset))

	outp = put32be(outp, CSSLOT_REQUIREMENTS)
	outp = put32be(outp, uint32(reqOffset))

	if hasEntitlements {
		outp = put32be(outp, CSSLOT_ENTITLEMENTS)
		outp = put32be(outp, uint32(entOffset))

		if !isEmptyEntitlements {
			outp = put32be(outp, CSSLOT_DER_ENTITLEMENTS)
			outp = put32be(outp, uint32(entDEROffset))
		}
	}

	outp = put32be(outp, CSSLOT_ALTERNATE_CODEDIRECTORIES)
	outp = put32be(outp, uint32(cdirSHA256Offset))

	outp = put32be(outp, CSSLOT_SIGNATURESLOT)
	_ = put32be(outp, uint32(cmsOffset))

	copy(superBlob[cdirSHA1Offset:], cdirSHA1)
	copy(superBlob[reqOffset:], reqBlob)
	if hasEntitlements {
		copy(superBlob[entOffset:], entBlob)
		if !isEmptyEntitlements && len(entDERBlob) > 0 {
			copy(superBlob[entDEROffset:], entDERBlob)
		}
	}
	copy(superBlob[cdirSHA256Offset:], cdirSHA256)
	copy(superBlob[cmsOffset:], cmsBlob)

	return superBlob, nil
}

func buildCodeDirectory(codeData []byte, bundleID, teamID string, nSpecialSlots uint32, nhashes, codeSize int64,
	textOffset, textSize uint64, reqBlob, entBlob, entDERBlob, infoPlistData, codeResourcesData []byte,
	hashSize int, hashType uint8, execSegFlags uint64) []byte {

	idOff := uint32(88)
	teamOff := uint32(0)
	hashOff := idOff + uint32(len(bundleID)+1)

	if teamID != "" {
		teamOff = hashOff
		hashOff = teamOff + uint32(len(teamID)+1)
	}

	hashOff += nSpecialSlots * uint32(hashSize)

	cdirLen := hashOff + uint32(nhashes)*uint32(hashSize)

	cdir := make([]byte, cdirLen)
	outp := cdir

	outp = put32be(outp, CSMAGIC_CODEDIRECTORY)
	outp = put32be(outp, cdirLen)
	outp = put32be(outp, 0x20400)
	outp = put32be(outp, 0)
	outp = put32be(outp, hashOff)
	outp = put32be(outp, idOff)
	outp = put32be(outp, nSpecialSlots)
	outp = put32be(outp, uint32(nhashes))
	outp = put32be(outp, uint32(codeSize))
	outp = put8(outp, uint8(hashSize))
	outp = put8(outp, hashType)
	outp = put8(outp, 0)
	outp = put8(outp, PageSizeBits)
	outp = put32be(outp, 0)
	outp = put32be(outp, 0)
	outp = put32be(outp, teamOff)
	outp = put32be(outp, 0)
	outp = put64be(outp, 0)
	outp = put64be(outp, textOffset)
	outp = put64be(outp, textSize)
	outp = put64be(outp, execSegFlags)

	outp = puts(outp, []byte(bundleID+"\x00"))

	if teamID != "" {
		outp = puts(outp, []byte(teamID+"\x00"))
	}

	for i := int(nSpecialSlots); i >= 1; i-- {
		var hash []byte
		switch i {
		case CSSLOT_INFOSLOT:
			hash = computeHash(infoPlistData, hashType)
		case CSSLOT_REQUIREMENTS:
			hash = computeHash(reqBlob, hashType)
		case CSSLOT_RESOURCEDIR:
			hash = computeHash(codeResourcesData, hashType)
		case CSSLOT_ENTITLEMENTS:
			hash = computeHash(entBlob, hashType)
		case CSSLOT_DER_ENTITLEMENTS:
			hash = computeHash(entDERBlob, hashType)
		default:
			hash = make([]byte, hashSize)
		}
		outp = puts(outp, hash)
	}

	for p := int64(0); p < codeSize; p += PageSize {
		end := p + PageSize
		if end > codeSize {
			end = codeSize
		}
		hash := computeHash(codeData[p:end], hashType)
		outp = puts(outp, hash)
	}

	return cdir
}

func computeHash(data []byte, hashType uint8) []byte {
	if len(data) == 0 {
		if hashType == CS_HASHTYPE_SHA1 {
			return make([]byte, CS_SHA1_LEN)
		}
		return make([]byte, CS_SHA256_LEN)
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

func isEmptyEntitlementsXML(entitlements string) bool {
	if strings.Contains(entitlements, "<dict></dict>") || strings.Contains(entitlements, "<dict/>") {
		return !strings.Contains(entitlements, "<key>")
	}
	return false
}

func buildRequirementsBlobWithCert(bundleID string, signerCN string) []byte {
	reqExpr := buildDesignatedRequirementWithCert(bundleID, signerCN)

	reqCount := uint32(1)
	headerSize := 12 + reqCount*8
	totalSize := headerSize + uint32(len(reqExpr))

	blob := make([]byte, totalSize)
	outp := blob

	outp = put32be(outp, CSMAGIC_REQUIREMENTS)
	outp = put32be(outp, totalSize)
	outp = put32be(outp, reqCount)

	outp = put32be(outp, 3) // kSecDesignatedRequirementType
	_ = put32be(outp, headerSize)

	copy(blob[headerSize:], reqExpr)

	return blob
}

func buildDesignatedRequirementWithCert(bundleID string, signerCN string) []byte {
	const (
		opAnd                = 6
		opIdent              = 2
		opAppleGenericAnchor = 15
		opCertField          = 11
		opCertGeneric        = 14
		matchExists          = 0
		matchEqual           = 1
	)

	var exprData bytes.Buffer

	writeString := func(s string) {
		data := []byte(s)
		strLen := len(data)
		paddedLen := (strLen + 3) &^ 3
		_ = binary.Write(&exprData, binary.BigEndian, uint32(strLen))
		exprData.Write(data)
		for i := strLen; i < paddedLen; i++ {
			exprData.WriteByte(0)
		}
	}

	if signerCN == "" {
		_ = binary.Write(&exprData, binary.BigEndian, uint32(opAnd))
		_ = binary.Write(&exprData, binary.BigEndian, uint32(opIdent))
		writeString(bundleID)
		_ = binary.Write(&exprData, binary.BigEndian, uint32(opAppleGenericAnchor))
	} else {
		_ = binary.Write(&exprData, binary.BigEndian, uint32(opAnd))
		_ = binary.Write(&exprData, binary.BigEndian, uint32(opIdent))
		writeString(bundleID)

		_ = binary.Write(&exprData, binary.BigEndian, uint32(opAnd))
		_ = binary.Write(&exprData, binary.BigEndian, uint32(opAppleGenericAnchor))

		_ = binary.Write(&exprData, binary.BigEndian, uint32(opAnd))

		_ = binary.Write(&exprData, binary.BigEndian, uint32(opCertField))
		_ = binary.Write(&exprData, binary.BigEndian, uint32(0))
		writeString("subject.CN")
		_ = binary.Write(&exprData, binary.BigEndian, uint32(matchEqual))
		writeString(signerCN)

		appleDevOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01}
		_ = binary.Write(&exprData, binary.BigEndian, uint32(opCertGeneric))
		_ = binary.Write(&exprData, binary.BigEndian, uint32(1))
		oidLen := len(appleDevOID)
		paddedOIDLen := (oidLen + 3) &^ 3
		_ = binary.Write(&exprData, binary.BigEndian, uint32(oidLen))
		exprData.Write(appleDevOID)
		for i := oidLen; i < paddedOIDLen; i++ {
			exprData.WriteByte(0)
		}
		_ = binary.Write(&exprData, binary.BigEndian, uint32(matchExists))
	}

	expr := exprData.Bytes()
	totalSize := 8 + 4 + len(expr)
	blob := make([]byte, totalSize)
	binary.BigEndian.PutUint32(blob[0:], CSMAGIC_REQUIREMENT)
	binary.BigEndian.PutUint32(blob[4:], uint32(totalSize))
	binary.BigEndian.PutUint32(blob[8:], 1)
	copy(blob[12:], expr)

	return blob
}

func buildEntitlementsBlob(entitlements []byte) []byte {
	totalSize := 8 + len(entitlements)
	blob := make([]byte, totalSize)

	binary.BigEndian.PutUint32(blob[0:], CSMAGIC_EMBEDDED_ENTITLEMENTS)
	binary.BigEndian.PutUint32(blob[4:], uint32(totalSize))
	copy(blob[8:], entitlements)

	return blob
}

func buildEntitlementsDERBlob(entitlements []byte) []byte {
	entMap, err := ParseEntitlementsXML(entitlements)
	if err != nil {
		return nil
	}

	derData, err := EntitlementsToDER(entMap)
	if err != nil {
		return nil
	}

	totalSize := 8 + len(derData)
	blob := make([]byte, totalSize)

	binary.BigEndian.PutUint32(blob[0:], CSMAGIC_EMBEDDED_DER_ENTITLEMENTS)
	binary.BigEndian.PutUint32(blob[4:], uint32(totalSize))
	copy(blob[8:], derData)

	return blob
}

func buildCMSSignatureWithDualCD(cdirSHA1, cdirSHA256 []byte, identity *SigningIdentity) ([]byte, error) {
	// Allow loading a pre-built CMS blob for debugging
	if cmsPath := os.Getenv("DEBUG_CMS_BLOB"); cmsPath != "" {
		cmsBlob, err := os.ReadFile(cmsPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read DEBUG_CMS_BLOB: %w", err)
		}
		return cmsBlob, nil
	}

	signedData, err := pkcs7.NewSignedData(cdirSHA1)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed data: %w", err)
	}

	signedData.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	rsaKey, ok := identity.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("only RSA keys are supported")
	}

	cdHashesAttrs, err := buildCDHashesAttributesWithDualCD(cdirSHA1, cdirSHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to build CDHashes attributes: %w", err)
	}

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

	signedData.Detach()

	der, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("failed to finish signing: %w", err)
	}

	totalSize := 8 + len(der)
	blob := make([]byte, totalSize)
	binary.BigEndian.PutUint32(blob[0:], CSMAGIC_BLOBWRAPPER)
	binary.BigEndian.PutUint32(blob[4:], uint32(totalSize))
	copy(blob[8:], der)

	return blob, nil
}

func buildCDHashesAttributesWithDualCD(cdirSHA1, cdirSHA256 []byte) ([]pkcs7.Attribute, error) {
	oidCDHashesPlist := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}
	oidCDHashes2 := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}

	sha1CDHash := sha1.Sum(cdirSHA1)
	sha256CDHash := sha256.Sum256(cdirSHA256)

	cdHashesPlist := buildCDHashesPlist(sha1CDHash[:], sha256CDHash[:CS_CDHASH_LEN])

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

func buildCDHashesPlist(sha1Hash, truncatedSHA256 []byte) []byte {
	cdHashes := map[string]interface{}{
		"cdhashes": [][]byte{sha1Hash, truncatedSHA256},
	}

	data, err := plist.Marshal(cdHashes, plist.XMLFormat)
	if err != nil {
		return []byte{}
	}
	return data
}

func buildCDHashes2ASN1(sha256Hash []byte) (asn1.RawValue, error) {
	sha256OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

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

	return asn1.RawValue{
		FullBytes: encoded,
	}, nil
}

func nativeSignFatMachOWithContext(path string, data []byte, identity *SigningIdentity, entitlements []byte, bundleID string, bundleCtx *BundleSigningContext) error {
	fat, err := macho.NewFatFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to parse fat binary: %w", err)
	}
	defer func() { _ = fat.Close() }()

	signedArches := make([][]byte, len(fat.Arches))
	for i, arch := range fat.Arches {
		archData := data[arch.Offset : uint64(arch.Offset)+uint64(arch.Size)]

		archDataForParsing := make([]byte, len(archData))
		copy(archDataForParsing, archData)
		if sigOffset, sigSize, found := findCodeSignatureOffset(archData); found && sigOffset > 0 && sigOffset < uint32(len(archData)) {
			end := sigOffset + sigSize
			if end > uint32(len(archData)) {
				end = uint32(len(archData))
			}
			for j := sigOffset; j < end; j++ {
				archDataForParsing[j] = 0
			}
		}

		m, err := macho.NewFile(bytes.NewReader(archDataForParsing))
		if err != nil {
			return fmt.Errorf("failed to parse arch %d: %w", i, err)
		}

		signedArch, err := nativeSignThinMachOWithContext(archData, m, identity, entitlements, bundleID, bundleCtx)
		_ = m.Close()
		if err != nil {
			return fmt.Errorf("failed to sign arch %d: %w", i, err)
		}

		signedArches[i] = signedArch
	}

	headerSize := 8 + len(fat.Arches)*20

	offsets := make([]uint32, len(fat.Arches))
	currentOffset := uint32(headerSize)

	for i := range signedArches {
		if currentOffset%FatArchAlignment != 0 {
			currentOffset = ((currentOffset / FatArchAlignment) + 1) * FatArchAlignment
		}
		offsets[i] = currentOffset
		currentOffset += uint32(len(signedArches[i]))
	}

	result := make([]byte, currentOffset)

	result[0] = 0xca
	result[1] = 0xfe
	result[2] = 0xba
	result[3] = 0xbe
	binary.BigEndian.PutUint32(result[4:], uint32(len(fat.Arches)))

	for i, arch := range fat.Arches {
		base := 8 + i*20
		binary.BigEndian.PutUint32(result[base:], uint32(arch.CPU))
		binary.BigEndian.PutUint32(result[base+4:], uint32(arch.SubCPU))
		binary.BigEndian.PutUint32(result[base+8:], offsets[i])
		binary.BigEndian.PutUint32(result[base+12:], uint32(len(signedArches[i])))
		binary.BigEndian.PutUint32(result[base+16:], arch.Align)
	}

	for i, archData := range signedArches {
		copy(result[offsets[i]:], archData)
	}

	return os.WriteFile(path, result, 0755)
}

// NativeSignAppBundle signs all Mach-O binaries in an app bundle
func NativeSignAppBundle(appPath string, identity *SigningIdentity, entitlements []byte, bundleID string) error {
	// Validate app path
	info, err := os.Stat(appPath)
	if err != nil {
		return fmt.Errorf("failed to stat app path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("app path is not a directory: %s", appPath)
	}

	nestedBundles, err := findNestedBundles(appPath)
	if err != nil {
		return fmt.Errorf("failed to find nested bundles: %w", err)
	}

	sort.Slice(nestedBundles, func(i, j int) bool {
		// Use filepath.ToSlash to normalize paths for consistent depth counting
		// This ensures cross-platform compatibility (Windows uses backslashes, others use forward slashes)
		depthI := strings.Count(filepath.ToSlash(nestedBundles[i]), "/")
		depthJ := strings.Count(filepath.ToSlash(nestedBundles[j]), "/")
		return depthI > depthJ
	})

	for _, bundle := range nestedBundles {
		if err := signNestedBundle(bundle, identity); err != nil {
			return fmt.Errorf("failed to sign nested bundle %s: %w", bundle, err)
		}
	}

	if err := WriteCodeResources(appPath); err != nil {
		return fmt.Errorf("failed to generate CodeResources: %w", err)
	}

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

func findNestedBundles(appPath string) ([]string, error) {
	var bundles []string

	err := filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext == ".framework" || ext == ".appex" || ext == ".xctest" {
			bundles = append(bundles, path)
		}

		return nil
	})

	return bundles, err
}

func signNestedBundle(bundlePath string, identity *SigningIdentity) error {
	bundleName := filepath.Base(bundlePath)
	ext := filepath.Ext(bundleName)
	binaryName := strings.TrimSuffix(bundleName, ext)

	binaryPath := filepath.Join(bundlePath, binaryName)
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		return nil
	}

	codeSignDir := filepath.Join(bundlePath, "_CodeSignature")
	if err := os.RemoveAll(codeSignDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove old _CodeSignature: %w", err)
	}

	if err := WriteCodeResources(bundlePath); err != nil {
		return fmt.Errorf("failed to generate CodeResources: %w", err)
	}

	bundleCtx := &BundleSigningContext{
		InfoPlistPath:     filepath.Join(bundlePath, "Info.plist"),
		CodeResourcesPath: filepath.Join(bundlePath, "_CodeSignature", "CodeResources"),
		TeamID:            identity.TeamID,
	}

	bundleID := binaryName
	if plistPath := filepath.Join(bundlePath, "Info.plist"); fileExists(plistPath) {
		if bid, err := GetBundleIDFromPlist(plistPath); err == nil && bid != "" {
			bundleID = bid
		}
	}

	emptyEntitlements := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict/>
</plist>
`)

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
