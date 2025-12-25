package codesign

import (
	"crypto/x509"
	"fmt"
	"time"

	"go.mozilla.org/pkcs7"
	"howett.net/plist"
)

// ProvisioningProfile represents a parsed .mobileprovision file
type ProvisioningProfile struct {
	Name                        string                 `plist:"Name"`
	TeamName                    string                 `plist:"TeamName"`
	TeamIdentifier              []string               `plist:"TeamIdentifier"`
	AppIDName                   string                 `plist:"AppIDName"`
	ApplicationIdentifierPrefix []string               `plist:"ApplicationIdentifierPrefix"`
	Entitlements                map[string]interface{} `plist:"Entitlements"`
	DeveloperCertificates       [][]byte               `plist:"DeveloperCertificates"`
	ProvisionedDevices          []string               `plist:"ProvisionedDevices"`
	ProvisionsAllDevices        bool                   `plist:"ProvisionsAllDevices"`
	CreationDate                time.Time              `plist:"CreationDate"`
	ExpirationDate              time.Time              `plist:"ExpirationDate"`
	UUID                        string                 `plist:"UUID"`
	Platform                    []string               `plist:"Platform"`
}

// ParseProvisioningProfile parses a .mobileprovision file
// The file is a CMS (PKCS#7) signed container with a plist payload
func ParseProvisioningProfile(data []byte) (*ProvisioningProfile, error) {
	// Parse the CMS/PKCS#7 container
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 container: %w", err)
	}

	// The content is a plist
	var profile ProvisioningProfile
	_, err = plist.Unmarshal(p7.Content, &profile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse provisioning profile plist: %w", err)
	}

	return &profile, nil
}

// GetTeamID returns the team identifier from the profile
func (p *ProvisioningProfile) GetTeamID() string {
	if len(p.TeamIdentifier) > 0 {
		return p.TeamIdentifier[0]
	}
	if len(p.ApplicationIdentifierPrefix) > 0 {
		return p.ApplicationIdentifierPrefix[0]
	}
	return ""
}

// GetApplicationIdentifier returns the application identifier from entitlements
func (p *ProvisioningProfile) GetApplicationIdentifier() string {
	if appID, ok := p.Entitlements["application-identifier"].(string); ok {
		return appID
	}
	return ""
}

// IsExpired checks if the provisioning profile has expired
func (p *ProvisioningProfile) IsExpired() bool {
	return time.Now().After(p.ExpirationDate)
}

// IsDeviceAllowed checks if a specific device UDID is allowed by this profile
func (p *ProvisioningProfile) IsDeviceAllowed(udid string) bool {
	// Enterprise/distribution profiles provision all devices
	if p.ProvisionsAllDevices {
		return true
	}

	for _, device := range p.ProvisionedDevices {
		if device == udid {
			return true
		}
	}
	return false
}

// GetCertificates parses and returns the developer certificates from the profile
func (p *ProvisioningProfile) GetCertificates() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for i, certData := range p.DeveloperCertificates {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %d: %w", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// MatchesCertificate checks if the given certificate matches any certificate in the profile
func (p *ProvisioningProfile) MatchesCertificate(cert *x509.Certificate) bool {
	for _, certData := range p.DeveloperCertificates {
		profileCert, err := x509.ParseCertificate(certData)
		if err != nil {
			continue
		}
		// Compare by public key
		if cert.Equal(profileCert) {
			return true
		}
	}
	return false
}
