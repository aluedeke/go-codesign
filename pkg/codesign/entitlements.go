package codesign

import (
	"encoding/asn1"
	"fmt"
	"sort"
	"strings"

	"howett.net/plist"
)

// ExtractEntitlements extracts entitlements from a provisioning profile as XML plist bytes
func ExtractEntitlements(profile *ProvisioningProfile) ([]byte, error) {
	if profile.Entitlements == nil {
		return nil, fmt.Errorf("provisioning profile has no entitlements")
	}

	data, err := plist.MarshalIndent(profile.Entitlements, plist.XMLFormat, "\t")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entitlements: %w", err)
	}

	return data, nil
}

// UpdateEntitlementsForBundleID updates the entitlements with a new bundle ID
// It updates application-identifier and keychain-access-groups
func UpdateEntitlementsForBundleID(entitlements map[string]interface{}, teamID, newBundleID string) map[string]interface{} {
	updated := make(map[string]interface{})
	for k, v := range entitlements {
		updated[k] = v
	}

	// Update application-identifier
	// If newBundleID already starts with teamID, don't add it again
	var newAppID string
	if strings.HasPrefix(newBundleID, teamID+".") {
		newAppID = newBundleID
	} else {
		newAppID = fmt.Sprintf("%s.%s", teamID, newBundleID)
	}
	updated["application-identifier"] = newAppID

	// Update keychain-access-groups if present
	if groups, ok := updated["keychain-access-groups"].([]interface{}); ok {
		newGroups := make([]interface{}, 0, len(groups))
		for _, group := range groups {
			if groupStr, ok := group.(string); ok {
				// Replace the bundle ID portion while keeping the team ID prefix
				if strings.Contains(groupStr, ".") {
					parts := strings.SplitN(groupStr, ".", 2)
					if len(parts) == 2 {
						// Keep team ID, use new bundle ID (without team prefix if present)
						bundleIDWithoutTeam := newBundleID
						if strings.HasPrefix(newBundleID, teamID+".") {
							bundleIDWithoutTeam = strings.TrimPrefix(newBundleID, teamID+".")
						}
						newGroups = append(newGroups, fmt.Sprintf("%s.%s", teamID, bundleIDWithoutTeam))
					} else {
						newGroups = append(newGroups, groupStr)
					}
				} else {
					newGroups = append(newGroups, groupStr)
				}
			}
		}
		updated["keychain-access-groups"] = newGroups
	}

	return updated
}

// MergeEntitlements merges override entitlements into base entitlements
// Override values take precedence
func MergeEntitlements(base, override map[string]interface{}) map[string]interface{} {
	merged := make(map[string]interface{})

	// Copy base entitlements
	for k, v := range base {
		merged[k] = v
	}

	// Apply overrides
	for k, v := range override {
		merged[k] = v
	}

	return merged
}

// EntitlementsToXML converts entitlements map to XML plist bytes
func EntitlementsToXML(entitlements map[string]interface{}) ([]byte, error) {
	data, err := plist.MarshalIndent(entitlements, plist.XMLFormat, "\t")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entitlements to XML: %w", err)
	}
	return data, nil
}

// ParseEntitlementsXML parses XML plist entitlements into a map
func ParseEntitlementsXML(data []byte) (map[string]interface{}, error) {
	var entitlements map[string]interface{}
	_, err := plist.Unmarshal(data, &entitlements)
	if err != nil {
		return nil, fmt.Errorf("failed to parse entitlements XML: %w", err)
	}
	return entitlements, nil
}

// EntitlementsToDER converts entitlements map to DER-encoded ASN.1 format
// This is required for iOS code signing alongside the XML plist format
// The format follows Apple's specific plist-to-DER encoding:
// - Top-level: APPLICATION 16 { INTEGER 1, WrappedValue }
// - Dictionary: [16] SEQUENCE { SEQUENCE { UTF8String key, WrappedValue }... }
// - Array: SEQUENCE { WrappedValue... }
// - Boolean: BOOLEAN
// - Integer: INTEGER
// - String: UTF8String
func EntitlementsToDER(entitlements map[string]interface{}) ([]byte, error) {
	// Encode the dictionary content
	dictContent, err := encodeDERDict(entitlements)
	if err != nil {
		return nil, err
	}

	// Wrap in the top-level APPLICATION 16 structure
	// APPLICATION 16 { INTEGER 1, dictContent }
	versionBytes, err := asn1.Marshal(1)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal version: %w", err)
	}

	// Build the content: version + dictionary
	content := append(versionBytes, dictContent...)

	// Wrap in APPLICATION 16 tag (0x70 = Application class, constructed, tag 16)
	return wrapWithTag(0x70, content), nil
}

// encodeDERDict encodes a dictionary to Apple's DER format
// Format: [16] { SEQUENCE { UTF8String key, WrappedValue }... }
// Note: The key-value pair SEQUENCEs go directly inside the context tag,
// without an outer SEQUENCE wrapper.
func encodeDERDict(dict map[string]interface{}) ([]byte, error) {
	// Get sorted keys for deterministic output
	keys := make([]string, 0, len(dict))
	for k := range dict {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Encode each key-value pair as a SEQUENCE
	var pairsContent []byte
	for _, key := range keys {
		value := dict[key]

		// Encode key as UTF8String (Apple uses UTF8String, not PrintableString)
		keyBytes := encodeUTF8String(key)

		// Encode value
		valueBytes, err := encodeDERValue(value)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal value for key %s: %w", key, err)
		}

		// Wrap key-value in a SEQUENCE
		pairContent := append(keyBytes, valueBytes...)
		pairSeq := wrapWithTag(0x30, pairContent) // SEQUENCE tag
		pairsContent = append(pairsContent, pairSeq...)
	}

	// Wrap directly in context-specific tag [16] (0xB0 = context class, constructed, tag 16)
	// Apple's format does NOT have an outer SEQUENCE wrapping all pairs
	return wrapWithTag(0xB0, pairsContent), nil
}

// encodeUTF8String encodes a string as ASN.1 UTF8String (tag 0x0C)
func encodeUTF8String(s string) []byte {
	data := []byte(s)
	return wrapWithTag(0x0C, data)
}

// encodeDERValue encodes a plist value to Apple's DER format
func encodeDERValue(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case bool:
		return asn1.Marshal(val)
	case string:
		// Apple uses UTF8String for string values
		return encodeUTF8String(val), nil
	case int:
		return asn1.Marshal(val)
	case int64:
		return asn1.Marshal(val)
	case uint64:
		return asn1.Marshal(int64(val))
	case []interface{}:
		// Encode array as SEQUENCE
		var content []byte
		for _, item := range val {
			itemBytes, err := encodeDERValue(item)
			if err != nil {
				return nil, err
			}
			content = append(content, itemBytes...)
		}
		return wrapWithTag(0x30, content), nil
	case map[string]interface{}:
		// Nested dictionary
		return encodeDERDict(val)
	default:
		return nil, fmt.Errorf("unsupported plist type: %T", v)
	}
}

// wrapWithTag wraps content with a DER tag and length
func wrapWithTag(tag byte, content []byte) []byte {
	length := len(content)
	var result []byte

	if length < 128 {
		// Short form: 1 byte length
		result = make([]byte, 2+length)
		result[0] = tag
		result[1] = byte(length)
		copy(result[2:], content)
	} else if length < 256 {
		// Long form: 0x81 + 1 byte length
		result = make([]byte, 3+length)
		result[0] = tag
		result[1] = 0x81
		result[2] = byte(length)
		copy(result[3:], content)
	} else if length < 65536 {
		// Long form: 0x82 + 2 byte length
		result = make([]byte, 4+length)
		result[0] = tag
		result[1] = 0x82
		result[2] = byte(length >> 8)
		result[3] = byte(length)
		copy(result[4:], content)
	} else {
		// Long form: 0x83 + 3 byte length
		result = make([]byte, 5+length)
		result[0] = tag
		result[1] = 0x83
		result[2] = byte(length >> 16)
		result[3] = byte(length >> 8)
		result[4] = byte(length)
		copy(result[5:], content)
	}

	return result
}
