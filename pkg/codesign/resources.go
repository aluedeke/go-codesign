package codesign

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"howett.net/plist"
)

// CodeResourcesRules defines the rules for hashing resources
type CodeResourcesRules struct {
	// Files that should be omitted (not hashed)
	Omit []string
	// Files that are optional (hash if present)
	Optional []string
	// Files that must be nested (e.g., frameworks)
	Nested bool
	// Weight for rule priority
	Weight int
}

// GenerateCodeResources generates the _CodeSignature/CodeResources plist
// This hashes ALL files recursively, including those inside nested bundles
// (.framework, .xctest, etc.)
func GenerateCodeResources(appPath string) ([]byte, error) {
	// CodeResources has two sections: files and files2
	// files uses SHA1 (legacy), files2 uses SHA256
	// We'll generate the modern format with both for compatibility

	files := make(map[string]interface{})
	files2 := make(map[string]interface{})
	rules := defaultRules()
	rules2 := defaultRules2()

	// Get the main executable name to exclude it
	execName, _ := GetAppExecutableName(appPath)

	// Walk the app bundle and hash ALL files recursively
	// Nested bundle contents are included in the hash
	err := filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(appPath, path)
		if err != nil {
			return err
		}

		// Skip the main app's _CodeSignature/CodeResources only
		if relPath == filepath.Join("_CodeSignature", "CodeResources") {
			return nil
		}

		// Skip the main executable (it's signed separately)
		if relPath == execName {
			return nil
		}

		// Apply rules to determine if/how to hash this file
		if shouldOmit(relPath) {
			return nil
		}

		// Calculate hashes
		hash, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("failed to hash %s: %w", relPath, err)
		}

		// Check if this is an optional file
		optional := isOptional(relPath)

		// Add to files (using just the hash data for simple files)
		if optional {
			files[relPath] = map[string]interface{}{
				"hash":     hash,
				"optional": true,
			}
		} else {
			files[relPath] = hash
		}

		// Add to files2 with both hash (SHA1) and hash2 (SHA256)
		// Some files like Info.plist and PkgInfo are in 'files' but not 'files2'
		if !shouldOmitFromFiles2(relPath) {
			hash2, err := hashFileSHA256(path)
			if err != nil {
				return fmt.Errorf("failed to hash2 %s: %w", relPath, err)
			}

			// Include both hash (SHA1) and hash2 (SHA256) in files2
			files2Entry := map[string]interface{}{
				"hash":  hash,
				"hash2": hash2,
			}
			if optional {
				files2Entry["optional"] = true
			}
			files2[relPath] = files2Entry
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Build the CodeResources structure
	codeResources := map[string]interface{}{
		"files":  files,
		"files2": files2,
		"rules":  rules,
		"rules2": rules2,
	}

	// Marshal to plist
	data, err := plist.MarshalIndent(codeResources, plist.XMLFormat, "\t")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CodeResources: %w", err)
	}

	return data, nil
}

// WriteCodeResources generates and writes the CodeResources file
func WriteCodeResources(appPath string) error {
	data, err := GenerateCodeResources(appPath)
	if err != nil {
		return err
	}

	// Ensure _CodeSignature directory exists
	codeSignDir := filepath.Join(appPath, "_CodeSignature")
	if err := os.MkdirAll(codeSignDir, 0755); err != nil {
		return fmt.Errorf("failed to create _CodeSignature directory: %w", err)
	}

	// Write CodeResources
	codeResPath := filepath.Join(codeSignDir, "CodeResources")
	if err := os.WriteFile(codeResPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write CodeResources: %w", err)
	}

	return nil
}

func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Use SHA1 for legacy 'files' section
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func hashFileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// HashData hashes arbitrary data with SHA256
func HashData(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// Base64Hash returns base64-encoded hash for plist
func Base64Hash(hash []byte) string {
	return base64.StdEncoding.EncodeToString(hash)
}

// findNestedBundlePaths returns relative paths to all nested bundles in the app
func findNestedBundlePaths(appPath string) []string {
	var bundles []string

	_ = filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(appPath, path)
		if err != nil || relPath == "." {
			return nil
		}

		if isNestedBundle(relPath) {
			bundles = append(bundles, relPath)
			return filepath.SkipDir // Don't recurse into nested bundles
		}

		return nil
	})

	return bundles
}

// isNestedBundle returns true if the path is a nested bundle (.framework, .xctest, .appex, .app)
func isNestedBundle(relPath string) bool {
	ext := filepath.Ext(relPath)
	switch ext {
	case ".framework", ".xctest", ".appex", ".app":
		return true
	}
	return false
}

func shouldOmit(path string) bool {
	// Files that should be omitted from signing

	// Skip .DS_Store files
	if strings.HasSuffix(path, ".DS_Store") {
		return true
	}

	// Skip .git files
	if strings.Contains(path, ".git") {
		return true
	}

	// Skip AppleDouble files (._*)
	base := filepath.Base(path)
	if strings.HasPrefix(base, "._") {
		return true
	}

	// Skip locversion.plist files
	if strings.HasSuffix(path, ".lproj/locversion.plist") {
		return true
	}

	// Note: We do NOT skip nested bundle _CodeSignature directories here
	// All _CodeSignature/CodeResources files from nested bundles are included
	// The main app's _CodeSignature/CodeResources is skipped in GenerateCodeResources

	return false
}

func isOptional(path string) bool {
	// Files that are marked as optional (localized bundles)
	if strings.Contains(path, ".lproj/") {
		return true
	}
	return false
}

// shouldOmitFromFiles2 returns true for files that should be in 'files' but not in 'files2'
// This matches Apple's rules2 which has omit:true for Info.plist and PkgInfo
func shouldOmitFromFiles2(path string) bool {
	if path == "Info.plist" || path == "PkgInfo" {
		return true
	}
	return false
}

func defaultRules() map[string]interface{} {
	// Use float64 for weights to produce <real> type in plist output
	return map[string]interface{}{
		"^.*": true,
		"^.*\\.lproj/": map[string]interface{}{
			"optional": true,
			"weight":   float64(1000),
		},
		"^.*\\.lproj/locversion.plist$": map[string]interface{}{
			"omit":   true,
			"weight": float64(1100),
		},
		"^Base\\.lproj/": map[string]interface{}{
			"weight": float64(1010),
		},
		"^version.plist$": true,
	}
}

func defaultRules2() map[string]interface{} {
	// Use float64 for weights to produce <real> type in plist output
	return map[string]interface{}{
		"^.*": true,
		".*\\.dSYM($|/)": map[string]interface{}{
			"weight": float64(11),
		},
		// DS_Store omit rule
		"^(.*/)?\\.DS_Store$": map[string]interface{}{
			"omit":   true,
			"weight": float64(2000),
		},
		"^.*\\.lproj/": map[string]interface{}{
			"optional": true,
			"weight":   float64(1000),
		},
		"^.*\\.lproj/locversion.plist$": map[string]interface{}{
			"omit":   true,
			"weight": float64(1100),
		},
		"^Base\\.lproj/": map[string]interface{}{
			"weight": float64(1010),
		},
		"^Info\\.plist$": map[string]interface{}{
			"omit":   true,
			"weight": float64(20),
		},
		"^PkgInfo$": map[string]interface{}{
			"omit":   true,
			"weight": float64(20),
		},
		// provisionprofile rule (note: different from mobileprovision)
		"^embedded\\.provisionprofile$": map[string]interface{}{
			"weight": float64(20),
		},
		"^version\\.plist$": map[string]interface{}{
			"weight": float64(20),
		},
	}
}
