package codesign

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractIPA extracts an IPA file to a temporary directory
// Returns the path to the temp directory
func ExtractIPA(ipaPath string) (string, error) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "ipa-resign-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Open the IPA (ZIP file)
	r, err := zip.OpenReader(ipaPath)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to open IPA: %w", err)
	}
	defer r.Close()

	// Extract all files
	for _, f := range r.File {
		err := extractZipFile(f, tempDir)
		if err != nil {
			os.RemoveAll(tempDir)
			return "", fmt.Errorf("failed to extract %s: %w", f.Name, err)
		}
	}

	return tempDir, nil
}

func extractZipFile(f *zip.File, destDir string) error {
	// Sanitize the file path to prevent zip slip
	destPath := filepath.Join(destDir, f.Name)
	if !strings.HasPrefix(destPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
		return fmt.Errorf("invalid file path: %s", f.Name)
	}

	if f.FileInfo().IsDir() {
		return os.MkdirAll(destPath, f.Mode())
	}

	// Create parent directories
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	// Create the file
	destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer destFile.Close()

	// Copy contents
	srcFile, err := f.Open()
	if err != nil {
		return err
	}
	defer srcFile.Close()

	_, err = io.Copy(destFile, srcFile)
	return err
}

// FindAppBundle finds the .app bundle inside an extracted IPA
// Returns the full path to the .app directory
func FindAppBundle(extractedDir string) (string, error) {
	payloadDir := filepath.Join(extractedDir, "Payload")

	entries, err := os.ReadDir(payloadDir)
	if err != nil {
		return "", fmt.Errorf("failed to read Payload directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasSuffix(entry.Name(), ".app") {
			return filepath.Join(payloadDir, entry.Name()), nil
		}
	}

	return "", fmt.Errorf("no .app bundle found in Payload directory")
}

// RepackageIPA creates an IPA file from an extracted directory
func RepackageIPA(extractedDir, outputPath string) error {
	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Create ZIP writer
	w := zip.NewWriter(outFile)
	defer w.Close()

	// Walk the extracted directory and add files
	err = filepath.Walk(extractedDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the root directory itself
		if path == extractedDir {
			return nil
		}

		// Get relative path for ZIP entry
		relPath, err := filepath.Rel(extractedDir, path)
		if err != nil {
			return err
		}

		// Use forward slashes for ZIP paths
		zipPath := strings.ReplaceAll(relPath, string(os.PathSeparator), "/")

		if info.IsDir() {
			// Add directory entry
			_, err := w.Create(zipPath + "/")
			return err
		}

		// Create file entry with proper compression
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = zipPath
		header.Method = zip.Deflate

		writer, err := w.CreateHeader(header)
		if err != nil {
			return err
		}

		// Copy file contents
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	})

	return err
}

// GetAppBundleID reads the bundle ID from an app's Info.plist
func GetAppBundleID(appPath string) (string, error) {
	infoPlistPath := filepath.Join(appPath, "Info.plist")
	data, err := os.ReadFile(infoPlistPath)
	if err != nil {
		return "", fmt.Errorf("failed to read Info.plist: %w", err)
	}

	info, err := parseInfoPlist(data)
	if err != nil {
		return "", err
	}

	bundleID, ok := info["CFBundleIdentifier"].(string)
	if !ok {
		return "", fmt.Errorf("CFBundleIdentifier not found in Info.plist")
	}

	return bundleID, nil
}

// GetAppExecutableName reads the executable name from an app's Info.plist
func GetAppExecutableName(appPath string) (string, error) {
	infoPlistPath := filepath.Join(appPath, "Info.plist")
	data, err := os.ReadFile(infoPlistPath)
	if err != nil {
		return "", fmt.Errorf("failed to read Info.plist: %w", err)
	}

	info, err := parseInfoPlist(data)
	if err != nil {
		return "", err
	}

	execName, ok := info["CFBundleExecutable"].(string)
	if !ok {
		return "", fmt.Errorf("CFBundleExecutable not found in Info.plist")
	}

	return execName, nil
}

// CopyAppBundle copies a .app bundle directory from src to dst
func CopyAppBundle(src, dst string) error {
	// Remove destination if it exists
	if err := os.RemoveAll(dst); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing destination: %w", err)
	}

	// Create destination directory
	if err := os.MkdirAll(dst, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Walk source directory and copy all files
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		// Skip root directory
		if relPath == "." {
			return nil
		}

		// Construct destination path
		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			// Create directory
			return os.MkdirAll(dstPath, info.Mode())
		}

		// Copy file
		return copyFile(path, dstPath, info.Mode())
	})
}

// copyFile copies a single file from src to dst with the given mode using streaming I/O
func copyFile(src, dst string, mode os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}
