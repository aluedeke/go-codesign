package codesign

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

const (
	// WDA download URL from appium releases
	wdaDownloadURL = "https://github.com/appium/WebDriverAgent/releases/download/v11.0.1/WebDriverAgentRunner-Runner.zip"
	wdaAppName     = "WebDriverAgentRunner-Runner.app"
	// SHA256 checksum of the expected WDA zip file
	wdaExpectedSHA256 = "76549921269cc7fac842569b90a90b2c28abeca0b9bfdc2be9eccbae8336a90d"
)

var (
	testDataOnce sync.Once
	testDataErr  error
	testDataPath string
)

// getTestDataPath returns the path to the test data directory.
// It downloads and extracts the WDA app if not already present or if checksum doesn't match.
func getTestDataPath(t *testing.T) string {
	testDataOnce.Do(func() {
		testDataPath = filepath.Join("testdata", wdaAppName)
		versionFile := filepath.Join("testdata", ".wda_version")

		// Check if already exists with correct version
		if _, err := os.Stat(testDataPath); err == nil {
			if storedChecksum, err := os.ReadFile(versionFile); err == nil {
				if string(storedChecksum) == wdaExpectedSHA256 {
					return // Correct version already downloaded
				}
				t.Log("WDA version mismatch, re-downloading...")
				os.RemoveAll(testDataPath)
			}
		}

		// Create testdata directory
		if err := os.MkdirAll("testdata", 0755); err != nil {
			testDataErr = fmt.Errorf("failed to create testdata directory: %w", err)
			return
		}

		t.Logf("Downloading WDA test data from %s", wdaDownloadURL)

		// Download the zip file
		zipPath := filepath.Join("testdata", "wda.zip")
		if err := downloadFile(zipPath, wdaDownloadURL); err != nil {
			testDataErr = fmt.Errorf("failed to download WDA: %w", err)
			return
		}
		defer os.Remove(zipPath)

		// Verify checksum
		actualChecksum, err := fileChecksum(zipPath)
		if err != nil {
			testDataErr = fmt.Errorf("failed to compute checksum: %w", err)
			return
		}
		if actualChecksum != wdaExpectedSHA256 {
			testDataErr = fmt.Errorf("checksum mismatch: expected %s, got %s", wdaExpectedSHA256, actualChecksum)
			return
		}

		// Extract the zip file
		if err := extractZip(zipPath, "testdata"); err != nil {
			testDataErr = fmt.Errorf("failed to extract WDA: %w", err)
			return
		}

		// Write version file to track which version is installed
		if err := os.WriteFile(versionFile, []byte(wdaExpectedSHA256), 0644); err != nil {
			t.Logf("Warning: failed to write version file: %v", err)
		}

		t.Log("WDA test data downloaded and extracted successfully")
	})

	if testDataErr != nil {
		t.Skipf("Test data not available: %v", testDataErr)
	}

	return testDataPath
}

// getTestAppPath returns the path to the WDA test app, downloading if necessary
func getTestAppPath(t *testing.T) string {
	return getTestDataPath(t)
}

// skipIfNoTestData skips the test if test data is not available and cannot be downloaded
func skipIfNoTestData(t *testing.T) string {
	appPath := getTestDataPath(t)
	if _, err := os.Stat(appPath); os.IsNotExist(err) {
		t.Skip("Test app not available")
	}
	return appPath
}

func fileChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func downloadFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func extractZip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)

		// Check for ZipSlip vulnerability
		if !filepath.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}

	return nil
}
