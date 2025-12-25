package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aluedeke/go-codesign/pkg/codesign"
	"github.com/docopt/docopt-go"
)

const version = "1.0.0"

const usage = `go-codesign - iOS App Code Signing Tool

A command-line tool for resigning iOS IPA files and .app bundles with new certificates and provisioning profiles.

Usage:
  go-codesign resign --app=<path> [--p12=<path>] [--profile=<path>] [--password=<password>] [--output=<path>] [--bundleid=<id>] [--inplace]
  go-codesign info --app=<path> [--signature] [--recursive]
  go-codesign info --profile=<path>
  go-codesign diff --app1=<path> --app2=<path> [--recursive]
  go-codesign -h | --help
  go-codesign --version

Commands:
  resign    Resign an IPA file or .app bundle with a new signing identity
  info      Display information about an IPA file or .app bundle or provisioning profile
  diff      Compare code signatures between two apps

Options:
  --app=<path>          Path to the input .ipa file or .app bundle directory
  --app1=<path>         Path to first app for comparison (diff command)
  --app2=<path>         Path to second app for comparison (diff command)
  --p12=<path>          Path to the P12 certificate file (or CODESIGN_P12 env var)
  --profile=<path>      Path to the provisioning profile (or CODESIGN_PROFILE env var)
  --password=<password> Password for the P12 certificate (or CODESIGN_PASSWORD env var)
  --output=<path>       Path for the output (resigned IPA or .app, defaults to input-resigned.ext)
  --bundleid=<id>       New bundle ID to apply (optional)
  --inplace             Sign the app bundle in-place (modifies original, only works with .app)
  --signature           Show detailed code signature information (info command)
  --recursive           Include nested bundles like Frameworks/ and PlugIns/
  -h --help             Show this help message
  --version             Show version

Environment Variables:
  CODESIGN_P12          Path to P12 certificate file (overridden by --p12)
  CODESIGN_PROFILE      Path to provisioning profile (overridden by --profile)
  CODESIGN_PASSWORD     P12 certificate password (overridden by --password)

Examples:
  # Resign an IPA with a new certificate (creates new file)
  go-codesign resign --app=MyApp.ipa --p12=cert.p12 --profile=dev.mobileprovision --password=secret

  # Resign using environment variables (useful for CI/CD)
  export CODESIGN_P12=/path/to/cert.p12
  export CODESIGN_PROFILE=/path/to/profile.mobileprovision
  export CODESIGN_PASSWORD=secret
  go-codesign resign --app=MyApp.ipa

  # Resign a .app bundle with a new certificate (creates new file)
  go-codesign resign --app=MyApp.app --p12=cert.p12 --profile=dev.mobileprovision --password=secret

  # Resign a .app bundle in-place (modifies original)
  go-codesign resign --app=MyApp.app --p12=cert.p12 --profile=dev.mobileprovision --inplace

  # Resign and change bundle ID
  go-codesign resign --app=MyApp.ipa --p12=cert.p12 --profile=dev.mobileprovision --bundleid=com.example.newapp

  # View IPA information
  go-codesign info --app=MyApp.ipa

  # View .app bundle information
  go-codesign info --app=MyApp.app

  # View provisioning profile information
  go-codesign info --profile=dev.mobileprovision

  # View detailed code signature information
  go-codesign info --app=MyApp.app --signature

  # View signature info for app and all nested bundles
  go-codesign info --app=MyApp.app --signature --recursive

  # Compare signatures between two apps
  go-codesign diff --app1=App1.app --app2=App2.app

  # Compare including nested bundles
  go-codesign diff --app1=App1.app --app2=App2.app --recursive
`

func main() {
	opts, err := docopt.ParseArgs(usage, os.Args[1:], version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments: %v\n", err)
		os.Exit(1)
	}

	if resign, _ := opts.Bool("resign"); resign {
		if err := runResign(opts); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else if info, _ := opts.Bool("info"); info {
		if err := runInfo(opts); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else if diff, _ := opts.Bool("diff"); diff {
		if err := runDiff(opts); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}

func runResign(opts docopt.Opts) error {
	inputPath, _ := opts.String("--app")
	p12Path, _ := opts.String("--p12")
	profilePath, _ := opts.String("--profile")
	password, _ := opts.String("--password")
	outputPath, _ := opts.String("--output")
	bundleID, _ := opts.String("--bundleid")
	inplace, _ := opts.Bool("--inplace")

	// Get values from environment if not provided via flags
	if p12Path == "" {
		p12Path = os.Getenv("CODESIGN_P12")
	}
	if profilePath == "" {
		profilePath = os.Getenv("CODESIGN_PROFILE")
	}
	if password == "" {
		password = os.Getenv("CODESIGN_PASSWORD")
	}

	// Validate required parameters
	if p12Path == "" {
		return fmt.Errorf("--p12 is required (or set CODESIGN_P12 environment variable)")
	}
	if profilePath == "" {
		return fmt.Errorf("--profile is required (or set CODESIGN_PROFILE environment variable)")
	}

	// Detect if input is .ipa or .app
	isIPA := strings.HasSuffix(strings.ToLower(inputPath), ".ipa")

	// Validate inplace flag
	if inplace {
		if isIPA {
			return fmt.Errorf("--inplace can only be used with .app bundles, not .ipa files")
		}
		if outputPath != "" {
			return fmt.Errorf("cannot specify both --inplace and --output")
		}
	}

	// Set default output path (not used if inplace)
	if outputPath == "" && !inplace {
		ext := filepath.Ext(inputPath)
		base := strings.TrimSuffix(inputPath, ext)
		outputPath = base + "-resigned" + ext
	}

	// Read input files
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		return fmt.Errorf("failed to read P12 file: %w", err)
	}

	profileData, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("failed to read provisioning profile: %w", err)
	}

	if isIPA {
		fmt.Printf("Resigning IPA: %s\n", inputPath)
	} else {
		fmt.Printf("Resigning .app bundle: %s\n", inputPath)
	}
	fmt.Printf("Using certificate: %s\n", p12Path)
	fmt.Printf("Using profile: %s\n", profilePath)
	if inplace {
		fmt.Printf("Mode: In-place (modifies original)\n")
	} else {
		fmt.Printf("Output: %s\n", outputPath)
	}
	if bundleID != "" {
		fmt.Printf("New Bundle ID: %s\n", bundleID)
	}
	fmt.Println()

	var appPath string
	var tempDir string
	var shouldCleanup bool

	if isIPA {
		// Extract IPA to temp directory
		tempDir, err = codesign.ExtractIPA(inputPath)
		if err != nil {
			return fmt.Errorf("failed to extract IPA: %w", err)
		}
		shouldCleanup = true
		defer func() {
			if shouldCleanup {
				os.RemoveAll(tempDir)
			}
		}()

		// Find the .app bundle
		appPath, err = codesign.FindAppBundle(tempDir)
		if err != nil {
			return fmt.Errorf("failed to find app bundle: %w", err)
		}
	} else if inplace {
		// Sign in-place, work directly with input
		appPath = inputPath
	} else {
		// Input is a .app bundle - copy to temp location to avoid modifying the original
		tempDir, err = os.MkdirTemp("", "app-resign-*")
		if err != nil {
			return fmt.Errorf("failed to create temp directory: %w", err)
		}
		shouldCleanup = true
		defer func() {
			if shouldCleanup {
				os.RemoveAll(tempDir)
			}
		}()

		appPath = filepath.Join(tempDir, filepath.Base(inputPath))
		if err := codesign.CopyAppBundle(inputPath, appPath); err != nil {
			return fmt.Errorf("failed to copy app bundle to temp location: %w", err)
		}
	}

	// Perform the resign on the .app bundle
	resignOpts := codesign.ResignOptions{
		AppPath:             appPath,
		P12Data:             p12Data,
		P12Password:         password,
		ProvisioningProfile: profileData,
		NewBundleID:         bundleID,
	}

	if err := codesign.Resign(resignOpts); err != nil {
		return err
	}

	// Handle output based on input type and mode
	if isIPA {
		// Repackage IPA
		if err := codesign.RepackageIPA(tempDir, outputPath); err != nil {
			return fmt.Errorf("failed to repackage IPA: %w", err)
		}
		fmt.Printf("Successfully resigned IPA: %s\n", outputPath)
	} else if inplace {
		// Already signed in-place
		fmt.Printf("Successfully resigned .app bundle in-place: %s\n", inputPath)
	} else {
		// Copy signed .app to output location
		if err := codesign.CopyAppBundle(appPath, outputPath); err != nil {
			return fmt.Errorf("failed to copy signed app bundle: %w", err)
		}
		fmt.Printf("Successfully resigned .app bundle: %s\n", outputPath)
	}

	return nil
}

func runInfo(opts docopt.Opts) error {
	inputPath, _ := opts.String("--app")
	profilePath, _ := opts.String("--profile")
	showSignature, _ := opts.Bool("--signature")
	recursive, _ := opts.Bool("--recursive")

	if inputPath != "" {
		return showAppInfo(inputPath, showSignature, recursive)
	} else if profilePath != "" {
		return showProfileInfo(profilePath)
	}

	return fmt.Errorf("either --app or --profile is required")
}

func runDiff(opts docopt.Opts) error {
	app1Path, _ := opts.String("--app1")
	app2Path, _ := opts.String("--app2")
	recursive, _ := opts.Bool("--recursive")

	if app1Path == "" || app2Path == "" {
		return fmt.Errorf("both --app1 and --app2 are required")
	}

	diff, err := codesign.CompareBundles(app1Path, app2Path, recursive)
	if err != nil {
		return err
	}

	codesign.PrintSignatureDiff(diff, os.Stdout)
	return nil
}

func showAppInfo(inputPath string, showSignature, recursive bool) error {
	var appPath string
	var tempDir string
	var shouldCleanup bool

	// Detect if input is .ipa or .app
	isIPA := strings.HasSuffix(strings.ToLower(inputPath), ".ipa")

	if isIPA {
		// Extract IPA temporarily
		var err error
		tempDir, err = codesign.ExtractIPA(inputPath)
		if err != nil {
			return fmt.Errorf("failed to extract IPA: %w", err)
		}
		shouldCleanup = true
		defer func() {
			if shouldCleanup {
				os.RemoveAll(tempDir)
			}
		}()

		// Find the app bundle
		appPath, err = codesign.FindAppBundle(tempDir)
		if err != nil {
			return fmt.Errorf("failed to find app bundle: %w", err)
		}
	} else {
		// Input is already a .app bundle
		appPath = inputPath
	}

	// Get bundle ID
	bundleID, err := codesign.GetAppBundleID(appPath)
	if err != nil {
		return fmt.Errorf("failed to get bundle ID: %w", err)
	}

	// Get executable name
	execName, err := codesign.GetAppExecutableName(appPath)
	if err != nil {
		return fmt.Errorf("failed to get executable name: %w", err)
	}

	appName := filepath.Base(appPath)

	if isIPA {
		fmt.Println("IPA Information")
		fmt.Println("===============")
		fmt.Printf("File:        %s\n", inputPath)
	} else {
		fmt.Println("App Bundle Information")
		fmt.Println("======================")
		fmt.Printf("Path:        %s\n", inputPath)
	}
	fmt.Printf("App Name:    %s\n", appName)
	fmt.Printf("Bundle ID:   %s\n", bundleID)
	fmt.Printf("Executable:  %s\n", execName)

	// Try to read embedded provisioning profile
	embeddedProfilePath := filepath.Join(appPath, "embedded.mobileprovision")
	if profileData, err := os.ReadFile(embeddedProfilePath); err == nil {
		if profile, err := codesign.ParseProvisioningProfile(profileData); err == nil {
			fmt.Println()
			fmt.Println("Embedded Provisioning Profile")
			fmt.Println("-----------------------------")
			fmt.Printf("Team ID:        %s\n", profile.GetTeamID())
			fmt.Printf("App ID:         %s\n", profile.GetApplicationIdentifier())
			fmt.Printf("Expired:        %v\n", profile.IsExpired())
			fmt.Printf("Expiration:     %s\n", profile.ExpirationDate.Format("2006-01-02"))
			if certs, err := profile.GetCertificates(); err == nil {
				fmt.Printf("Certificates:   %d\n", len(certs))
				for i, cert := range certs {
					fmt.Printf("  [%d] %s\n", i+1, cert.Subject.CommonName)
					fmt.Printf("      Serial: %s\n", cert.SerialNumber.String())
					fmt.Printf("      Expires: %s\n", cert.NotAfter.Format("2006-01-02"))
					if len(cert.Subject.OrganizationalUnit) > 0 {
						fmt.Printf("      Team ID: %s\n", cert.Subject.OrganizationalUnit[0])
					}
				}
			}
		}
	}

	// Show signature details if requested
	if showSignature {
		fmt.Println()
		fmt.Println("Code Signature Details")
		fmt.Println("======================")

		infos, err := codesign.GetBundleSignatureInfo(appPath, recursive)
		if err != nil {
			return fmt.Errorf("failed to get signature info: %w", err)
		}

		for _, info := range infos {
			codesign.PrintSignatureInfo(info, os.Stdout, info.BundlePath)
		}
	}

	return nil
}

func showProfileInfo(profilePath string) error {
	profileData, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("failed to read profile: %w", err)
	}

	profile, err := codesign.ParseProvisioningProfile(profileData)
	if err != nil {
		return fmt.Errorf("failed to parse profile: %w", err)
	}

	fmt.Println("Provisioning Profile Information")
	fmt.Println("================================")
	fmt.Printf("File:           %s\n", profilePath)
	fmt.Printf("Name:           %s\n", profile.Name)
	fmt.Printf("Team ID:        %s\n", profile.GetTeamID())
	fmt.Printf("App ID:         %s\n", profile.GetApplicationIdentifier())
	fmt.Printf("UUID:           %s\n", profile.UUID)
	fmt.Printf("Created:        %s\n", profile.CreationDate.Format("2006-01-02 15:04:05"))
	fmt.Printf("Expiration:     %s\n", profile.ExpirationDate.Format("2006-01-02 15:04:05"))
	fmt.Printf("Expired:        %v\n", profile.IsExpired())
	if certs, err := profile.GetCertificates(); err == nil {
		fmt.Printf("Certificates:   %d\n", len(certs))
		for i, cert := range certs {
			fmt.Printf("  [%d] %s\n", i+1, cert.Subject.CommonName)
			fmt.Printf("      Serial: %s\n", cert.SerialNumber.String())
			fmt.Printf("      Expires: %s\n", cert.NotAfter.Format("2006-01-02"))
			if len(cert.Subject.OrganizationalUnit) > 0 {
				fmt.Printf("      Team ID: %s\n", cert.Subject.OrganizationalUnit[0])
			}
		}
	}

	if len(profile.ProvisionedDevices) > 0 {
		fmt.Printf("Devices:        %d\n", len(profile.ProvisionedDevices))
		fmt.Println()
		fmt.Println("Provisioned Devices:")
		for _, udid := range profile.ProvisionedDevices {
			fmt.Printf("  - %s\n", udid)
		}
	}

	if len(profile.Entitlements) > 0 {
		fmt.Println()
		fmt.Println("Entitlements:")
		for key, value := range profile.Entitlements {
			fmt.Printf("  %s: %v\n", key, value)
		}
	}

	return nil
}
