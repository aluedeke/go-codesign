package codesign

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"sort"
)

// fprint is a helper that ignores fmt.Fprintf errors (for CLI output)
func fprint(w io.Writer, format string, a ...interface{}) {
	_, _ = fmt.Fprintf(w, format, a...)
}

// fprintln is a helper that ignores fmt.Fprintln errors (for CLI output)
func fprintln(w io.Writer) {
	_, _ = fmt.Fprintln(w)
}

// SignatureDiff represents the differences between two signatures
type SignatureDiff struct {
	Path1       string
	Path2       string
	BundleDiffs []BundleDiff
}

// BundleDiff represents differences for a single bundle
type BundleDiff struct {
	RelativePath     string
	SuperBlobDiff    FieldDiff
	CodeDirDiffs     []CodeDirDiff
	RequirementsDiff FieldDiff
	EntitlementsDiff EntitlementsDiff
	CMSDiff          FieldDiff

	// Only in one app
	OnlyIn1 bool
	OnlyIn2 bool
}

// FieldDiff represents a simple field comparison
type FieldDiff struct {
	Name    string
	Same    bool
	Value1  string
	Value2  string
	Details string
}

// CodeDirDiff represents CodeDirectory differences
type CodeDirDiff struct {
	Slot             uint32
	HashType         string
	VersionDiff      FieldDiff
	FlagsDiff        FieldDiff
	IdentifierDiff   FieldDiff
	TeamIDDiff       FieldDiff
	PageSizeDiff     FieldDiff
	CodeLimitDiff    FieldDiff
	SpecialSlotDiffs []FieldDiff
	CodeHashesSame   bool
	CodeHashesCount1 int
	CodeHashesCount2 int
}

// EntitlementsDiff represents entitlements differences
type EntitlementsDiff struct {
	Same    bool
	Added   map[string]interface{}    // In 2 but not in 1
	Removed map[string]interface{}    // In 1 but not in 2
	Changed map[string][2]interface{} // Different values
}

// CompareSignatures compares two SignatureInfo structures
func CompareSignatures(info1, info2 *SignatureInfo) *BundleDiff {
	diff := &BundleDiff{
		RelativePath: filepath.Base(info1.BundlePath),
	}

	// Compare SuperBlob
	diff.SuperBlobDiff = compareField("SuperBlob",
		fmt.Sprintf("%d blobs, %d bytes", info1.SuperBlob.BlobCount, info1.SuperBlob.Length),
		fmt.Sprintf("%d blobs, %d bytes", info2.SuperBlob.BlobCount, info2.SuperBlob.Length),
	)

	// Compare CodeDirectories
	cdMap1 := make(map[uint32]*CodeDirectoryInfo)
	cdMap2 := make(map[uint32]*CodeDirectoryInfo)

	for i := range info1.CodeDirs {
		cdMap1[info1.CodeDirs[i].Slot] = &info1.CodeDirs[i]
	}
	for i := range info2.CodeDirs {
		cdMap2[info2.CodeDirs[i].Slot] = &info2.CodeDirs[i]
	}

	// Get all unique slots
	allSlots := make(map[uint32]bool)
	for slot := range cdMap1 {
		allSlots[slot] = true
	}
	for slot := range cdMap2 {
		allSlots[slot] = true
	}

	for slot := range allSlots {
		cd1, ok1 := cdMap1[slot]
		cd2, ok2 := cdMap2[slot]

		if ok1 && ok2 {
			cdDiff := compareCodeDirectories(cd1, cd2)
			diff.CodeDirDiffs = append(diff.CodeDirDiffs, cdDiff)
		} else if ok1 {
			diff.CodeDirDiffs = append(diff.CodeDirDiffs, CodeDirDiff{
				Slot:     slot,
				HashType: getHashTypeName(cd1.HashType),
				VersionDiff: FieldDiff{
					Name:   "Presence",
					Same:   false,
					Value1: "present",
					Value2: "missing",
				},
			})
		} else {
			diff.CodeDirDiffs = append(diff.CodeDirDiffs, CodeDirDiff{
				Slot:     slot,
				HashType: getHashTypeName(cd2.HashType),
				VersionDiff: FieldDiff{
					Name:   "Presence",
					Same:   false,
					Value1: "missing",
					Value2: "present",
				},
			})
		}
	}

	// Compare Requirements
	diff.RequirementsDiff = compareField("Requirements",
		fmt.Sprintf("%d bytes", info1.Requirements.Size),
		fmt.Sprintf("%d bytes", info2.Requirements.Size),
	)
	if info1.Requirements.Size > 0 && info2.Requirements.Size > 0 {
		diff.RequirementsDiff.Same = bytes.Equal(info1.Requirements.RawData, info2.Requirements.RawData)
		if diff.RequirementsDiff.Same {
			diff.RequirementsDiff.Details = "identical"
		}
	}

	// Compare Entitlements
	diff.EntitlementsDiff = compareEntitlements(info1.Entitlements.Parsed, info2.Entitlements.Parsed)

	// Compare CMS
	diff.CMSDiff = compareField("CMS Signature",
		fmt.Sprintf("%d bytes", info1.CMSSignature.Size),
		fmt.Sprintf("%d bytes", info2.CMSSignature.Size),
	)

	return diff
}

// compareField creates a FieldDiff for simple value comparison
func compareField(name, val1, val2 string) FieldDiff {
	return FieldDiff{
		Name:   name,
		Same:   val1 == val2,
		Value1: val1,
		Value2: val2,
	}
}

// compareCodeDirectories compares two CodeDirectory structures
func compareCodeDirectories(cd1, cd2 *CodeDirectoryInfo) CodeDirDiff {
	diff := CodeDirDiff{
		Slot:     cd1.Slot,
		HashType: getHashTypeName(cd1.HashType),
	}

	diff.VersionDiff = compareField("Version",
		fmt.Sprintf("0x%x", cd1.Version),
		fmt.Sprintf("0x%x", cd2.Version),
	)

	diff.FlagsDiff = compareField("Flags",
		fmt.Sprintf("0x%x", cd1.Flags),
		fmt.Sprintf("0x%x", cd2.Flags),
	)

	diff.IdentifierDiff = compareField("Identifier", cd1.Identifier, cd2.Identifier)
	diff.TeamIDDiff = compareField("Team ID", cd1.TeamID, cd2.TeamID)

	diff.PageSizeDiff = compareField("Page Size",
		fmt.Sprintf("%d", cd1.PageSize),
		fmt.Sprintf("%d", cd2.PageSize),
	)

	diff.CodeLimitDiff = compareField("Code Limit",
		fmt.Sprintf("%d", cd1.CodeLimit),
		fmt.Sprintf("%d", cd2.CodeLimit),
	)

	// Compare special slots
	allSlots := make(map[int]bool)
	for slot := range cd1.SpecialHashes {
		allSlots[slot] = true
	}
	for slot := range cd2.SpecialHashes {
		allSlots[slot] = true
	}

	slotNames := map[int]string{
		-1: "Info.plist",
		-2: "Requirements",
		-3: "CodeResources",
		-4: "Application",
		-5: "Entitlements",
		-6: "RepSpecific",
		-7: "EntitlementsDER",
	}

	slots := make([]int, 0, len(allSlots))
	for slot := range allSlots {
		slots = append(slots, slot)
	}
	sort.Ints(slots)

	for _, slot := range slots {
		hash1, ok1 := cd1.SpecialHashes[slot]
		hash2, ok2 := cd2.SpecialHashes[slot]

		name := slotNames[slot]
		if name == "" {
			name = fmt.Sprintf("Slot %d", slot)
		}

		var val1, val2 string
		if ok1 {
			val1 = hex.EncodeToString(hash1)
		} else {
			val1 = "<empty>"
		}
		if ok2 {
			val2 = hex.EncodeToString(hash2)
		} else {
			val2 = "<empty>"
		}

		diff.SpecialSlotDiffs = append(diff.SpecialSlotDiffs, FieldDiff{
			Name:   fmt.Sprintf("%d (%s)", slot, name),
			Same:   bytes.Equal(hash1, hash2),
			Value1: val1,
			Value2: val2,
		})
	}

	// Compare code hashes
	diff.CodeHashesCount1 = len(cd1.CodeHashes)
	diff.CodeHashesCount2 = len(cd2.CodeHashes)
	diff.CodeHashesSame = len(cd1.CodeHashes) == len(cd2.CodeHashes)

	if diff.CodeHashesSame {
		for i := range cd1.CodeHashes {
			if !bytes.Equal(cd1.CodeHashes[i], cd2.CodeHashes[i]) {
				diff.CodeHashesSame = false
				break
			}
		}
	}

	return diff
}

// compareEntitlements compares two entitlements maps
func compareEntitlements(ent1, ent2 map[string]interface{}) EntitlementsDiff {
	diff := EntitlementsDiff{
		Same:    true,
		Added:   make(map[string]interface{}),
		Removed: make(map[string]interface{}),
		Changed: make(map[string][2]interface{}),
	}

	// Check for removed and changed
	for key, val1 := range ent1 {
		if val2, ok := ent2[key]; ok {
			if !entitlementValuesEqual(val1, val2) {
				diff.Changed[key] = [2]interface{}{val1, val2}
				diff.Same = false
			}
		} else {
			diff.Removed[key] = val1
			diff.Same = false
		}
	}

	// Check for added
	for key, val2 := range ent2 {
		if _, ok := ent1[key]; !ok {
			diff.Added[key] = val2
			diff.Same = false
		}
	}

	return diff
}

// entitlementValuesEqual compares two entitlement values
func entitlementValuesEqual(v1, v2 interface{}) bool {
	return fmt.Sprintf("%v", v1) == fmt.Sprintf("%v", v2)
}

// getHashTypeName returns the name for a hash type
func getHashTypeName(hashType uint8) string {
	switch hashType {
	case CS_HASHTYPE_SHA1:
		return "SHA-1"
	case CS_HASHTYPE_SHA256:
		return "SHA-256"
	default:
		return fmt.Sprintf("Unknown(%d)", hashType)
	}
}

// PrintSignatureDiff prints a signature diff to a writer
func PrintSignatureDiff(diff *SignatureDiff, w io.Writer) {
	fprint(w, "Comparing:\n")
	fprint(w, "  App 1: %s\n", diff.Path1)
	fprint(w, "  App 2: %s\n", diff.Path2)
	fprintln(w)

	for _, bundleDiff := range diff.BundleDiffs {
		printBundleDiff(&bundleDiff, w)
	}
}

// printBundleDiff prints a single bundle diff
func printBundleDiff(diff *BundleDiff, w io.Writer) {
	fprint(w, "=== %s ===\n", diff.RelativePath)

	if diff.OnlyIn1 {
		fprint(w, "  Only in App 1\n")
		return
	}
	if diff.OnlyIn2 {
		fprint(w, "  Only in App 2\n")
		return
	}

	// SuperBlob
	printFieldDiff(w, "SuperBlob", diff.SuperBlobDiff)

	// CodeDirectories
	for _, cdDiff := range diff.CodeDirDiffs {
		printCodeDirDiff(w, &cdDiff)
	}

	// Requirements
	printFieldDiff(w, "Requirements", diff.RequirementsDiff)

	// Entitlements
	printEntitlementsDiff(w, &diff.EntitlementsDiff)

	// CMS
	printFieldDiff(w, "CMS Signature", diff.CMSDiff)

	fprintln(w)
}

// printFieldDiff prints a field diff
func printFieldDiff(w io.Writer, name string, diff FieldDiff) {
	status := "SAME"
	if !diff.Same {
		status = "DIFFER"
	}

	if diff.Same {
		fprint(w, "  %-16s %s (%s)\n", name+":", status, diff.Value1)
	} else {
		fprint(w, "  %-16s %s\n", name+":", status)
		fprint(w, "    - App 1: %s\n", diff.Value1)
		fprint(w, "    + App 2: %s\n", diff.Value2)
	}
}

// printCodeDirDiff prints a CodeDirectory diff
func printCodeDirDiff(w io.Writer, diff *CodeDirDiff) {
	var slotName string
	switch diff.Slot {
	case CSSLOT_ALTERNATE_CODEDIRECTORIES:
		slotName = "CodeDirectory (SHA256)"
	case CSSLOT_CODEDIRECTORY:
		slotName = "CodeDirectory (SHA1)"
	default:
		slotName = "CodeDirectory"
	}

	// Check if all fields are same
	allSame := diff.VersionDiff.Same && diff.FlagsDiff.Same &&
		diff.IdentifierDiff.Same && diff.TeamIDDiff.Same &&
		diff.PageSizeDiff.Same && diff.CodeLimitDiff.Same

	for _, slotDiff := range diff.SpecialSlotDiffs {
		if !slotDiff.Same {
			allSame = false
			break
		}
	}

	if allSame && diff.CodeHashesSame {
		fprint(w, "  %-16s SAME\n", slotName+":")
		return
	}

	fprint(w, "  %-16s\n", slotName+":")

	if !diff.VersionDiff.Same {
		fprint(w, "    Version:      DIFFER (%s vs %s)\n", diff.VersionDiff.Value1, diff.VersionDiff.Value2)
	}
	if !diff.IdentifierDiff.Same {
		fprint(w, "    Identifier:   DIFFER\n")
		fprint(w, "      - App 1: %s\n", diff.IdentifierDiff.Value1)
		fprint(w, "      + App 2: %s\n", diff.IdentifierDiff.Value2)
	}
	if !diff.TeamIDDiff.Same {
		fprint(w, "    Team ID:      DIFFER (%s vs %s)\n", diff.TeamIDDiff.Value1, diff.TeamIDDiff.Value2)
	}
	if !diff.PageSizeDiff.Same {
		fprint(w, "    Page Size:    DIFFER (%s vs %s)\n", diff.PageSizeDiff.Value1, diff.PageSizeDiff.Value2)
	}
	if !diff.CodeLimitDiff.Same {
		fprint(w, "    Code Limit:   DIFFER (%s vs %s)\n", diff.CodeLimitDiff.Value1, diff.CodeLimitDiff.Value2)
	}

	// Special slots
	hasDifferentSlots := false
	for _, slotDiff := range diff.SpecialSlotDiffs {
		if !slotDiff.Same {
			hasDifferentSlots = true
			break
		}
	}

	if hasDifferentSlots {
		fprint(w, "    Special Slots:\n")
		for _, slotDiff := range diff.SpecialSlotDiffs {
			status := "SAME"
			if !slotDiff.Same {
				status = "DIFFER"
			}
			fprint(w, "      %s: %s\n", slotDiff.Name, status)
			if !slotDiff.Same {
				v1 := slotDiff.Value1
				v2 := slotDiff.Value2
				if len(v1) > 40 {
					v1 = v1[:40] + "..."
				}
				if len(v2) > 40 {
					v2 = v2[:40] + "..."
				}
				fprint(w, "        - App 1: %s\n", v1)
				fprint(w, "        + App 2: %s\n", v2)
			}
		}
	} else {
		fprint(w, "    Special Slots: SAME\n")
	}

	// Code hashes
	if diff.CodeHashesSame {
		fprint(w, "    Code Hashes:  SAME (%d pages)\n", diff.CodeHashesCount1)
	} else {
		fprint(w, "    Code Hashes:  DIFFER (%d vs %d pages)\n", diff.CodeHashesCount1, diff.CodeHashesCount2)
	}
}

// printEntitlementsDiff prints entitlements diff
func printEntitlementsDiff(w io.Writer, diff *EntitlementsDiff) {
	if diff.Same {
		fprint(w, "  %-16s SAME\n", "Entitlements:")
		return
	}

	fprint(w, "  %-16s DIFFER\n", "Entitlements:")

	for key, val := range diff.Removed {
		fprint(w, "    - %s: %v\n", key, val)
	}
	for key, val := range diff.Added {
		fprint(w, "    + %s: %v\n", key, val)
	}
	for key, vals := range diff.Changed {
		fprint(w, "    ~ %s:\n", key)
		fprint(w, "      - App 1: %v\n", vals[0])
		fprint(w, "      + App 2: %v\n", vals[1])
	}
}

// CompareBundles compares signatures of two bundles (and optionally nested bundles)
func CompareBundles(path1, path2 string, recursive bool) (*SignatureDiff, error) {
	// Get signature info for both bundles
	infos1, err := GetBundleSignatureInfo(path1, recursive)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature info for %s: %w", path1, err)
	}

	infos2, err := GetBundleSignatureInfo(path2, recursive)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature info for %s: %w", path2, err)
	}

	diff := &SignatureDiff{
		Path1: path1,
		Path2: path2,
	}

	// Create maps by relative path
	infoMap1 := make(map[string]*SignatureInfo)
	infoMap2 := make(map[string]*SignatureInfo)

	basePath1 := filepath.Dir(path1)
	basePath2 := filepath.Dir(path2)

	for _, info := range infos1 {
		relPath, _ := filepath.Rel(basePath1, info.BundlePath)
		infoMap1[relPath] = info
	}
	for _, info := range infos2 {
		relPath, _ := filepath.Rel(basePath2, info.BundlePath)
		infoMap2[relPath] = info
	}

	// Get all unique paths
	allPaths := make(map[string]bool)
	for path := range infoMap1 {
		allPaths[path] = true
	}
	for path := range infoMap2 {
		allPaths[path] = true
	}

	// Sort paths for consistent output
	sortedPaths := make([]string, 0, len(allPaths))
	for path := range allPaths {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Strings(sortedPaths)

	// Compare each bundle
	for _, path := range sortedPaths {
		info1, ok1 := infoMap1[path]
		info2, ok2 := infoMap2[path]

		if ok1 && ok2 {
			bundleDiff := CompareSignatures(info1, info2)
			bundleDiff.RelativePath = path
			diff.BundleDiffs = append(diff.BundleDiffs, *bundleDiff)
		} else if ok1 {
			diff.BundleDiffs = append(diff.BundleDiffs, BundleDiff{
				RelativePath: path,
				OnlyIn1:      true,
			})
		} else {
			diff.BundleDiffs = append(diff.BundleDiffs, BundleDiff{
				RelativePath: path,
				OnlyIn2:      true,
			})
		}
	}

	return diff, nil
}
