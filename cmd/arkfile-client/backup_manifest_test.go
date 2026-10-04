package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func manifestFixtureDir(t *testing.T) (string, []byte) {
	t.Helper()
	key := randomBytes(t, 32)
	customKey, customSalt := testCustomKey(t)
	dir := t.TempDir()
	writeTestBundle(t, testBundleSpec{Dir: dir, Name: "photo.png.arkbackup", FileID: batchFileA, AccountKey: key, Filename: "photo.png", Tags: "private-tag", Plaintext: []byte("photo")})
	writeTestBundle(t, testBundleSpec{Dir: dir, Name: "photo-1.png.arkbackup", FileID: batchFileA, AccountKey: key, Filename: "photo.png", Plaintext: []byte("photo")})
	writeTestBundle(t, testBundleSpec{Dir: dir, Name: "renamed-bundle", FileID: batchFileB, AccountKey: key, PasswordType: "custom", CustomKey: customKey, CustomSalt: customSalt, Filename: "secret.txt", Hint: "private-hint", Plaintext: []byte("s")})
	if err := os.WriteFile(filepath.Join(dir, "recovery-note.txt"), []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, key
}

func runManifest(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = handleBackupManifestCommand(args) })
	return out, err
}

func TestBackupManifestCreateIsDeterministicAndMinimal(t *testing.T) {
	dir, _ := manifestFixtureDir(t)
	if out, err := runManifest(t, "create", "--bundle-dir", dir); err != nil {
		t.Fatalf("create failed: %v\n%s", err, out)
	}
	path := filepath.Join(dir, defaultIntegrityManifestName)
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runManifest(t, "create", "--bundle-dir", dir); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if string(first) != string(second) {
		t.Fatal("manifest is not deterministic")
	}

	var generic map[string]interface{}
	if err := json.Unmarshal(first, &generic); err != nil {
		t.Fatal(err)
	}
	if generic["format"] != integrityManifestFormat || generic["version"].(float64) != 1 || len(generic) != 3 {
		t.Fatalf("unexpected top level: %v", generic)
	}
	entries := generic["entries"].([]interface{})
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (duplicates kept, renamed bundle found by content), got %d", len(entries))
	}
	names := make([]string, 0, len(entries))
	for _, raw := range entries {
		e := raw.(map[string]interface{})
		if len(e) != 5 {
			t.Fatalf("entry has %d fields, want exactly 5: %v", len(e), e)
		}
		for _, field := range []string{"bundle_name", "file_id", "bundle_version", "bundle_size_bytes", "sha256"} {
			if _, ok := e[field]; !ok {
				t.Fatalf("entry missing %s", field)
			}
		}
		names = append(names, e["bundle_name"].(string))
		if got := fileSHA256Hex(t, filepath.Join(dir, e["bundle_name"].(string))); got != e["sha256"] {
			t.Fatalf("recorded digest does not match the whole bundle")
		}
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("entries not sorted: %v", names)
	}
	text := string(first)
	for _, forbidden := range []string{"private-tag", "private-hint", "secret.txt", testOwner, "custom", "account", "owner", "password", "tags", "hint", "kdf"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("manifest leaks %q:\n%s", forbidden, text)
		}
	}
	if out, err := runManifest(t, "verify", "--bundle-dir", dir); err != nil {
		t.Fatalf("verify of unchanged directory failed: %v\n%s", err, out)
	}
}

func TestBackupManifestCreateKeepsEarlierManifestOnFailure(t *testing.T) {
	dir, _ := manifestFixtureDir(t)
	if _, err := runManifest(t, "create", "--bundle-dir", dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, defaultIntegrityManifestName)
	before, _ := os.ReadFile(path)

	damagedMagic := filepath.Join(dir, "damaged.arkbackup")
	if err := os.WriteFile(damagedMagic, []byte("ARKX not quite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runManifest(t, "create", "--bundle-dir", dir); err == nil {
		t.Fatal("create must fail when a .arkbackup candidate has damaged magic")
	}
	os.Remove(damagedMagic)

	truncated := filepath.Join(dir, "truncated-copy")
	data, _ := os.ReadFile(filepath.Join(dir, "photo.png.arkbackup"))
	if err := os.WriteFile(truncated, data[:len(data)-5], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runManifest(t, "create", "--bundle-dir", dir); err == nil {
		t.Fatal("create must fail when an ARKB candidate is malformed")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("failed creation changed the earlier manifest")
	}
	if hasTempLeftovers(listDirNames(t, dir)) {
		t.Fatal("failed creation left a temporary file")
	}
}

func TestBackupManifestCreateInterruptedLeavesManifest(t *testing.T) {
	dir, _ := manifestFixtureDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := buildIntegrityManifest(ctx, dir); err == nil {
		t.Fatal("interrupted scan must not produce a manifest")
	}
}

func TestBackupManifestVerifyDetectsProblems(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, dir string, manifestPath string)
		reason string
	}{
		{"missing bundle", func(t *testing.T, dir, _ string) {
			os.Remove(filepath.Join(dir, "photo.png.arkbackup"))
		}, manifestReasonMissing},
		{"changed bytes", func(t *testing.T, dir, _ string) {
			p := filepath.Join(dir, "photo.png.arkbackup")
			data, _ := os.ReadFile(p)
			data[len(data)-1] ^= 0xff
			os.WriteFile(p, data, 0o600)
		}, manifestReasonChanged},
		{"changed length", func(t *testing.T, dir, _ string) {
			p := filepath.Join(dir, "photo.png.arkbackup")
			data, _ := os.ReadFile(p)
			os.WriteFile(p, data[:len(data)-1], 0o600)
		}, manifestReasonChanged},
		{"malformed candidate", func(t *testing.T, dir, _ string) {
			os.WriteFile(filepath.Join(dir, "broken.arkbackup"), []byte("ARKB\x00\x02junk"), 0o600)
		}, manifestReasonMalformed},
		{"unlisted valid bundle", func(t *testing.T, dir, _ string) {
			data, _ := os.ReadFile(filepath.Join(dir, "photo.png.arkbackup"))
			os.WriteFile(filepath.Join(dir, "photo-2.png.arkbackup"), data, 0o600)
		}, manifestReasonUnlisted},
		{"symlink in place of listed file", func(t *testing.T, dir, _ string) {
			p := filepath.Join(dir, "photo.png.arkbackup")
			os.Rename(p, filepath.Join(t.TempDir(), "moved"))
			if err := os.Symlink(filepath.Join(dir, "photo-1.png.arkbackup"), p); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
		}, manifestReasonUnsafe},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := manifestFixtureDir(t)
			if _, err := runManifest(t, "create", "--bundle-dir", dir); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, dir, filepath.Join(dir, defaultIntegrityManifestName))
			out, err := runManifest(t, "verify", "--bundle-dir", dir)
			if err == nil || !strings.Contains(out, tc.reason) {
				t.Fatalf("expected %s: err=%v\n%s", tc.reason, err, out)
			}
		})
	}
}

func TestBackupManifestVerifyRejectsUntrustedManifests(t *testing.T) {
	dir, _ := manifestFixtureDir(t)
	if _, err := runManifest(t, "create", "--bundle-dir", dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, defaultIntegrityManifestName)
	original, _ := os.ReadFile(path)
	var m integrityManifest
	if err := json.Unmarshal(original, &m); err != nil {
		t.Fatal(err)
	}

	write := func(mutated integrityManifest) {
		data, _ := json.Marshal(mutated)
		os.WriteFile(path, data, 0o600)
	}
	pathEntry := m
	pathEntry.Entries = append([]integrityManifestEntry(nil), m.Entries...)
	pathEntry.Entries[0].BundleName = "../" + pathEntry.Entries[0].BundleName
	write(pathEntry)
	if _, err := runManifest(t, "verify", "--bundle-dir", dir); err == nil {
		t.Fatal("accepted an entry with a path separator")
	}

	dup := m
	dup.Entries = append(append([]integrityManifestEntry(nil), m.Entries...), m.Entries[0])
	write(dup)
	if _, err := runManifest(t, "verify", "--bundle-dir", dir); err == nil {
		t.Fatal("accepted a duplicate bundle name")
	}

	version := m
	version.Version = 2
	write(version)
	if _, err := runManifest(t, "verify", "--bundle-dir", dir); err == nil {
		t.Fatal("accepted an unsupported manifest version")
	}
}

func TestBackupManifestIgnoresOrdinaryFilesAndRejectsBundleOutputName(t *testing.T) {
	dir, _ := manifestFixtureDir(t)
	out, err := runManifest(t, "create", "--bundle-dir", dir)
	if err != nil || !strings.Contains(out, "3 bundle(s), 1 other file(s) ignored") {
		t.Fatalf("unexpected create output: %v\n%s", err, out)
	}
	if _, err := runManifest(t, "create", "--bundle-dir", dir, "--output", filepath.Join(dir, "x.arkbackup")); err == nil {
		t.Fatal("accepted a manifest path ending in .arkbackup")
	}
	if _, err := runManifest(t, "create", "--bundle-dir", dir, "--output", filepath.Join(dir, "renamed-bundle")); err == nil {
		t.Fatal("accepted a manifest path that aliases a bundle")
	}
}
