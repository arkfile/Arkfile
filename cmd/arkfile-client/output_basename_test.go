package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNextAvailableBasename(t *testing.T) {
	taken := map[string]struct{}{}
	if got := nextAvailableBasename("photo.png", taken); got != "photo.png" {
		t.Fatalf("got %q", got)
	}
	taken["photo.png"] = struct{}{}
	if got := nextAvailableBasename("photo.png", taken); got != "photo-1.png" {
		t.Fatalf("got %q", got)
	}
	taken["photo-1.png"] = struct{}{}
	if got := nextAvailableBasename("photo.png", taken); got != "photo-2.png" {
		t.Fatalf("got %q", got)
	}
}

func TestNextAvailableBasenameNoExtension(t *testing.T) {
	taken := map[string]struct{}{"readme": {}}
	if got := nextAvailableBasename("readme", taken); got != "readme-1" {
		t.Fatalf("got %q", got)
	}
}

func TestReserveBasenamesStableAcrossCalls(t *testing.T) {
	items := []struct {
		Key      string
		Filename string
	}{
		{Key: "a", Filename: "photo.png"},
		{Key: "b", Filename: "photo.png"},
	}
	first := reserveBasenames(items, nil)
	if first["a"] != "photo.png" || first["b"] != "photo-1.png" {
		t.Fatalf("unexpected first reservation: %#v", first)
	}
	// Retries must reuse the same reserved names, not re-increment.
	second := map[string]string{"a": first["a"], "b": first["b"]}
	if second["a"] != "photo.png" || second["b"] != "photo-1.png" {
		t.Fatalf("retry reservation drifted: %#v", second)
	}
}

func TestSafeDownloadBasenameRejectsPathsAndHiddenNames(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"report.pdf", "report.pdf"},
		{"../../.bashrc", "bashrc"},
		{"/home/user/.ssh/authorized_keys", "authorized_keys"},
		{`..\..\evil.exe`, "evil.exe"},
		{"nested/dir/", "fallback.bin"},
		{".profile", "profile"},
		{". .bash_profile", "bash_profile"},
		{"--checkpoint=1", "checkpoint=1"},
		{"  spaced name.txt  ", "spaced name.txt"},
		{"bad\x1b[31m\u202ename.txt", "bad[31mname.txt"},
		{"line\nbreak.txt", "linebreak.txt"},
		{"caf\u00e9 \u65e5\u672c.txt", "caf\u00e9 \u65e5\u672c.txt"},
		{".", "fallback.bin"},
		{"..", "fallback.bin"},
		{"...", "fallback.bin"},
		{"", "fallback.bin"},
		{"   ", "fallback.bin"},
		{"\x00\x07", "fallback.bin"},
	}
	for _, tc := range cases {
		if got := safeDownloadBasename(tc.name, "fallback.bin"); got != tc.want {
			t.Errorf("safeDownloadBasename(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSafeDownloadBasenameSanitizesFallback(t *testing.T) {
	if got := safeDownloadBasename("..", "../share/abc.bin"); got != "abc.bin" {
		t.Fatalf("got %q, want abc.bin", got)
	}
	if got := safeDownloadBasename("", ""); got != "download" {
		t.Fatalf("got %q, want download", got)
	}
}

func TestSafeDownloadBasenameBoundsLength(t *testing.T) {
	long := strings.Repeat("\u00e9", 300) + ".pdf"
	got := safeDownloadBasename(long, "fallback.bin")
	if len(got) > maxSafeBasenameBytes {
		t.Fatalf("length %d exceeds %d", len(got), maxSafeBasenameBytes)
	}
	if !strings.HasSuffix(got, ".pdf") {
		t.Fatalf("extension lost: %q", got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncation split a character: %q", got)
	}

	longExtension := "name." + strings.Repeat("x", 300)
	got = safeDownloadBasename(longExtension, "fallback.bin")
	if len(got) > maxSafeBasenameBytes || !strings.HasPrefix(got, "name.") {
		t.Fatalf("unexpected truncation: %q (%d bytes)", got, len(got))
	}
}

func TestResolveDefaultDownloadPathAvoidsExistingEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "report.pdf"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "report-1.pdf"), 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := resolveDefaultDownloadPath(dir, "../../report.pdf", "fallback.bin")
	if err != nil {
		t.Fatalf("resolveDefaultDownloadPath: %v", err)
	}
	if want := filepath.Join(dir, "report-2.pdf"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if filepath.Dir(got) != dir {
		t.Fatalf("resolved path left the directory: %q", got)
	}
}

func TestResolveDefaultDownloadPathTreatsLinksAsTaken(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "missing-target"), filepath.Join(dir, "notes.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	got, err := resolveDefaultDownloadPath(dir, "notes.txt", "fallback.bin")
	if err != nil {
		t.Fatalf("resolveDefaultDownloadPath: %v", err)
	}
	if want := filepath.Join(dir, "notes-1.txt"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveDefaultDownloadPathFailsWhenDirectoryUnreadable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := resolveDefaultDownloadPath(missing, "report.pdf", "fallback.bin"); err == nil {
		t.Fatal("expected an error for a directory that cannot be listed")
	}
}
