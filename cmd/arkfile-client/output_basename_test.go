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

func TestOutputNameReserverCollisionsAreCaseInsensitive(t *testing.T) {
	r := newOutputNameReserverFromNames("/dest", "", []string{"Photo.png"})
	if got := r.reserve("photo.png"); got != "photo-1.png" {
		t.Fatalf("got %q, want photo-1.png", got)
	}
	if got := r.reserve("PHOTO.png"); got != "PHOTO-2.png" {
		t.Fatalf("got %q, want PHOTO-2.png (case kept, collision counted)", got)
	}
}

func TestOutputNameReserverSuffixReservation(t *testing.T) {
	r := newOutputNameReserverFromNames("/dest", arkbackupSuffix, []string{"photo.png.ARKBACKUP", "photo.png", "notes.txt"})
	if got := r.reserve("photo.png"); got != "photo-1.png.arkbackup" {
		t.Fatalf("got %q, want photo-1.png.arkbackup", got)
	}
	if got := r.reserve("photo.jpg"); got != "photo.jpg.arkbackup" {
		t.Fatalf("got %q, want photo.jpg.arkbackup", got)
	}
	if got := r.reserve("notes.txt"); got != "notes.txt.arkbackup" {
		t.Fatalf("non-bundle entries must not count as taken: %q", got)
	}
}

func TestOutputTargetRetryReusesReservation(t *testing.T) {
	dir := t.TempDir()
	r, err := newOutputNameReserver(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	a := reservedOutputTarget(r, "photo.png")
	b := reservedOutputTarget(r, "photo.png")
	if filepath.Base(a.path()) != "photo.png" || filepath.Base(b.path()) != "photo-1.png" {
		t.Fatalf("unexpected reservations: %s %s", a.path(), b.path())
	}
	if _, err := b.write(func(*os.File) error { return os.ErrInvalid }); err == nil {
		t.Fatal("expected failure")
	}
	if filepath.Base(b.path()) != "photo-1.png" {
		t.Fatalf("failed attempt changed the reservation: %s", b.path())
	}
	if hasTempLeftovers(listDirNames(t, dir)) || len(listDirNames(t, dir)) != 0 {
		t.Fatalf("failed write left entries: %v", listDirNames(t, dir))
	}
}

func TestOutputTargetLateCollisionNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	r, err := newOutputNameReserver(dir, arkbackupSuffix)
	if err != nil {
		t.Fatal(err)
	}
	target := reservedOutputTarget(r, "photo.png")
	late := filepath.Join(dir, "photo.png.arkbackup")
	if err := os.WriteFile(late, []byte("appeared after the scan"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := target.write(func(f *os.File) error {
		_, werr := f.WriteString("new bundle")
		return werr
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if filepath.Base(path) != "photo-1.png.arkbackup" {
		t.Fatalf("late collision published at %s", path)
	}
	if got, _ := os.ReadFile(late); string(got) != "appeared after the scan" {
		t.Fatal("late entry was replaced")
	}
	if got, _ := os.ReadFile(path); string(got) != "new bundle" {
		t.Fatal("published bytes wrong")
	}
}

func TestExactOutputTargetReplacesOnlyAfterSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.arkbackup")
	if err := os.WriteFile(path, []byte("earlier bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := exactOutputTarget(path)
	if _, err := target.write(func(f *os.File) error {
		f.WriteString("partial")
		return os.ErrInvalid
	}); err == nil {
		t.Fatal("expected failure")
	}
	if got, _ := os.ReadFile(path); string(got) != "earlier bundle" {
		t.Fatal("failed exact-path write destroyed the earlier file")
	}
	if _, err := target.write(func(f *os.File) error {
		_, werr := f.WriteString("replacement")
		return werr
	}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "replacement" {
		t.Fatal("successful exact-path write did not replace")
	}
}

func TestSafeOwnerBasenameKeepsLeadingDots(t *testing.T) {
	cases := []struct{ in, want string }{
		{".bashrc", ".bashrc"},
		{"../../.ssh/config", "config"},
		{"..", "fallback.bin"},
		{"...", "fallback.bin"},
		{"dir\\.profile", ".profile"},
		{"evil\u202ename.txt", "evilname.txt"},
		{"--rf", "rf"},
	}
	for _, tc := range cases {
		if got := safeOwnerBasename(tc.in, "fallback.bin"); got != tc.want {
			t.Errorf("safeOwnerBasename(%q) = %q, want %q", tc.in, got, tc.want)
		}
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

	target, err := resolveDefaultDownloadPath(dir, "../../report.pdf", "fallback.bin")
	if err != nil {
		t.Fatalf("resolveDefaultDownloadPath: %v", err)
	}
	got := target.path()
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

	target, err := resolveDefaultDownloadPath(dir, "notes.txt", "fallback.bin")
	if err != nil {
		t.Fatalf("resolveDefaultDownloadPath: %v", err)
	}
	if want := filepath.Join(dir, "notes-1.txt"); target.path() != want {
		t.Fatalf("got %q, want %q", target.path(), want)
	}
}

func TestResolveDefaultDownloadPathIsCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Photo.png"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := resolveDefaultDownloadPath(dir, "photo.png", "fallback.bin")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "photo-1.png"); target.path() != want {
		t.Fatalf("got %q, want %q", target.path(), want)
	}
}

func TestResolveDefaultDownloadPathFailsWhenDirectoryUnreadable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := resolveDefaultDownloadPath(missing, "report.pdf", "fallback.bin"); err == nil {
		t.Fatal("expected an error for a directory that cannot be listed")
	}
}
