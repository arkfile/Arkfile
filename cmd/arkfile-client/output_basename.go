package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// Keeps sanitized names well under the common 255-byte filename limit so
	// collision suffixes such as "-12" and ".arkbackup" still fit.
	maxSafeBasenameBytes = 200
	// Longer trailing "extensions" are treated as part of the name when truncating.
	maxKeptExtensionBytes = 16
	// Bounds re-reservation when other writers keep claiming names in the
	// destination between reservation and publish.
	maxLateCollisionRetries = 32
)

func splitBasenameExtension(filename string) (stem, ext string) {
	base := filepath.Base(filename)
	if base == "." || base == "/" || base == "" {
		base = "download"
	}
	// filepath.Ext includes the dot; treat leading-dot names as stem-only.
	ext = filepath.Ext(base)
	if ext == "" || ext == base {
		return base, ""
	}
	stem = strings.TrimSuffix(base, ext)
	if stem == "" {
		return base, ""
	}
	return stem, ext
}

// nextAvailableBasename returns desiredName, or desiredName with a numeric
// suffix before its extension, whose lowercase form is not in taken. Keys in
// taken are lowercase so names that differ only in case collide, as they do
// on FAT, exFAT, macOS, and Windows destinations.
func nextAvailableBasename(desiredName string, taken map[string]struct{}) string {
	stem, ext := splitBasenameExtension(desiredName)
	candidate := stem + ext
	if _, exists := taken[strings.ToLower(candidate)]; !exists {
		return candidate
	}
	for n := 1; ; n++ {
		candidate = fmt.Sprintf("%s-%d%s", stem, n, ext)
		if _, exists := taken[strings.ToLower(candidate)]; !exists {
			return candidate
		}
	}
}

// outputNameReserver hands out collision-free names inside one directory.
// With a suffix such as ".arkbackup", reservation works on names without the
// suffix ("photo.png" -> "photo.png.arkbackup", "photo-1.png.arkbackup"), and
// only existing entries ending in the suffix count as taken.
type outputNameReserver struct {
	dir    string
	suffix string
	taken  map[string]struct{}
}

func newOutputNameReserver(dir, suffix string) (*outputNameReserver, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot list directory %q to choose a safe output name: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return newOutputNameReserverFromNames(dir, suffix, names), nil
}

func newOutputNameReserverFromNames(dir, suffix string, existing []string) *outputNameReserver {
	r := &outputNameReserver{dir: dir, suffix: suffix, taken: make(map[string]struct{}, len(existing))}
	for _, name := range existing {
		r.markTaken(name)
	}
	return r
}

func (r *outputNameReserver) takenKey(name string) (string, bool) {
	lower := strings.ToLower(name)
	if r.suffix == "" {
		return lower, lower != ""
	}
	lowerSuffix := strings.ToLower(r.suffix)
	if !strings.HasSuffix(lower, lowerSuffix) {
		return "", false
	}
	return strings.TrimSuffix(lower, lowerSuffix), true
}

func (r *outputNameReserver) markTaken(name string) {
	if key, ok := r.takenKey(name); ok {
		r.taken[key] = struct{}{}
	}
}

// reserve claims the first free name derived from desired and returns it
// with the reserver's suffix appended.
func (r *outputNameReserver) reserve(desired string) string {
	name := nextAvailableBasename(desired, r.taken)
	r.taken[strings.ToLower(name)] = struct{}{}
	return name + r.suffix
}

// outputTarget is one output file: either an exact path that is replaced
// only after a complete successful write, or a reserved name inside a
// directory that is never allowed to replace an existing entry.
type outputTarget struct {
	exactPath string
	reserver  *outputNameReserver
	desired   string
	name      string
}

func exactOutputTarget(path string) *outputTarget {
	return &outputTarget{exactPath: path}
}

func reservedOutputTarget(r *outputNameReserver, desired string) *outputTarget {
	return &outputTarget{reserver: r, desired: desired, name: r.reserve(desired)}
}

// path is the intended destination; after a late collision it reflects the
// re-reserved name, so retries reuse it.
func (t *outputTarget) path() string {
	if t.exactPath != "" {
		return t.exactPath
	}
	return filepath.Join(t.reserver.dir, t.name)
}

// write streams output into a temporary file beside the destination and
// publishes it only after write returns nil. Failure removes only the
// temporary file this call created.
func (t *outputTarget) write(write func(file *os.File) error) (string, error) {
	if t.exactPath != "" {
		if err := writeAtomicOutput(t.exactPath, write); err != nil {
			return "", err
		}
		return t.exactPath, nil
	}
	output, err := createAtomicOutput(t.path())
	if err != nil {
		return "", err
	}
	defer output.abort()
	if err := write(output.file); err != nil {
		return "", err
	}
	for attempt := 0; ; attempt++ {
		err := output.commitNoReplace(t.path())
		if err == nil {
			return t.path(), nil
		}
		if !errors.Is(err, errDestinationExists) || attempt >= maxLateCollisionRetries {
			return "", err
		}
		t.reserver.markTaken(t.name)
		t.name = t.reserver.reserve(t.desired)
	}
}

// safeDownloadBasename reduces an untrusted filename, such as the one a sharer
// placed in a share envelope, to a single path element: no directory parts, no
// control or bidirectional characters, no leading dots or dashes (so it cannot
// be ".", "..", a hidden file, or read as a command-line option), and a bounded
// length. The fallback gets the same treatment when nothing usable remains.
func safeDownloadBasename(name, fallback string) string {
	if safe := sanitizeUntrustedBasename(name, true); safe != "" {
		return safe
	}
	if safe := sanitizeUntrustedBasename(fallback, true); safe != "" {
		return safe
	}
	return "download"
}

// safeOwnerBasename is safeDownloadBasename for the owner's own decrypted
// filenames: leading dots are kept because dotfile backups are legitimate,
// but names made only of dots are still rejected.
func safeOwnerBasename(name, fallback string) string {
	if safe := sanitizeUntrustedBasename(name, false); safe != "" {
		return safe
	}
	return safeDownloadBasename(fallback, "download")
}

func sanitizeUntrustedBasename(name string, stripLeadingDots bool) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Map(func(r rune) rune {
		if isUnsafeDisplayRune(r) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimLeftFunc(name, func(r rune) bool {
		return (stripLeadingDots && r == '.') || r == '-' || unicode.IsSpace(r)
	})
	name = strings.TrimRightFunc(name, unicode.IsSpace)
	if strings.Trim(name, ".") == "" {
		return ""
	}
	return truncateBasename(name, maxSafeBasenameBytes)
}

// truncateBasename shortens name to at most maxBytes bytes on a UTF-8
// boundary, keeping a short extension when there is one.
func truncateBasename(name string, maxBytes int) string {
	if len(name) <= maxBytes {
		return name
	}
	stem, ext := splitBasenameExtension(name)
	if len(ext) > maxKeptExtensionBytes {
		stem, ext = name, ""
	}
	return truncateUTF8(stem, maxBytes-len(ext)) + ext
}

// truncateUTF8 returns the longest prefix of s that fits in maxBytes bytes
// without splitting a multi-byte character.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// resolveDefaultDownloadPath returns a reserved output target inside dir for
// an untrusted filename. The name is reduced with safeDownloadBasename, then
// given a numeric suffix if any existing entry in dir (file, directory, or
// link, compared case-insensitively) already uses it, and it is published
// without replacing an entry that appears later.
func resolveDefaultDownloadPath(dir, untrustedName, fallback string) (*outputTarget, error) {
	r, err := newOutputNameReserver(dir, "")
	if err != nil {
		return nil, fmt.Errorf("%w; pass --output instead", err)
	}
	return reservedOutputTarget(r, safeDownloadBasename(untrustedName, fallback)), nil
}
