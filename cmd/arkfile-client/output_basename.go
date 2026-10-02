package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// Keeps sanitized names well under the common 255-byte filename limit so
	// collision suffixes such as "-12" still fit.
	maxSafeBasenameBytes = 200
	// Longer trailing "extensions" are treated as part of the name when truncating.
	maxKeptExtensionBytes = 16
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

func nextAvailableBasename(desiredName string, taken map[string]struct{}) string {
	stem, ext := splitBasenameExtension(desiredName)
	candidate := stem + ext
	if _, exists := taken[candidate]; !exists {
		return candidate
	}
	for n := 1; ; n++ {
		candidate = fmt.Sprintf("%s-%d%s", stem, n, ext)
		if _, exists := taken[candidate]; !exists {
			return candidate
		}
	}
}

func reserveBasenames(items []struct {
	Key      string
	Filename string
}, alreadyTaken []string) map[string]string {
	taken := make(map[string]struct{}, len(alreadyTaken)+len(items))
	for _, name := range alreadyTaken {
		if name != "" {
			taken[name] = struct{}{}
		}
	}
	reserved := make(map[string]string, len(items))
	for _, item := range items {
		filename := item.Filename
		if filename == "" {
			filename = item.Key
		}
		name := nextAvailableBasename(filename, taken)
		taken[name] = struct{}{}
		reserved[item.Key] = name
	}
	return reserved
}

// safeDownloadBasename reduces an untrusted filename, such as the one a sharer
// placed in a share envelope, to a single path element: no directory parts, no
// control or bidirectional characters, no leading dots or dashes (so it cannot
// be ".", "..", a hidden file, or read as a command-line option), and a bounded
// length. The fallback gets the same treatment when nothing usable remains.
func safeDownloadBasename(name, fallback string) string {
	if safe := sanitizeUntrustedBasename(name); safe != "" {
		return safe
	}
	if safe := sanitizeUntrustedBasename(fallback); safe != "" {
		return safe
	}
	return "download"
}

func sanitizeUntrustedBasename(name string) string {
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
		return r == '.' || r == '-' || unicode.IsSpace(r)
	})
	name = strings.TrimRightFunc(name, unicode.IsSpace)
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

// resolveDefaultDownloadPath returns a path inside dir for an untrusted
// filename. The name is reduced with safeDownloadBasename, then given a numeric
// suffix if any existing entry in dir (file, directory, or link) already uses
// it, so a default download never replaces existing data.
func resolveDefaultDownloadPath(dir, untrustedName, fallback string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("cannot list directory %q to choose a safe output name; pass --output instead: %w", dir, err)
	}
	taken := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		taken[entry.Name()] = struct{}{}
	}
	name := nextAvailableBasename(safeDownloadBasename(untrustedName, fallback), taken)
	return filepath.Join(dir, name), nil
}
