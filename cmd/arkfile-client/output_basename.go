package main

import (
	"fmt"
	"path/filepath"
	"strings"
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
