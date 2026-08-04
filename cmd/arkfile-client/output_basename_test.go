package main

import "testing"

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
