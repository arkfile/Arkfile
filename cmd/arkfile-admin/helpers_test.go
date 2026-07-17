package main

import "testing"

func TestParseStorageLimit(t *testing.T) {
	bytes, err := parseStorageLimit("10GB")
	if err != nil {
		t.Fatalf("parseStorageLimit: %v", err)
	}
	if bytes != 10*1024*1024*1024 {
		t.Fatalf("unexpected bytes: %d", bytes)
	}
}

func TestLooksLikeDollarsAndCents(t *testing.T) {
	if !looksLikeDollarsAndCents("19.99") {
		t.Fatal("expected valid price")
	}
	if looksLikeDollarsAndCents("-1") {
		t.Fatal("expected invalid negative price")
	}
}

func TestEmptyOrValue(t *testing.T) {
	if got := emptyOrValue("", "fallback"); got != "fallback" {
		t.Fatalf("got %q", got)
	}
	if got := emptyOrValue("value", "fallback"); got != "value" {
		t.Fatalf("got %q", got)
	}
}
