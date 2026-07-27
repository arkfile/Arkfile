package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicOutputPublishesCompletedFile(t *testing.T) {
	directory := t.TempDir()
	finalPath := filepath.Join(directory, "download.bin")
	if err := os.WriteFile(finalPath, []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := writeAtomicOutput(finalPath, func(file *os.File) error {
		_, err := file.Write([]byte("complete"))
		return err
	}); err != nil {
		t.Fatalf("writeAtomicOutput returned error: %v", err)
	}

	data, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "complete" {
		t.Fatalf("published data = %q, want complete", data)
	}
	assertNoAtomicOutputTemps(t, directory)
}

func TestWriteAtomicOutputFailurePreservesDestination(t *testing.T) {
	directory := t.TempDir()
	finalPath := filepath.Join(directory, "download.bin")
	if err := os.WriteFile(finalPath, []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}

	expectedErr := errors.New("interrupted")
	err := writeAtomicOutput(finalPath, func(file *os.File) error {
		if _, err := file.Write([]byte("partial plaintext")); err != nil {
			return err
		}
		return expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("writeAtomicOutput error = %v, want %v", err, expectedErr)
	}

	data, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "previous" {
		t.Fatalf("destination changed on failure: %q", data)
	}
	assertNoAtomicOutputTemps(t, directory)
}

func TestWriteAtomicOutputFailureLeavesNoDestination(t *testing.T) {
	directory := t.TempDir()
	finalPath := filepath.Join(directory, "download.bin")

	err := writeAtomicOutput(finalPath, func(file *os.File) error {
		if _, err := file.Write([]byte("partial plaintext")); err != nil {
			return err
		}
		return errors.New("interrupted")
	})
	if err == nil {
		t.Fatal("writeAtomicOutput unexpectedly succeeded")
	}
	if _, statErr := os.Stat(finalPath); !os.IsNotExist(statErr) {
		t.Fatalf("destination exists after failure: %v", statErr)
	}
	assertNoAtomicOutputTemps(t, directory)
}

func assertNoAtomicOutputTemps(t *testing.T, directory string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, ".arkfile-output-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary output files remain: %v", matches)
	}
}
