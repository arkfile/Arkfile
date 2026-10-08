//go:build linux

package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

func TestLoadUserSecretMasterUsesDedicatedPage(t *testing.T) {
	t.Cleanup(SecureZeroUserSecretMaster)

	master := bytes.Repeat([]byte{0xA5}, 32)
	path := filepath.Join(t.TempDir(), "user-secret-master.bin")
	if err := os.WriteFile(path, master, 0400); err != nil {
		t.Fatalf("write master: %v", err)
	}

	if err := loadUserSecretMasterFrom(path); err != nil {
		t.Fatalf("load master: %v", err)
	}

	if !bytes.Equal(userSecretMasterKey, master) {
		t.Fatalf("loaded key does not match file contents")
	}
	if len(userSecretMasterPage) != os.Getpagesize() {
		t.Fatalf("expected a dedicated page of %d bytes, got %d", os.Getpagesize(), len(userSecretMasterPage))
	}
	if addr := uintptr(unsafe.Pointer(&userSecretMasterKey[0])); addr%uintptr(os.Getpagesize()) != 0 {
		t.Fatalf("key is not page-aligned: %#x", addr)
	}
	if &userSecretMasterKey[0] != &userSecretMasterPage[0] {
		t.Fatalf("key does not start at the dedicated page")
	}
	if err := mAdviseDontDump(userSecretMasterPage); err != nil {
		t.Fatalf("MADV_DONTDUMP on dedicated page failed: %v", err)
	}

	subkey, err := DeriveUserSecretSubkey([]byte("test_purpose"))
	if err != nil {
		t.Fatalf("derive subkey: %v", err)
	}
	expected, err := DeriveUserSecretSubkeyFromMaster(master, []byte("test_purpose"))
	if err != nil {
		t.Fatalf("derive expected subkey: %v", err)
	}
	if !bytes.Equal(subkey, expected) {
		t.Fatalf("subkey from page-backed master differs from heap-derived subkey")
	}

	SecureZeroUserSecretMaster()
	if userSecretMasterKey != nil || userSecretMasterPage != nil || userSecretMasterMlocked {
		t.Fatalf("secure zero did not reset master key state")
	}
}

func TestLoadUserSecretMasterShortFileFails(t *testing.T) {
	SecureZeroUserSecretMaster()
	t.Cleanup(SecureZeroUserSecretMaster)

	path := filepath.Join(t.TempDir(), "user-secret-master.bin")
	if err := os.WriteFile(path, []byte("short"), 0400); err != nil {
		t.Fatalf("write master: %v", err)
	}

	if err := loadUserSecretMasterFrom(path); err == nil {
		t.Fatalf("expected error for short master key file")
	}
	if userSecretMasterKey != nil || userSecretMasterPage != nil {
		t.Fatalf("failed load must not install key state")
	}
}

func TestSetUserSecretMasterForTestReleasesDedicatedPage(t *testing.T) {
	t.Cleanup(SecureZeroUserSecretMaster)

	path := filepath.Join(t.TempDir(), "user-secret-master.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x11}, 32), 0400); err != nil {
		t.Fatalf("write master: %v", err)
	}
	if err := loadUserSecretMasterFrom(path); err != nil {
		t.Fatalf("load master: %v", err)
	}

	heapKey := bytes.Repeat([]byte{0x22}, 32)
	SetUserSecretMasterForTest(heapKey)
	if userSecretMasterPage != nil {
		t.Fatalf("dedicated page was not released")
	}
	if !bytes.Equal(userSecretMasterKey, heapKey) {
		t.Fatalf("test key was not installed")
	}
}
