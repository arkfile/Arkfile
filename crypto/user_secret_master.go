package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
)

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var (
	tier3MasterKey []byte
	tier3Mlocked   bool
)

const (
	// Default path for Tier-3 user secret master
	Tier3MasterKeyPath = "/opt/arkfile/etc/keys/user-secret-master.bin"
)

// LoadTier3Master loads and memory-hardens the Tier-3 master key.
// It is intended to run once at startup.
func LoadTier3Master() error {
	// Read Master Key
	file, err := os.Open(Tier3MasterKeyPath)
	if err != nil {
		return fmt.Errorf("failed to open Tier-3 master key file: %w", err)
	}
	defer file.Close()

	key := make([]byte, 32)
	n, err := io.ReadFull(file, key)
	if err != nil {
		return fmt.Errorf("failed to read Tier-3 master key (got %d bytes): %w", n, err)
	}

	// Disable core dumps for the entire process (defense-in-depth / MADV_DONTDUMP / PR_SET_DUMPABLE)
	// prctl(PR_SET_DUMPABLE, 0)
	if err := prctlDisableCoredump(); err != nil {
		// Log warning but do not fail-closed in pure dev/unprivileged environments
		fmt.Fprintf(os.Stderr, "Warning: failed to set PR_SET_DUMPABLE=0: %v\n", err)
	}

	// Try to mlock the key to prevent swapping to disk
	if err := mLockMemory(key); err == nil {
		tier3Mlocked = true
	} else {
		fmt.Fprintf(os.Stderr, "Warning: failed to mlock Tier-3 master key: %v\n", err)
	}

	// Mark page as MADV_DONTDUMP to exclude it from core dumps
	// Note: unix.Madvise requires passing a pointer offset or the whole slice
	if len(key) > 0 {
		// Madvise requires slice page alignment but since key is small, madvising key slice is best-effort.
		// On Linux we can pass the slice directly.
		err := mAdviseDontDump(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to madvise MADV_DONTDUMP on Tier-3 master key: %v\n", err)
		}
	}

	tier3MasterKey = key
	return nil
}

// DeriveTier3Subkey derives a context-specific key from the loaded Tier-3 master using HKDF-Expand.
func DeriveTier3Subkey(purpose []byte) ([]byte, error) {
	if len(tier3MasterKey) == 0 {
		return nil, fmt.Errorf("Tier-3 master key is not initialized")
	}
	return DeriveTier3SubkeyFromMaster(tier3MasterKey, purpose)
}

// DeriveTier3SubkeyFromMaster derives a context-specific Tier-3 subkey from an explicit master.
func DeriveTier3SubkeyFromMaster(master []byte, purpose []byte) ([]byte, error) {
	if len(master) != 32 {
		return nil, fmt.Errorf("Tier-3 master key must be 32 bytes, got %d", len(master))
	}
	if len(purpose) == 0 {
		return nil, fmt.Errorf("Tier-3 subkey purpose cannot be empty")
	}

	info := append([]byte("ARKFILE_TIER3:"), purpose...)
	hkdfReader := hkdf.Expand(sha256.New, master, info)

	subkey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, subkey); err != nil {
		return nil, fmt.Errorf("failed to expand Tier-3 subkey: %w", err)
	}

	return subkey, nil
}

// ReadTier3MasterFile reads the Tier-3 master key from the given path.
func ReadTier3MasterFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open Tier-3 master key file: %w", err)
	}
	defer file.Close()

	key := make([]byte, 32)
	n, err := io.ReadFull(file, key)
	if err != nil {
		return nil, fmt.Errorf("failed to read Tier-3 master key (got %d bytes): %w", n, err)
	}
	return key, nil
}

// WriteTier3MasterFile atomically writes a Tier-3 master key to path via a temp file in the same directory.
func WriteTier3MasterFile(path string, key []byte, uid, gid int) error {
	if len(key) != 32 {
		return fmt.Errorf("Tier-3 master key must be 32 bytes, got %d", len(key))
	}

	dir := filepath.Dir(path)
	tempPath := filepath.Join(dir, ".user-secret-master."+randomHex(8)+".tmp")

	if err := os.WriteFile(tempPath, key, 0400); err != nil {
		return fmt.Errorf("failed to write temp Tier-3 master key: %w", err)
	}
	if uid >= 0 && gid >= 0 {
		_ = os.Chown(tempPath, uid, gid)
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to install Tier-3 master key: %w", err)
	}
	return nil
}

// SecureZeroTier3 zeroes out tier3MasterKey from memory (intended for graceful shutdown)
func SecureZeroTier3() {
	if len(tier3MasterKey) > 0 {
		if tier3Mlocked {
			_ = mUnlockMemory(tier3MasterKey)
			tier3Mlocked = false
		}
		// Zero memory
		for i := range tier3MasterKey {
			tier3MasterKey[i] = 0
		}
		tier3MasterKey = nil
	}
}

// SetTier3MasterForTest allows unit tests to set a mock/temp master key
func SetTier3MasterForTest(key []byte) {
	tier3MasterKey = key
}
