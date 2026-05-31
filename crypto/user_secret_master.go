package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

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

// DeriveTier3Subkey derives a context-specific key from the Tier-3 master using HKDF-Expand.
func DeriveTier3Subkey(purpose []byte) ([]byte, error) {
	if len(tier3MasterKey) == 0 {
		// If Tier-3 master is not initialized, we fall back gracefully only if not in production.
		// However, for clean fail-closed posture, let's return an explicit error.
		return nil, fmt.Errorf("Tier-3 master key is not initialized")
	}

	info := append([]byte("ARKFILE_TIER3:"), purpose...)
	hkdfReader := hkdf.Expand(sha256.New, tier3MasterKey, info)

	subkey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, subkey); err != nil {
		return nil, fmt.Errorf("failed to expand Tier-3 subkey: %w", err)
	}

	return subkey, nil
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
