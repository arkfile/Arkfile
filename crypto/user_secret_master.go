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
	userSecretMasterKey     []byte
	userSecretMasterMlocked bool
)

const (
	// Default path for the user-secret master
	UserSecretMasterPath = "/opt/arkfile/etc/keys/user-secret-master.bin"
)

// LoadUserSecretMaster loads and memory-hardens the user-secret master key.
// It is intended to run once at startup.
func LoadUserSecretMaster() error {
	// Read Master Key
	file, err := os.Open(UserSecretMasterPath)
	if err != nil {
		return fmt.Errorf("failed to open user-secret master key file: %w", err)
	}
	defer file.Close()

	key := make([]byte, 32)
	n, err := io.ReadFull(file, key)
	if err != nil {
		return fmt.Errorf("failed to read user-secret master key (got %d bytes): %w", n, err)
	}

	// Disable core dumps for the entire process (defense-in-depth / MADV_DONTDUMP / PR_SET_DUMPABLE)
	// prctl(PR_SET_DUMPABLE, 0)
	if err := prctlDisableCoredump(); err != nil {
		// Log warning but do not fail-closed in pure dev/unprivileged environments
		fmt.Fprintf(os.Stderr, "Warning: failed to set PR_SET_DUMPABLE=0: %v\n", err)
	}

	// Try to mlock the key to prevent swapping to disk
	if err := mLockMemory(key); err == nil {
		userSecretMasterMlocked = true
	} else {
		fmt.Fprintf(os.Stderr, "Warning: failed to mlock user-secret master key: %v\n", err)
	}

	// Mark page as MADV_DONTDUMP to exclude it from core dumps
	// Note: unix.Madvise requires passing a pointer offset or the whole slice
	if len(key) > 0 {
		// Madvise requires slice page alignment but since key is small, madvising key slice is best-effort.
		// On Linux we can pass the slice directly.
		err := mAdviseDontDump(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to madvise MADV_DONTDUMP on user-secret master key: %v\n", err)
		}
	}

	userSecretMasterKey = key
	return nil
}

// DeriveUserSecretSubkey derives a context-specific key from the loaded user-secret master using HKDF-Expand.
func DeriveUserSecretSubkey(purpose []byte) ([]byte, error) {
	if len(userSecretMasterKey) == 0 {
		return nil, fmt.Errorf("user-secret master key is not initialized")
	}
	return DeriveUserSecretSubkeyFromMaster(userSecretMasterKey, purpose)
}

// DeriveUserSecretSubkeyFromMaster derives a context-specific user-secret subkey from an explicit master.
func DeriveUserSecretSubkeyFromMaster(master []byte, purpose []byte) ([]byte, error) {
	if len(master) != 32 {
		return nil, fmt.Errorf("user-secret master key must be 32 bytes, got %d", len(master))
	}
	if len(purpose) == 0 {
		return nil, fmt.Errorf("user-secret subkey purpose cannot be empty")
	}

	info := append([]byte("ARKFILE_USER_SECRET:"), purpose...)
	hkdfReader := hkdf.Expand(sha256.New, master, info)

	subkey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, subkey); err != nil {
		return nil, fmt.Errorf("failed to expand user-secret subkey: %w", err)
	}

	return subkey, nil
}

// ReadUserSecretMasterFile reads the user-secret master key from the given path.
func ReadUserSecretMasterFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open user-secret master key file: %w", err)
	}
	defer file.Close()

	key := make([]byte, 32)
	n, err := io.ReadFull(file, key)
	if err != nil {
		return nil, fmt.Errorf("failed to read user-secret master key (got %d bytes): %w", n, err)
	}
	return key, nil
}

// WriteUserSecretMasterFile atomically writes a user-secret master key to path via a temp file in the same directory.
func WriteUserSecretMasterFile(path string, key []byte, uid, gid int) error {
	if len(key) != 32 {
		return fmt.Errorf("user-secret master key must be 32 bytes, got %d", len(key))
	}

	dir := filepath.Dir(path)
	tempPath := filepath.Join(dir, ".user-secret-master."+randomHex(8)+".tmp")

	if err := os.WriteFile(tempPath, key, 0400); err != nil {
		return fmt.Errorf("failed to write temp user-secret master key: %w", err)
	}
	if uid >= 0 && gid >= 0 {
		_ = os.Chown(tempPath, uid, gid)
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to install user-secret master key: %w", err)
	}
	return nil
}

// SecureZeroUserSecretMaster zeroes out userSecretMasterKey from memory (intended for graceful shutdown)
func SecureZeroUserSecretMaster() {
	if len(userSecretMasterKey) > 0 {
		if userSecretMasterMlocked {
			_ = mUnlockMemory(userSecretMasterKey)
			userSecretMasterMlocked = false
		}
		// Zero memory
		for i := range userSecretMasterKey {
			userSecretMasterKey[i] = 0
		}
		userSecretMasterKey = nil
	}
}

// SetUserSecretMasterForTest allows unit tests to set a mock/temp master key
func SetUserSecretMasterForTest(key []byte) {
	userSecretMasterKey = key
}
