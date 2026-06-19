package auth

import (
	"crypto/rand"
	"fmt"
	"io"
	"strconv"

	"github.com/84adam/Arkfile/crypto"
)

// JWTRotationResult reports the active versions after a rotation.
type JWTRotationResult struct {
	TempVersion int `json:"temp_version"`
	FullVersion int `json:"full_version"`
}

// RotateJWTSigningKeys generates the next version for both the temp and full
// signing tiers, points each active-version metadata row at the new version,
// and reloads the in-memory key rings so the new keys take effect immediately.
// Previous versions remain in the verification set for the overlap window so
// that tokens already issued continue to validate until they expire.
func RotateJWTSigningKeys() (JWTRotationResult, error) {
	var result JWTRotationResult

	km, err := crypto.GetKeyManager()
	if err != nil {
		return result, fmt.Errorf("failed to get KeyManager: %w", err)
	}

	tempVersion, err := rotateJWTTier(km, jwtTempKeyIDPrefix, jwtTempActiveVersionKeyID)
	if err != nil {
		return result, fmt.Errorf("temp-tier rotation failed: %w", err)
	}
	fullVersion, err := rotateJWTTier(km, jwtFullKeyIDPrefix, jwtFullActiveVersionKeyID)
	if err != nil {
		return result, fmt.Errorf("full-tier rotation failed: %w", err)
	}

	if err := ReloadJWTKeys(); err != nil {
		return result, fmt.Errorf("rotation stored but in-memory reload failed: %w", err)
	}

	result.TempVersion = tempVersion
	result.FullVersion = fullVersion
	return result, nil
}

func rotateJWTTier(km *crypto.KeyManager, keyIDPrefix, activeVersionKeyID string) (int, error) {
	versions, err := listJWTVersions(km, keyIDPrefix)
	if err != nil {
		return 0, err
	}
	next := 1
	if len(versions) > 0 {
		next = versions[len(versions)-1] + 1
	}

	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return 0, fmt.Errorf("failed to generate new JWT signing seed: %w", err)
	}
	if err := km.StoreKey(keyIDPrefix+strconv.Itoa(next), jwtKeyType, seed); err != nil {
		return 0, fmt.Errorf("failed to store new JWT signing key: %w", err)
	}
	if err := km.StoreKey(activeVersionKeyID, jwtKeyType, []byte(strconv.Itoa(next))); err != nil {
		return 0, fmt.Errorf("failed to update active JWT version pointer: %w", err)
	}
	return next, nil
}

// RetireJWTKeyVersion removes a superseded signing key version from both tiers.
// It refuses to delete the currently active version of either tier. Call this
// only after the overlap window has elapsed (no unexpired token can still be
// signed under the retired version).
func RetireJWTKeyVersion(version int) error {
	if version <= 0 {
		return fmt.Errorf("version must be a positive integer")
	}

	km, err := crypto.GetKeyManager()
	if err != nil {
		return fmt.Errorf("failed to get KeyManager: %w", err)
	}

	tempActive, fullActive, err := ActiveJWTKeyVersions()
	if err != nil {
		return err
	}
	if version == tempActive || version == fullActive {
		return fmt.Errorf("refusing to retire active JWT version %d", version)
	}

	if err := km.DeleteKey(jwtTempKeyIDPrefix + strconv.Itoa(version)); err != nil {
		return fmt.Errorf("failed to delete temp-tier version %d: %w", version, err)
	}
	if err := km.DeleteKey(jwtFullKeyIDPrefix + strconv.Itoa(version)); err != nil {
		return fmt.Errorf("failed to delete full-tier version %d: %w", version, err)
	}

	if err := ReloadJWTKeys(); err != nil {
		return fmt.Errorf("version retired but in-memory reload failed: %w", err)
	}
	return nil
}
