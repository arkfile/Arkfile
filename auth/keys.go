package auth

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/arkfile/Arkfile/crypto"
)

// Two-tier, versioned JWT signing keys.
//
// The temp-tier key signs short-lived tokens issued by OPAQUE finalize that
// carry aud=arkfile-mfa and requires_mfa=true. Those tokens are only valid
// at /api/mfa/{setup,verify,auth}, validated by MFAJWTMiddleware against
// the temp public key(s).
//
// The full-tier key signs full-access tokens issued after a successful MFA
// step (or via /api/refresh on an existing full session). Those tokens carry
// aud=arkfile-api and requires_mfa=false and are validated by JWTMiddleware
// against the full public key(s).
//
// Two separate keys make audience confusion structurally impossible:
// presenting a temp token to JWTMiddleware fails signature verification
// before any claim is inspected, and vice versa. The audience claim is
// enforced as defense in depth in ParseTokenFunc.
//
// Each tier is versioned. Tokens are always signed with the active version,
// but every version still present in system_keys is accepted for
// verification. Rotation introduces a new active version while the previous
// version stays in the verification set until any token signed under it has
// expired, after which the old version can be retired. The active version is
// recorded as a metadata row in system_keys.
const (
	jwtKeyType = "jwt"

	jwtTempKeyIDPrefix = "jwt_signing_key_temp_v"
	jwtFullKeyIDPrefix = "jwt_signing_key_full_v"

	jwtTempActiveVersionKeyID = "jwt_signing_active_version_temp"
	jwtFullActiveVersionKeyID = "jwt_signing_active_version_full"
)

// jwtKeyRing holds the active signing keypair plus every public key still
// accepted for verification during a rotation overlap window. verifyPubs is
// ordered with the active public key first for a fast common-case match.
type jwtKeyRing struct {
	activeVersion int
	signingPriv   ed25519.PrivateKey
	signingPub    ed25519.PublicKey
	verifyPubs    []ed25519.PublicKey
}

var (
	jwtKeysMu   sync.RWMutex
	jwtTempRing *jwtKeyRing
	jwtFullRing *jwtKeyRing
)

// LoadJWTTempKeys ensures the temp-tier key ring is loaded from system_keys.
func LoadJWTTempKeys() error {
	return ensureRingLoaded(&jwtTempRing, jwtTempKeyIDPrefix, jwtTempActiveVersionKeyID)
}

// LoadJWTFullKeys ensures the full-tier key ring is loaded from system_keys.
func LoadJWTFullKeys() error {
	return ensureRingLoaded(&jwtFullRing, jwtFullKeyIDPrefix, jwtFullActiveVersionKeyID)
}

// LoadJWTKeys initializes both tiers. Kept for callers that just need to
// ensure the JWT subsystem is ready at startup.
func LoadJWTKeys() error {
	if err := LoadJWTTempKeys(); err != nil {
		return err
	}
	return LoadJWTFullKeys()
}

// ReloadJWTKeys reloads both tiers from system_keys, picking up any rotation
// (new active version, newly added or retired versions) without a restart.
func ReloadJWTKeys() error {
	tempRing, err := loadJWTRing(jwtTempKeyIDPrefix, jwtTempActiveVersionKeyID)
	if err != nil {
		return err
	}
	fullRing, err := loadJWTRing(jwtFullKeyIDPrefix, jwtFullActiveVersionKeyID)
	if err != nil {
		return err
	}

	jwtKeysMu.Lock()
	jwtTempRing = tempRing
	jwtFullRing = fullRing
	jwtKeysMu.Unlock()
	return nil
}

func ensureRingLoaded(ring **jwtKeyRing, keyIDPrefix, activeVersionKeyID string) error {
	jwtKeysMu.RLock()
	loaded := *ring != nil
	jwtKeysMu.RUnlock()
	if loaded {
		return nil
	}

	loadedRing, err := loadJWTRing(keyIDPrefix, activeVersionKeyID)
	if err != nil {
		return err
	}

	jwtKeysMu.Lock()
	if *ring == nil {
		*ring = loadedRing
	}
	jwtKeysMu.Unlock()
	return nil
}

// loadJWTRing reads all versions for a tier from system_keys, determines the
// active version from the metadata row (falling back to the highest present
// version), and builds the signing keypair and verification set.
func loadJWTRing(keyIDPrefix, activeVersionKeyID string) (*jwtKeyRing, error) {
	km, err := crypto.GetKeyManager()
	if err != nil {
		return nil, fmt.Errorf("failed to get KeyManager: %w", err)
	}

	versions, err := listJWTVersions(km, keyIDPrefix)
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		// Fresh deployment: bootstrap version 1.
		if _, err := km.GetOrGenerateKey(keyIDPrefix+"1", jwtKeyType, 32); err != nil {
			return nil, fmt.Errorf("failed to bootstrap JWT key %s1: %w", keyIDPrefix, err)
		}
		versions = []int{1}
	}

	activeVersion := versions[len(versions)-1]
	if raw, err := km.GetKey(activeVersionKeyID, jwtKeyType); err == nil {
		if n, perr := strconv.Atoi(strings.TrimSpace(string(raw))); perr == nil && containsInt(versions, n) {
			activeVersion = n
		}
	}

	pubByVersion := make(map[int]ed25519.PublicKey, len(versions))
	ring := &jwtKeyRing{activeVersion: activeVersion}
	for _, v := range versions {
		seed, err := km.GetKey(keyIDPrefix+strconv.Itoa(v), jwtKeyType)
		if err != nil {
			return nil, fmt.Errorf("failed to load JWT key %s%d: %w", keyIDPrefix, v, err)
		}
		if len(seed) != 32 {
			return nil, fmt.Errorf("invalid JWT key seed length for %s%d: expected 32 bytes, got %d", keyIDPrefix, v, len(seed))
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		pubByVersion[v] = pub
		if v == activeVersion {
			ring.signingPriv = priv
			ring.signingPub = pub
		}
	}
	if ring.signingPriv == nil {
		return nil, fmt.Errorf("active JWT version %d not found for %s", activeVersion, keyIDPrefix)
	}

	// Active key first, then the remaining versions in ascending order.
	ring.verifyPubs = append(ring.verifyPubs, ring.signingPub)
	for _, v := range versions {
		if v == activeVersion {
			continue
		}
		ring.verifyPubs = append(ring.verifyPubs, pubByVersion[v])
	}
	return ring, nil
}

func listJWTVersions(km *crypto.KeyManager, keyIDPrefix string) ([]int, error) {
	ids, err := km.ListKeyIDs(keyIDPrefix)
	if err != nil {
		return nil, err
	}
	var versions []int
	for _, id := range ids {
		suffix := strings.TrimPrefix(id, keyIDPrefix)
		if n, err := strconv.Atoi(suffix); err == nil {
			versions = append(versions, n)
		}
	}
	sort.Ints(versions)
	return versions, nil
}

func containsInt(xs []int, target int) bool {
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}

// GetJWTTempPrivateKey returns the active Ed25519 private key for temp tokens.
func GetJWTTempPrivateKey() ed25519.PrivateKey {
	if err := LoadJWTTempKeys(); err != nil {
		panic(fmt.Sprintf("JWT temp private key not available: %v", err))
	}
	jwtKeysMu.RLock()
	defer jwtKeysMu.RUnlock()
	return jwtTempRing.signingPriv
}

// GetJWTTempPublicKey returns the active Ed25519 public key for temp tokens.
func GetJWTTempPublicKey() ed25519.PublicKey {
	if err := LoadJWTTempKeys(); err != nil {
		panic(fmt.Sprintf("JWT temp public key not available: %v", err))
	}
	jwtKeysMu.RLock()
	defer jwtKeysMu.RUnlock()
	return jwtTempRing.signingPub
}

// GetJWTFullPrivateKey returns the active Ed25519 private key for full tokens.
func GetJWTFullPrivateKey() ed25519.PrivateKey {
	if err := LoadJWTFullKeys(); err != nil {
		panic(fmt.Sprintf("JWT full private key not available: %v", err))
	}
	jwtKeysMu.RLock()
	defer jwtKeysMu.RUnlock()
	return jwtFullRing.signingPriv
}

// GetJWTFullPublicKey returns the active Ed25519 public key for full tokens.
func GetJWTFullPublicKey() ed25519.PublicKey {
	if err := LoadJWTFullKeys(); err != nil {
		panic(fmt.Sprintf("JWT full public key not available: %v", err))
	}
	jwtKeysMu.RLock()
	defer jwtKeysMu.RUnlock()
	return jwtFullRing.signingPub
}

// GetJWTTempVerificationKeys returns every temp-tier public key currently
// accepted for verification, active version first.
func GetJWTTempVerificationKeys() []ed25519.PublicKey {
	if err := LoadJWTTempKeys(); err != nil {
		panic(fmt.Sprintf("JWT temp verification keys not available: %v", err))
	}
	jwtKeysMu.RLock()
	defer jwtKeysMu.RUnlock()
	out := make([]ed25519.PublicKey, len(jwtTempRing.verifyPubs))
	copy(out, jwtTempRing.verifyPubs)
	return out
}

// GetJWTFullVerificationKeys returns every full-tier public key currently
// accepted for verification, active version first.
func GetJWTFullVerificationKeys() []ed25519.PublicKey {
	if err := LoadJWTFullKeys(); err != nil {
		panic(fmt.Sprintf("JWT full verification keys not available: %v", err))
	}
	jwtKeysMu.RLock()
	defer jwtKeysMu.RUnlock()
	out := make([]ed25519.PublicKey, len(jwtFullRing.verifyPubs))
	copy(out, jwtFullRing.verifyPubs)
	return out
}

// ActiveJWTKeyIDs returns the system_keys key ids of the active temp and full
// signing versions. Useful for health monitoring that must follow rotation.
func ActiveJWTKeyIDs() (tempKeyID, fullKeyID string, err error) {
	tempVersion, fullVersion, err := ActiveJWTKeyVersions()
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf("%s%d", jwtTempKeyIDPrefix, tempVersion),
		fmt.Sprintf("%s%d", jwtFullKeyIDPrefix, fullVersion), nil
}

// ActiveJWTKeyVersions reports the active signing version of each tier.
func ActiveJWTKeyVersions() (tempVersion, fullVersion int, err error) {
	if err := LoadJWTKeys(); err != nil {
		return 0, 0, err
	}
	jwtKeysMu.RLock()
	defer jwtKeysMu.RUnlock()
	return jwtTempRing.activeVersion, jwtFullRing.activeVersion, nil
}

// ResetKeysForTest clears the loaded key rings for testing purposes.
// DO NOT USE IN PRODUCTION.
func ResetKeysForTest() {
	jwtKeysMu.Lock()
	jwtTempRing = nil
	jwtFullRing = nil
	jwtKeysMu.Unlock()
}
