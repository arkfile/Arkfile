package auth

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

func verifyFullTokenAnyKey(tokenString string) (*jwt.Token, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithAudience(AudienceAPI),
		jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired(),
	)
	return parseEdDSAAnyKey(parser, tokenString, GetJWTFullVerificationKeys())
}

func verifyTempMFATokenAnyKey(tokenString string) (*jwt.Token, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithAudience(AudienceMFA),
		jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired(),
	)
	return parseEdDSAAnyKey(parser, tokenString, GetJWTTempVerificationKeys())
}

// runHandlerWithBearer drives a pre-built echo handler with an optional Bearer
// token and returns the recorded status plus the handler error. A nil error
// with code 200 means the middleware accepted the token and ran next.
func runHandlerWithBearer(handler echo.HandlerFunc, token string) (int, error) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := handler(c)
	return rec.Code, err
}

func TestJWTKeyRotation_OverlapAndRetire(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTKeys(); err != nil {
		t.Fatal(err)
	}

	_, fullV0, err := ActiveJWTKeyVersions()
	if err != nil {
		t.Fatal(err)
	}

	tokA, _, err := GenerateFullAccessToken("rotation-tester")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyFullTokenAnyKey(tokA); err != nil {
		t.Fatalf("token A should verify before rotation: %v", err)
	}

	res, err := RotateJWTSigningKeys()
	if err != nil {
		t.Fatal(err)
	}
	if res.FullVersion != fullV0+1 {
		t.Fatalf("expected full version %d after rotation, got %d", fullV0+1, res.FullVersion)
	}

	if len(GetJWTFullVerificationKeys()) < 2 {
		t.Fatal("expected at least two full verification keys during overlap")
	}

	// Token issued under the old key must still verify during the overlap.
	if _, err := verifyFullTokenAnyKey(tokA); err != nil {
		t.Fatalf("token A (old key) must still verify during overlap: %v", err)
	}

	// Token issued after rotation is signed under the new active key.
	tokB, _, err := GenerateFullAccessToken("rotation-tester")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyFullTokenAnyKey(tokB); err != nil {
		t.Fatalf("token B (new key) should verify: %v", err)
	}

	// After retiring the old version, tokens signed under it stop verifying
	// while the new active token continues to work.
	if err := RetireJWTKeyVersion(fullV0); err != nil {
		t.Fatalf("retire failed: %v", err)
	}
	if _, err := verifyFullTokenAnyKey(tokA); err == nil {
		t.Fatal("token A must fail verification after its key version is retired")
	}
	if _, err := verifyFullTokenAnyKey(tokB); err != nil {
		t.Fatalf("token B must still verify after retiring the old version: %v", err)
	}
}

func TestJWTKeyRotation_RefusesToRetireActiveVersion(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTKeys(); err != nil {
		t.Fatal(err)
	}
	_, fullActive, err := ActiveJWTKeyVersions()
	if err != nil {
		t.Fatal(err)
	}
	if err := RetireJWTKeyVersion(fullActive); err == nil {
		t.Fatal("expected retiring the active version to be refused")
	}
}

// TestJWTKeyRotation_TempTierOverlap asserts the temp tier rotates and keeps
// the previous version in the verification set, exactly like the full tier.
func TestJWTKeyRotation_TempTierOverlap(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTKeys(); err != nil {
		t.Fatal(err)
	}
	tempV0, _, err := ActiveJWTKeyVersions()
	if err != nil {
		t.Fatal(err)
	}

	oldTemp, _, err := GenerateTemporaryMFAToken("temp-rotation-user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTempMFATokenAnyKey(oldTemp); err != nil {
		t.Fatalf("temp token should verify before rotation: %v", err)
	}

	res, err := RotateJWTSigningKeys()
	if err != nil {
		t.Fatal(err)
	}
	if res.TempVersion != tempV0+1 {
		t.Fatalf("expected temp version %d after rotation, got %d", tempV0+1, res.TempVersion)
	}
	if len(GetJWTTempVerificationKeys()) < 2 {
		t.Fatal("expected at least two temp verification keys during overlap")
	}

	if _, err := verifyTempMFATokenAnyKey(oldTemp); err != nil {
		t.Fatalf("temp token (old key) must still verify during overlap: %v", err)
	}
	newTemp, _, err := GenerateTemporaryMFAToken("temp-rotation-user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTempMFATokenAnyKey(newTemp); err != nil {
		t.Fatalf("new temp token should verify: %v", err)
	}
}

// TestJWTMiddleware_AcceptsTokensAcrossRotation exercises the real
// JWTMiddleware stack (not the unexported helper). The middleware is built
// BEFORE rotation to prove key resolution is per-request: a token signed under
// the new active key is accepted by the same handler instance, and a token
// signed under the old key still passes during the overlap window.
func TestJWTMiddleware_AcceptsTokensAcrossRotation(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTKeys(); err != nil {
		t.Fatal(err)
	}

	okHandler := func(c echo.Context) error { return c.String(http.StatusOK, "ok") }
	handler := JWTMiddleware()(okHandler)

	oldTok, _, err := GenerateFullAccessToken("mw-rotation-user")
	if err != nil {
		t.Fatal(err)
	}
	if code, err := runHandlerWithBearer(handler, oldTok); err != nil || code != http.StatusOK {
		t.Fatalf("old token before rotation: code=%d err=%v", code, err)
	}

	if _, err := RotateJWTSigningKeys(); err != nil {
		t.Fatal(err)
	}

	if code, err := runHandlerWithBearer(handler, oldTok); err != nil || code != http.StatusOK {
		t.Fatalf("old token during overlap (pre-built middleware): code=%d err=%v", code, err)
	}

	newTok, _, err := GenerateFullAccessToken("mw-rotation-user")
	if err != nil {
		t.Fatal(err)
	}
	if code, err := runHandlerWithBearer(handler, newTok); err != nil || code != http.StatusOK {
		t.Fatalf("new token after rotation: code=%d err=%v", code, err)
	}

	// A temp-tier token must still be rejected by the full-tier middleware,
	// before and after rotation (wrong signing key AND wrong audience).
	tempTok, _, err := GenerateTemporaryMFAToken("mw-rotation-user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runHandlerWithBearer(handler, tempTok); err == nil {
		t.Fatal("temp token must be rejected by JWTMiddleware after rotation")
	}
}

// TestMFAResetJWTMiddleware_AcrossRotation covers the dual-path reset
// middleware: it must keep accepting a full-tier token AND a reset-tier token
// that were issued before a rotation.
func TestMFAResetJWTMiddleware_AcrossRotation(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTKeys(); err != nil {
		t.Fatal(err)
	}

	okHandler := func(c echo.Context) error { return c.String(http.StatusOK, "ok") }
	handler := MFAResetJWTMiddleware()(okHandler)

	fullTok, _, err := GenerateFullAccessToken("reset-rotation-user")
	if err != nil {
		t.Fatal(err)
	}
	resetTok, _, err := GenerateTemporaryResetToken("reset-rotation-user")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := RotateJWTSigningKeys(); err != nil {
		t.Fatal(err)
	}

	if code, err := runHandlerWithBearer(handler, fullTok); err != nil || code != http.StatusOK {
		t.Fatalf("full token (old key) must pass MFAResetJWTMiddleware during overlap: code=%d err=%v", code, err)
	}
	if code, err := runHandlerWithBearer(handler, resetTok); err != nil || code != http.StatusOK {
		t.Fatalf("reset token (old key) must pass MFAResetJWTMiddleware during overlap: code=%d err=%v", code, err)
	}
}

// TestParseEitherTierToken_AcrossRotation covers the revocation/logout path,
// which must resolve a token signed under either tier across a rotation.
func TestParseEitherTierToken_AcrossRotation(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTKeys(); err != nil {
		t.Fatal(err)
	}

	fullTok, _, err := GenerateFullAccessToken("logout-rotation-user")
	if err != nil {
		t.Fatal(err)
	}
	tempTok, _, err := GenerateTemporaryMFAToken("logout-rotation-user")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := RotateJWTSigningKeys(); err != nil {
		t.Fatal(err)
	}

	if _, err := parseEitherTierToken(fullTok); err != nil {
		t.Fatalf("full token (old key) must still parse for revocation during overlap: %v", err)
	}
	if _, err := parseEitherTierToken(tempTok); err != nil {
		t.Fatalf("temp token (old key) must still parse for revocation during overlap: %v", err)
	}
}

// TestParseEdDSAClaimsAnyFullKey_AcrossRotation covers the exported helper used
// by export-token validation: a full-tier-signed token with custom claims must
// keep validating after a rotation while the old version is in the set.
func TestParseEdDSAClaimsAnyFullKey_AcrossRotation(t *testing.T) {
	ResetKeysForTest()
	if err := LoadJWTKeys(); err != nil {
		t.Fatal(err)
	}

	// Mint a custom-claims token signed with the (pre-rotation) active full key.
	claims := &Claims{
		Username: "export-rotation-user",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Audience:  []string{AudienceExport},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "export-token-id",
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(GetJWTFullPrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := RotateJWTSigningKeys(); err != nil {
		t.Fatal(err)
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithAudience(AudienceExport),
		jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired(),
	)
	if _, err := ParseEdDSAClaimsAnyFullKey(parser, signed, &Claims{}); err != nil {
		t.Fatalf("export-style token (old key) must validate during overlap: %v", err)
	}
}

// TestLoadJWTRing_FallsBackToMaxVersionWhenMetadataMissing verifies that with
// no active-version metadata row present, loadJWTRing selects the highest
// version and accepts every present version for verification. Uses a private
// key-id namespace so it never collides with the real JWT keys.
func TestLoadJWTRing_FallsBackToMaxVersionWhenMetadataMissing(t *testing.T) {
	km, err := crypto.GetKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "jwt_ringtest_missingmeta_v"
	const activeKeyID = "jwt_ringtest_missingmeta_active"
	defer cleanupRingTestKeys(km, prefix, activeKeyID, 1, 3)

	storeRingSeed(t, km, prefix+"1", 0x11)
	storeRingSeed(t, km, prefix+"3", 0x33) // intentional gap at v2

	ring, err := loadJWTRing(prefix, activeKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if ring.activeVersion != 3 {
		t.Fatalf("expected active version 3 (max present), got %d", ring.activeVersion)
	}
	if len(ring.verifyPubs) != 2 {
		t.Fatalf("expected 2 verification keys, got %d", len(ring.verifyPubs))
	}
}

// TestLoadJWTRing_FallsBackWhenMetadataPointsToMissingVersion verifies that an
// active-version metadata row pointing at a non-existent version is ignored in
// favor of the highest present version.
func TestLoadJWTRing_FallsBackWhenMetadataPointsToMissingVersion(t *testing.T) {
	km, err := crypto.GetKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "jwt_ringtest_badmeta_v"
	const activeKeyID = "jwt_ringtest_badmeta_active"
	defer cleanupRingTestKeys(km, prefix, activeKeyID, 1, 2)

	storeRingSeed(t, km, prefix+"1", 0x21)
	storeRingSeed(t, km, prefix+"2", 0x22)
	if err := km.StoreKey(activeKeyID, jwtKeyType, []byte("5")); err != nil {
		t.Fatal(err)
	}

	ring, err := loadJWTRing(prefix, activeKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if ring.activeVersion != 2 {
		t.Fatalf("expected fallback to active version 2, got %d", ring.activeVersion)
	}
}

// TestLoadJWTRing_RespectsValidMetadata verifies that a valid active-version
// row selects the corresponding signing key even when it is not the highest
// present version.
func TestLoadJWTRing_RespectsValidMetadata(t *testing.T) {
	km, err := crypto.GetKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "jwt_ringtest_goodmeta_v"
	const activeKeyID = "jwt_ringtest_goodmeta_active"
	defer cleanupRingTestKeys(km, prefix, activeKeyID, 1, 2)

	seed1 := storeRingSeed(t, km, prefix+"1", 0x31)
	storeRingSeed(t, km, prefix+"2", 0x32)
	if err := km.StoreKey(activeKeyID, jwtKeyType, []byte("1")); err != nil {
		t.Fatal(err)
	}

	ring, err := loadJWTRing(prefix, activeKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if ring.activeVersion != 1 {
		t.Fatalf("expected active version 1 from metadata, got %d", ring.activeVersion)
	}
	wantPub := ed25519.NewKeyFromSeed(seed1).Public().(ed25519.PublicKey)
	if !ring.signingPub.Equal(wantPub) {
		t.Fatal("active signing key does not match the version named by metadata")
	}
}

func storeRingSeed(t *testing.T, km *crypto.KeyManager, keyID string, fill byte) []byte {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = fill
	}
	if err := km.StoreKey(keyID, jwtKeyType, seed); err != nil {
		t.Fatal(err)
	}
	return seed
}

func cleanupRingTestKeys(km *crypto.KeyManager, prefix, activeKeyID string, versions ...int) {
	for _, v := range versions {
		_ = km.DeleteKey(prefix + strconv.Itoa(v))
	}
	_ = km.DeleteKey(activeKeyID)
}
