package logging

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/arkfile/Arkfile/crypto"
	"golang.org/x/crypto/hkdf"
)

// EntityIDService provides privacy-preserving entity identification
// using HMAC with daily-rotating keys derived from a master secret.
//
// Entity IDs are computed from composite inputs to distinguish different
// clients behind shared IP addresses (NAT, VPN, corporate networks):
//   - Authenticated requests use the username as input
//   - Unauthenticated requests use IP + coarse User-Agent/Accept-Language buckets
type EntityIDService struct {
	masterSecret   []byte
	keyCache       map[string][]byte // Cache for derived daily keys
	cacheMutex     sync.RWMutex
	rotationPeriod time.Duration
	retentionDays  int
}

// EntityIDConfig configures the entity ID service
type EntityIDConfig struct {
	RotationPeriod    time.Duration `json:"rotation_period"`    // 24 * time.Hour
	RetentionDays     int           `json:"retention_days"`     // 90
	CleanupInterval   time.Duration `json:"cleanup_interval"`   // 24 * time.Hour
	EmergencyRotation bool          `json:"emergency_rotation"` // true
}

// EntityIDInput holds the composite inputs for entity ID generation.
// For authenticated requests, set Username. For unauthenticated requests,
// provide IP and HTTP header signals to distinguish clients behind shared IPs.
type EntityIDInput struct {
	IP             net.IP // Client IP address
	UserAgent      string // HTTP User-Agent header
	AcceptLanguage string // HTTP Accept-Language header
	Username       string // Authenticated username (empty for anonymous requests)
}

// NewEntityIDService creates a new entity ID service with the given configuration
func NewEntityIDService(config EntityIDConfig) (*EntityIDService, error) {
	service := &EntityIDService{
		keyCache:       make(map[string][]byte),
		rotationPeriod: config.RotationPeriod,
		retentionDays:  config.RetentionDays,
	}

	// Generate or load master secret
	if err := service.initializeMasterSecret(); err != nil {
		return nil, fmt.Errorf("failed to initialize master secret: %w", err)
	}

	// Start cleanup goroutine
	go service.cleanupRoutine(config.CleanupInterval)

	return service, nil
}

// GetCompositeEntityID returns a privacy-preserving entity identifier from
// composite inputs. This is the primary method for entity ID generation.
//
// For authenticated requests (Username is set): HMAC(daily_key, "user:" + username)
// For anonymous requests: HMAC(daily_key, "anon:" + IP + "|" + uaBucket + "|" + langBucket)
//
// The "user:"/"anon:" prefix prevents collisions between the two input domains.
//
// The HMAC output is returned at full width (32 bytes / 64 hex characters).
// The previous 16-character (64-bit) truncation created a non-trivial birthday
// collision risk across a day window: two unrelated anonymous visitors sharing
// an entity ID also share a rate-limit bucket and an enumeration counter, which
// lets an attacker burn a neighbor's budget or hide inside a noisy shared
// bucket. Full width drops that collision probability to effectively zero for
// any realistic daily population at negligible storage cost (the field is TEXT).
//
// Browser fingerprint signals (User-Agent, Accept-Language) are reduced to
// coarse, low-entropy buckets before entering the HMAC. The intent of the
// composite input is NAT disambiguation, not fingerprint harvesting: a raw
// User-Agent carries platform, OS version, CPU architecture and exact build
// numbers, and a raw Accept-Language list with q-values is similarly
// near-unique, so including them verbatim would bake a strong day-stable
// tracker into the persisted pseudonym. Coarse bucketing preserves enough
// signal to distinguish a few co-located browsers behind one NAT while keeping
// each recipient inside a large anonymity set (e.g. all Tor Browser / Firefox
// users on the same IP collapse to one bucket).
func (e *EntityIDService) GetCompositeEntityID(input EntityIDInput) string {
	timeWindow := e.GetCurrentTimeWindow()
	dailyKey := e.getDailyKey(timeWindow)

	mac := hmac.New(sha256.New, dailyKey)

	if input.Username != "" {
		// Authenticated: use username for precise per-user identification
		mac.Write([]byte("user:"))
		mac.Write([]byte(input.Username))
	} else if input.IP != nil {
		// Anonymous: combine IP with coarse browser buckets for NAT disambiguation
		mac.Write([]byte("anon:"))
		mac.Write([]byte(input.IP.String()))
		mac.Write([]byte("|"))
		mac.Write([]byte(userAgentBucket(input.UserAgent)))
		mac.Write([]byte("|"))
		mac.Write([]byte(acceptLanguageBucket(input.AcceptLanguage)))
	} else {
		return "unknown"
	}

	return hex.EncodeToString(mac.Sum(nil))
}

// userAgentBucket reduces a raw User-Agent string to a coarse browser-family
// bucket, dropping platform, OS version, CPU architecture and exact build
// numbers. This preserves minimal NAT-disambiguation signal (one bucket per
// major browser family) while keeping each recipient inside a large anonymity
// set. Tor Browser is detected explicitly and bucketed alongside Firefox so
// its distinct UA does not become a per-user pseudonym.
func userAgentBucket(ua string) string {
	if ua == "" {
		return "unknown"
	}
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "tor browser") || strings.Contains(lower, "torbrowser"):
		return "firefox" // Tor Browser intentionally collapses into the Firefox set
	case strings.Contains(lower, "firefox"):
		return "firefox"
	case strings.Contains(lower, "edg/"):
		return "chrome"
	case strings.Contains(lower, "opera") || strings.Contains(lower, "opr/"):
		return "chrome"
	case strings.Contains(lower, "chrome") || strings.Contains(lower, "crios") || strings.Contains(lower, "chromium"):
		return "chrome"
	case strings.Contains(lower, "safari") || strings.Contains(lower, "webkit"):
		return "safari"
	default:
		return "other"
	}
}

// acceptLanguageBucket reduces a raw Accept-Language header to its primary
// language tag only (e.g. "en-US,en;q=0.9,de;q=0.7" -> "en"), dropping the
// full locale list and q-values which are themselves a fingerprint vector.
// If the header is empty or unparseable, returns "unknown" so the input is
// still deterministic.
func acceptLanguageBucket(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return "unknown"
	}
	// Take the first comma-separated entry, then the subtag before any '-'.
	first := header
	if idx := strings.Index(first, ","); idx >= 0 {
		first = first[:idx]
	}
	first = strings.TrimSpace(first)
	if first == "" {
		return "unknown"
	}
	if idx := strings.Index(first, "-"); idx > 0 {
		first = first[:idx]
	}
	first = strings.ToLower(strings.TrimSpace(first))
	if first == "" || len(first) > 8 {
		// Defensive: malformed or absurdly long tag -> unknown rather than
		// letting a crafted header become a unique bucket.
		return "unknown"
	}
	return first
}

// GetEntityID returns a privacy-preserving entity identifier for the given IP address.
// This is the legacy method that uses IP-only input. Prefer GetCompositeEntityID
// for new code to get better disambiguation behind shared IPs.
func (e *EntityIDService) GetEntityID(ip net.IP) string {
	return e.GetCompositeEntityID(EntityIDInput{IP: ip})
}

// GetCurrentTimeWindow returns the current time window identifier (YYYY-MM-DD format)
func (e *EntityIDService) GetCurrentTimeWindow() string {
	return time.Now().UTC().Format("2006-01-02")
}

// GetTimeWindowForTime returns the time window identifier for a specific time
func (e *EntityIDService) GetTimeWindowForTime(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// CleanupOldWindows removes old time window data beyond retention period
func (e *EntityIDService) CleanupOldWindows(retentionDays int) error {
	cutoffDate := time.Now().UTC().AddDate(0, 0, -retentionDays)
	cutoffWindow := e.GetTimeWindowForTime(cutoffDate)

	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	// Remove old keys from cache
	for window := range e.keyCache {
		if window < cutoffWindow {
			delete(e.keyCache, window)
		}
	}

	InfoLogger.Printf("Cleaned up entity ID keys older than %s", cutoffWindow)
	return nil
}

// GetMasterSecretHash returns a hash of the master secret for health monitoring
// This allows verification of key accessibility without exposing the secret
func (e *EntityIDService) GetMasterSecretHash() string {
	if e.masterSecret == nil {
		return ""
	}
	hash := sha256.Sum256(e.masterSecret)
	return hex.EncodeToString(hash[:8]) // First 8 bytes for identification
}

// getDailyKey derives or retrieves the daily key for the given time window
func (e *EntityIDService) getDailyKey(timeWindow string) []byte {
	e.cacheMutex.RLock()
	if key, exists := e.keyCache[timeWindow]; exists {
		e.cacheMutex.RUnlock()
		return key
	}
	e.cacheMutex.RUnlock()

	// Derive new key
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	// Double-check after acquiring write lock
	if key, exists := e.keyCache[timeWindow]; exists {
		return key
	}

	// Derive key using HKDF-SHA256
	key := make([]byte, 32)
	info := []byte("entity_id")
	salt := []byte(timeWindow)

	hkdf := hkdf.New(sha256.New, e.masterSecret, salt, info)
	if _, err := hkdf.Read(key); err != nil {
		// Fallback to direct HMAC if HKDF fails
		mac := hmac.New(sha256.New, e.masterSecret)
		mac.Write(salt)
		mac.Write(info)
		key = mac.Sum(nil)
	}

	// Cache the derived key
	e.keyCache[timeWindow] = key

	return key
}

// initializeMasterSecret loads or generates the master secret using KeyManager
func (e *EntityIDService) initializeMasterSecret() error {
	km, err := crypto.GetKeyManager()
	if err != nil {
		return fmt.Errorf("failed to get KeyManager: %w", err)
	}

	// Retrieve or generate the 32-byte master key. The key_id is the type
	// context for envelope wrapping derivation; see crypto.EntityIDMasterKeyID.
	key, err := km.GetOrGenerateKey(crypto.EntityIDMasterKeyID, crypto.EntityIDKeyType, 32)
	if err != nil {
		return fmt.Errorf("failed to get/generate entity ID master key: %w", err)
	}

	if len(key) != 32 {
		return fmt.Errorf("invalid entity ID master key length: expected 32 bytes, got %d", len(key))
	}

	e.masterSecret = key
	return nil
}

// cleanupRoutine runs periodic cleanup of old keys and cache entries
func (e *EntityIDService) cleanupRoutine(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if err := e.CleanupOldWindows(e.retentionDays); err != nil {
			ErrorLogger.Printf("Entity ID cleanup failed: %v", err)
		}
	}
}

// ValidateEntityID checks if an entity ID has the expected format.
//
// Entity IDs are full-width HMAC-SHA256 digests: 32 bytes encoded as 64 hex
// characters. The previous 16-character (64-bit) truncation is no longer used;
// see GetCompositeEntityID for the collision-resistance rationale.
func ValidateEntityID(entityID string) bool {
	if len(entityID) != 64 {
		return false
	}

	// Check if it's valid hex
	_, err := hex.DecodeString(entityID)
	return err == nil
}

// Global entity ID service instance
var DefaultEntityIDService *EntityIDService

// InitializeEntityIDService initializes the global entity ID service
func InitializeEntityIDService(config EntityIDConfig) error {
	var err error
	DefaultEntityIDService, err = NewEntityIDService(config)
	if err != nil {
		return fmt.Errorf("failed to initialize entity ID service: %w", err)
	}

	InfoLogger.Printf("Entity ID service initialized with daily rotation and composite input support")
	return nil
}

// GetCompositeEntityIDForRequest generates an entity ID from an HTTP request,
// using IP plus coarse User-Agent and Accept-Language buckets for anonymous
// disambiguation. See GetCompositeEntityID for the bucketing rationale.
func GetCompositeEntityIDForRequest(ip net.IP, r *http.Request) string {
	if DefaultEntityIDService == nil {
		return "uninitialized"
	}
	input := EntityIDInput{
		IP:             ip,
		UserAgent:      r.Header.Get("User-Agent"),
		AcceptLanguage: r.Header.Get("Accept-Language"),
	}
	return DefaultEntityIDService.GetCompositeEntityID(input)
}

// GetOrCreateEntityID extracts the client IP and HTTP signals from the Echo
// context and returns a composite entity ID. For authenticated requests where
// a username is available in the JWT claims, the username is used instead of
// IP-based identification for more precise per-user rate limiting.
//
// Client IP source priority (for anonymous requests):
//  1. X-Arkfile-Peer header, set by Caddy via `header_up X-Arkfile-Peer
//     {http.request.remote.host}`. Caddy strips any incoming X-Forwarded-For
//     / X-Real-IP / Forwarded headers before reverse-proxying, so this header
//     cannot be spoofed by a remote client. This is the production path.
//  2. c.RealIP() as fallback. With main.go pinning e.IPExtractor =
//     ExtractIPDirect, c.RealIP() returns the kernel transport peer (which
//     in production is 127.0.0.1 from Caddy, but in dev-without-Caddy is the
//     real local client). Never trusts X-Forwarded-For under any topology.
//
// The raw IP is HMAC'd through the daily-rotating EntityID layer before any
// persistence -- it never appears in logs, the DB, or any audit trail.
func GetOrCreateEntityID(c interface{}) string {
	// Type assertion for Echo context
	type ContextWithRealIP interface {
		RealIP() string
	}
	type ContextWithRequest interface {
		Request() *http.Request
	}
	type ContextWithGet interface {
		Get(string) interface{}
	}

	if DefaultEntityIDService == nil {
		return "uninitialized"
	}

	var input EntityIDInput

	// Try to extract username from JWT claims in context (authenticated requests)
	if ctx, ok := c.(ContextWithGet); ok {
		if user := ctx.Get("user"); user != nil {
			// The JWT middleware stores claims; try to extract username
			if claims, ok := extractUsernameFromClaims(user); ok && claims != "" {
				input.Username = claims
			}
		}
	}

	// Extract IP address. Prefer the Caddy-controlled X-Arkfile-Peer header
	// so EntityID buckets reflect the real public client behind the reverse
	// proxy. Fall back to c.RealIP() for dev-without-Caddy.
	if ctx, ok := c.(ContextWithRequest); ok {
		if r := ctx.Request(); r != nil {
			if peer := r.Header.Get("X-Arkfile-Peer"); peer != "" {
				if ip := net.ParseIP(strings.TrimSpace(peer)); ip != nil {
					input.IP = ip
				}
			}
		}
	}
	if input.IP == nil {
		if ctx, ok := c.(ContextWithRealIP); ok {
			clientIP := ctx.RealIP()
			if clientIP != "" {
				input.IP = net.ParseIP(clientIP)
			}
		}
	}

	// Extract HTTP headers for anonymous requests (only needed if no username)
	if input.Username == "" {
		if ctx, ok := c.(ContextWithRequest); ok {
			r := ctx.Request()
			if r != nil {
				input.UserAgent = r.Header.Get("User-Agent")
				input.AcceptLanguage = r.Header.Get("Accept-Language")
			}
		}
	}

	// Generate composite entity ID
	if input.Username != "" || input.IP != nil {
		return DefaultEntityIDService.GetCompositeEntityID(input)
	}

	return "unknown"
}

// extractUsernameFromClaims attempts to extract a username from a JWT token
// stored in the Echo context. The JWT middleware stores a *jwt.Token under
// the "user" key. We extract claims without importing the auth package
// (which would cause an import cycle) by using interface assertions on the
// token's Claims field.
func extractUsernameFromClaims(user interface{}) (string, bool) {
	// The JWT middleware stores *jwt.Token which has a public Claims field.
	// We use a structural interface to access it without importing jwt directly.
	type tokenWithClaims interface {
		GetClaims() interface{}
	}

	// jwt.Token has a public Claims field, not a method. Use reflection-free
	// approach: check if the Claims value has a Username field via interface.
	type claimsWithUsername struct {
		Username string
	}

	// Try to access via map claims (jwt.MapClaims)
	if m, ok := user.(map[string]interface{}); ok {
		if username, exists := m["username"]; exists {
			if u, ok := username.(string); ok && u != "" {
				return u, true
			}
		}
	}

	// The *jwt.Token stores Claims as an interface. Since we cannot import
	// the jwt or auth package here, we use a structural type assertion to
	// access the Valid bool and then try to read Username from the claims.
	// This works because Go's reflect-free interface matching checks methods.

	// Approach: define a minimal interface that *jwt.Token satisfies
	// jwt.Token has no getter methods for Claims, it's a public field.
	// We must use reflect to access the Claims.Username field.

	// Use lightweight reflect to extract Username from the token's claims
	return extractUsernameReflect(user)
}

// extractUsernameReflect uses fmt.Sprintf-based type introspection to extract
// the Username from JWT token claims without importing auth or jwt packages.
// The JWT token type is *jwt.Token{Claims: *auth.Claims{Username: "..."}}.
func extractUsernameReflect(user interface{}) (string, bool) {
	// Use fmt.Sprintf with %+v to get a string representation of the struct
	// and parse out the Username field. This is a pragmatic approach that
	// avoids importing reflect while still extracting the needed data.
	// The performance cost is negligible since this only runs once per request.

	repr := fmt.Sprintf("%+v", user)

	// Look for "Username:" in the string representation
	const marker = "Username:"
	idx := findSubstring(repr, marker)
	if idx < 0 {
		return "", false
	}

	// Extract the value after "Username:"
	rest := repr[idx+len(marker):]

	// Skip leading whitespace
	start := 0
	for start < len(rest) && rest[start] == ' ' {
		start++
	}
	rest = rest[start:]

	// Find the end of the username value (next space or closing brace)
	end := 0
	for end < len(rest) && rest[end] != ' ' && rest[end] != '}' && rest[end] != ',' {
		end++
	}

	username := rest[:end]
	if username != "" {
		return username, true
	}

	return "", false
}

// findSubstring returns the index of needle in haystack, or -1 if not found
func findSubstring(haystack, needle string) int {
	if len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
