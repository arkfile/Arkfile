package handlers

import (
	"fmt"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/logging"
)

// Unauthorized flood detection and progressive rate limiting.
// Tracks 401/404 responses per entity across all endpoints in a rolling
// 10-minute window. Entities that exceed thresholds receive progressive
// penalties (5s -> 30s -> 2m -> 10m -> 1h). Penalty tiers persist across
// window resets and decay after periods of silence.
//
// This catches vulnerability scanners probing nonexistent paths (e.g.
// WordPress .php files, webshell paths) that no per-endpoint rate limiter
// would detect because the paths don't match any registered route.

const (
	floodWindow       = 10 * time.Minute // rolling window for counting hits
	floodCleanupEvery = 1 * time.Minute  // cleanup interval for stale entries

	// Tier thresholds (window hits that trigger each tier)
	floodTier1Threshold = 10 // 10+ hits in window: 5 second penalty
	floodTier2Threshold = 20 // 20+ hits in window: 30 second penalty
	floodTier3Threshold = 40 // 40+ hits in window: 2 minute penalty
	floodTier4Threshold = 60 // 60+ hits in window: 10 minute penalty
	floodTier5Threshold = 80 // 80+ hits in window: 1 hour penalty

	// Tier decay: after this much silence, peakTier drops by 1
	tierDecayPeriod = 1 * time.Hour
	// Full reset after this much silence
	tierFullResetPeriod = 6 * time.Hour
)

// floodTracker tracks unauthorized response hits for a single entity
type floodTracker struct {
	windowHits   int       // hits in current rolling window (resets when window expires)
	peakTier     int       // highest penalty tier reached (persists across windows, decays over time)
	firstHit     time.Time // start of current window
	lastHit      time.Time // most recent bad response timestamp
	penaltyUntil time.Time // entity blocked until this time
}

// floodGuardService is the global in-memory tracker for unauthorized flood detection
type floodGuardService struct {
	mu       sync.Mutex
	trackers map[string]*floodTracker // keyed by entity ID
}

var defaultFloodGuard *floodGuardService

func init() {
	defaultFloodGuard = newFloodGuardService()
	go defaultFloodGuard.cleanupLoop()
}

// newFloodGuardService creates a new flood guard instance (also used by tests)
func newFloodGuardService() *floodGuardService {
	return &floodGuardService{
		trackers: make(map[string]*floodTracker),
	}
}

// cleanupLoop removes stale entries periodically
func (g *floodGuardService) cleanupLoop() {
	ticker := time.NewTicker(floodCleanupEvery)
	defer ticker.Stop()
	for range ticker.C {
		g.cleanup()
	}
}

// cleanup removes entries that have no active penalty and have been silent
// long enough for a full tier reset
func (g *floodGuardService) cleanup() {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for entityID, t := range g.trackers {
		penaltyExpired := t.penaltyUntil.IsZero() || now.After(t.penaltyUntil)
		fullyDecayed := now.Sub(t.lastHit) >= tierFullResetPeriod
		if penaltyExpired && fullyDecayed {
			delete(g.trackers, entityID)
		}
	}
}

// tierForHits returns the penalty tier for a given hit count
func tierForHits(hits int) int {
	switch {
	case hits >= floodTier5Threshold:
		return 5
	case hits >= floodTier4Threshold:
		return 4
	case hits >= floodTier3Threshold:
		return 3
	case hits >= floodTier2Threshold:
		return 2
	case hits >= floodTier1Threshold:
		return 1
	default:
		return 0
	}
}

// penaltyForTier returns the penalty duration for a given tier
func penaltyForTier(tier int) time.Duration {
	switch tier {
	case 1:
		return 5 * time.Second
	case 2:
		return 30 * time.Second
	case 3:
		return 2 * time.Minute
	case 4:
		return 10 * time.Minute
	case 5:
		return 1 * time.Hour
	default:
		return 0
	}
}

// decayTier applies tier decay based on silence duration.
// Must be called with g.mu held.
func decayTier(t *floodTracker, now time.Time) {
	if t.peakTier == 0 {
		return
	}

	silenceDuration := now.Sub(t.lastHit)

	// Full reset after extended silence
	if silenceDuration >= tierFullResetPeriod {
		t.peakTier = 0
		return
	}

	// Progressive decay: drop one tier per decay period of silence
	tiersToDecay := int(silenceDuration / tierDecayPeriod)
	if tiersToDecay > 0 {
		t.peakTier -= tiersToDecay
		if t.peakTier < 0 {
			t.peakTier = 0
		}
	}
}

// RecordUnauthorizedHit records a 401/404 response for this entity and returns
// the penalty duration (0 = no penalty, >0 = entity should be blocked)
func (g *floodGuardService) RecordUnauthorizedHit(entityID string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	t, exists := g.trackers[entityID]

	if !exists {
		t = &floodTracker{
			firstHit: now,
		}
		g.trackers[entityID] = t
	}

	// If the window has expired, reset window hits and apply tier decay
	if !t.lastHit.IsZero() && now.Sub(t.firstHit) > floodWindow {
		decayTier(t, now)
		t.windowHits = 0
		t.firstHit = now
	}

	t.windowHits++
	t.lastHit = now

	// Determine the tier from current window hits
	currentTier := tierForHits(t.windowHits)

	// The effective tier is the max of current window tier and remembered peak tier
	effectiveTier := currentTier
	if t.peakTier > effectiveTier {
		effectiveTier = t.peakTier
	}

	// Update peak tier if we've escalated
	if currentTier > t.peakTier {
		t.peakTier = currentTier
	}

	// If the entity just re-entered after a window reset with a remembered peak tier,
	// apply the peak tier penalty on the first hit
	if effectiveTier > 0 && t.windowHits == 1 && t.peakTier > 0 {
		penalty := penaltyForTier(effectiveTier)
		t.penaltyUntil = now.Add(penalty)

		// Log at first hit in new window when remembered tier applies
		if logging.InfoLogger != nil {
			logging.InfoLogger.Printf("Flood guard: entity %s re-entered at remembered tier %d, penalty %v",
				entityID, effectiveTier, penalty)
		}

		return penalty
	}

	// No penalty below tier 1
	if effectiveTier == 0 {
		return 0
	}

	penalty := penaltyForTier(effectiveTier)
	t.penaltyUntil = now.Add(penalty)

	// Log security event at tier threshold crossings (exact threshold values only)
	if t.windowHits == floodTier1Threshold ||
		t.windowHits == floodTier2Threshold ||
		t.windowHits == floodTier3Threshold ||
		t.windowHits == floodTier4Threshold ||
		t.windowHits == floodTier5Threshold {

		var eventType logging.SecurityEventType
		if effectiveTier >= 3 {
			eventType = logging.EventEndpointAbuse
		} else {
			eventType = logging.EventSuspiciousPattern
		}

		logging.LogSecurityEventWithEntityID(
			eventType,
			entityID,
			map[string]interface{}{
				"window_hits":     t.windowHits,
				"effective_tier":  effectiveTier,
				"peak_tier":       t.peakTier,
				"penalty_seconds": int(penalty.Seconds()),
				"detection_type":  "unauthorized_flood",
			},
		)
	}

	return penalty
}

// IsBlocked checks if an entity is currently blocked by the flood guard.
// Returns (blocked, retryAfterSeconds).
func (g *floodGuardService) IsBlocked(entityID string) (bool, int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	t, exists := g.trackers[entityID]
	if !exists {
		return false, 0
	}

	if t.penaltyUntil.IsZero() {
		return false, 0
	}

	now := time.Now()
	if now.After(t.penaltyUntil) {
		return false, 0
	}

	retryAfter := int(t.penaltyUntil.Sub(now).Seconds())
	if retryAfter < 1 {
		retryAfter = 1
	}
	return true, retryAfter
}

// isAuthenticatedRequest checks whether the request carries a valid JWT token.
// Authenticated users who hit 404s (e.g. deleted file) should not be penalized.
func isAuthenticatedRequest(c echo.Context) bool {
	return c.Get("user") != nil
}

// isFloodGuardExemptPath returns true for paths that should never trigger
// flood guard tracking (health probes, static assets)
func isFloodGuardExemptPath(path string) bool {
	exemptPaths := []string{
		"/healthz",
		"/readyz",
	}
	for _, p := range exemptPaths {
		if path == p {
			return true
		}
	}
	return false
}

// FloodGuardMiddleware detects and rate-limits entities that generate excessive
// 401/404 responses (vulnerability scanners, path probers). It wraps the
// request handler: checking for active blocks before processing, and recording
// bad responses after processing.
func FloodGuardMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		path := c.Request().URL.Path
		if isFloodGuardExemptPath(path) {
			return next(c)
		}

		entityID := logging.GetOrCreateEntityID(c)

		// PRE-CHECK: Is this entity currently blocked?
		blocked, retryAfter := defaultFloodGuard.IsBlocked(entityID)
		if blocked {
			// Record the hit even while blocked (escalates the penalty tier)
			defaultFloodGuard.RecordUnauthorizedHit(entityID)
			return ServeRateLimitPage(c, retryAfter,
				fmt.Sprintf("Too many unauthorized requests. Try again in %d seconds.", retryAfter))
		}

		// Process the request
		err := next(c)

		// POST-CHECK: Was the response a 401 or 404 from an unauthenticated request?
		// Echo returns HTTP errors as *echo.HTTPError from next(c), not via c.Response().Status
		// (the response status is still 200 at this point in the middleware chain).
		if err != nil && !isAuthenticatedRequest(c) {
			if httpErr, ok := err.(*echo.HTTPError); ok {
				if httpErr.Code == 401 || httpErr.Code == 404 {
					defaultFloodGuard.RecordUnauthorizedHit(entityID)
				}
			}
		}

		return err
	}
}
