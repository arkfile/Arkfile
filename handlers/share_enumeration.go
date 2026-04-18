package handlers

import (
	"fmt"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/logging"
)

// Share enumeration detection and rate limiting.
// Tracks unique share-ID 404s per entity across ALL share IDs in a 10-minute
// sliding window. This catches attackers iterating through different share IDs
// (which the per-share-ID rate limiter in rate_limiting.go does not detect).

const (
	enumerationWindow       = 10 * time.Minute
	enumerationCleanupEvery = 1 * time.Minute

	// Progressive penalty thresholds (unique 404s in window)
	enumThresholdDelay5s  = 4  // 4-5 hits: 5 second delay
	enumThresholdDelay30s = 6  // 6-8 hits: 30 second delay
	enumThresholdBlock2m  = 9  // 9-15 hits: 2 minute block
	enumThresholdBlock10m = 16 // 16-31 hits: 10 minute block
	enumThresholdBlock1h  = 32 // 32+ hits: 1 hour block
)

// enumerationTracker tracks share-not-found hits for a single entity
type enumerationTracker struct {
	uniqueShareIDs map[string]bool // Set of unique share ID prefixes that returned 404
	totalHits      int             // Total 404 count (may exceed unique count for repeated IDs)
	firstSeen      time.Time       // When the first 404 in this window was recorded
	lastSeen       time.Time       // When the most recent 404 was recorded
	penaltyUntil   time.Time       // If set, entity is blocked until this time
}

// shareEnumerationGuard is the global in-memory tracker for share enumeration
type shareEnumerationGuard struct {
	mu       sync.Mutex
	trackers map[string]*enumerationTracker // keyed by entity ID
}

var enumGuard *shareEnumerationGuard

func init() {
	enumGuard = &shareEnumerationGuard{
		trackers: make(map[string]*enumerationTracker),
	}
	go enumGuard.cleanupLoop()
}

// cleanupLoop removes stale entries every minute
func (g *shareEnumerationGuard) cleanupLoop() {
	ticker := time.NewTicker(enumerationCleanupEvery)
	defer ticker.Stop()
	for range ticker.C {
		g.cleanup()
	}
}

// cleanup removes entries that have expired their window and have no active penalty
func (g *shareEnumerationGuard) cleanup() {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for entityID, t := range g.trackers {
		windowExpired := now.Sub(t.lastSeen) > enumerationWindow
		penaltyExpired := t.penaltyUntil.IsZero() || now.After(t.penaltyUntil)
		if windowExpired && penaltyExpired {
			delete(g.trackers, entityID)
		}
	}
}

// RecordShareNotFound records a 404 for this entity and returns the penalty delay
// (0 = no penalty, >0 = entity should be delayed/blocked for this duration)
func (g *shareEnumerationGuard) RecordShareNotFound(entityID, shareIDPrefix string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	t, exists := g.trackers[entityID]

	if !exists {
		t = &enumerationTracker{
			uniqueShareIDs: make(map[string]bool),
			firstSeen:      now,
		}
		g.trackers[entityID] = t
	}

	// If the window has expired and no active penalty, reset the tracker
	if now.Sub(t.lastSeen) > enumerationWindow && (t.penaltyUntil.IsZero() || now.After(t.penaltyUntil)) {
		t.uniqueShareIDs = make(map[string]bool)
		t.totalHits = 0
		t.firstSeen = now
		t.penaltyUntil = time.Time{}
	}

	t.uniqueShareIDs[shareIDPrefix] = true
	t.totalHits++
	t.lastSeen = now

	uniqueCount := len(t.uniqueShareIDs)

	// Determine penalty based on unique 404 count
	var penalty time.Duration
	var eventType logging.SecurityEventType

	switch {
	case uniqueCount >= enumThresholdBlock1h:
		penalty = 1 * time.Hour
		eventType = logging.EventEndpointAbuse
	case uniqueCount >= enumThresholdBlock10m:
		penalty = 10 * time.Minute
		eventType = logging.EventEndpointAbuse
	case uniqueCount >= enumThresholdBlock2m:
		penalty = 2 * time.Minute
		eventType = logging.EventShareEnumeration
	case uniqueCount >= enumThresholdDelay30s:
		penalty = 30 * time.Second
		eventType = logging.EventShareEnumeration
	case uniqueCount >= enumThresholdDelay5s:
		penalty = 5 * time.Second
		eventType = logging.EventShareEnumeration
	default:
		// 1-3 hits: no penalty
		return 0
	}

	// Update penalty deadline
	t.penaltyUntil = now.Add(penalty)

	// Log security event at threshold crossings (log when first entering a new tier)
	// Only log at exact threshold values to avoid spamming
	if uniqueCount == enumThresholdDelay5s ||
		uniqueCount == enumThresholdDelay30s ||
		uniqueCount == enumThresholdBlock2m ||
		uniqueCount == enumThresholdBlock10m ||
		uniqueCount == enumThresholdBlock1h {
		logging.LogSecurityEventWithEntityID(
			eventType,
			entityID,
			map[string]interface{}{
				"unique_share_404s": uniqueCount,
				"total_hits":        t.totalHits,
				"window_minutes":    int(enumerationWindow.Minutes()),
				"penalty_seconds":   int(penalty.Seconds()),
				"last_share_prefix": shareIDPrefix,
				"detection_type":    "share_enumeration",
			},
		)
	}

	return penalty
}

// IsBlocked checks if an entity is currently blocked by enumeration protection.
// Returns (blocked, retryAfterSeconds).
func (g *shareEnumerationGuard) IsBlocked(entityID string) (bool, int) {
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

// ShareEnumerationMiddleware protects share endpoints against entity-global
// enumeration attacks (probing many different share IDs). This runs BEFORE
// the per-share-ID rate limiter and the handler itself.
//
// It applies to both /shared/:id (HTML page) and /api/public/shares/:id/* endpoints.
func ShareEnumerationMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		entityID := logging.GetOrCreateEntityID(c)

		blocked, retryAfter := enumGuard.IsBlocked(entityID)
		if blocked {
			// Record this blocked attempt so the counter keeps growing
			// even while the entity is being rate-limited. This ensures
			// progressive escalation (5s -> 30s -> 2m -> 10m -> 1h).
			shareID := c.Param("id")
			if shareID != "" {
				enumGuard.RecordShareNotFound(entityID, shareID)
			}
			msg := fmt.Sprintf("Too many failed share lookups. Try again in %d seconds.", retryAfter)
			return ServeRateLimitPage(c, retryAfter, msg)
		}

		return next(c)
	}
}

// NotifyShareNotFound should be called by share handlers when a share ID
// returns 404. It records the hit in the enumeration guard and applies
// progressive penalties. The share handler should call this AFTER logging
// the EventShareNotFound security event.
func NotifyShareNotFound(entityID, shareIDPrefix string) {
	enumGuard.RecordShareNotFound(entityID, shareIDPrefix)
}
