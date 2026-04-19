package handlers

import (
	"testing"
	"time"
)

// Helper: create a fresh flood guard for each test (no shared state)
func newTestFloodGuard() *floodGuardService {
	return newFloodGuardService()
}

// Helper: record N hits for an entity, returning the last penalty
func recordNHits(g *floodGuardService, entityID string, n int) time.Duration {
	var penalty time.Duration
	for i := 0; i < n; i++ {
		penalty = g.RecordUnauthorizedHit(entityID)
	}
	return penalty
}

// TestTierForHits verifies hit-count-to-tier mapping
func TestTierForHits(t *testing.T) {
	tests := []struct {
		hits     int
		wantTier int
	}{
		{0, 0},
		{1, 0},
		{9, 0},
		{10, 1},
		{15, 1},
		{19, 1},
		{20, 2},
		{39, 2},
		{40, 3},
		{59, 3},
		{60, 4},
		{79, 4},
		{80, 5},
		{100, 5},
		{1000, 5},
	}

	for _, tc := range tests {
		got := tierForHits(tc.hits)
		if got != tc.wantTier {
			t.Errorf("tierForHits(%d) = %d, want %d", tc.hits, got, tc.wantTier)
		}
	}
}

// TestPenaltyForTier verifies tier-to-penalty mapping
func TestPenaltyForTier(t *testing.T) {
	tests := []struct {
		tier        int
		wantPenalty time.Duration
	}{
		{0, 0},
		{1, 5 * time.Second},
		{2, 30 * time.Second},
		{3, 2 * time.Minute},
		{4, 10 * time.Minute},
		{5, 1 * time.Hour},
		{6, 0},  // out of range
		{-1, 0}, // negative
	}

	for _, tc := range tests {
		got := penaltyForTier(tc.tier)
		if got != tc.wantPenalty {
			t.Errorf("penaltyForTier(%d) = %v, want %v", tc.tier, got, tc.wantPenalty)
		}
	}
}

// TestFloodGuard_NoPenaltyUnderThreshold verifies no penalty for < 10 hits
func TestFloodGuard_NoPenaltyUnderThreshold(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-entity-under"

	for i := 1; i <= 9; i++ {
		penalty := g.RecordUnauthorizedHit(entity)
		if penalty != 0 {
			t.Errorf("hit %d: got penalty %v, want 0", i, penalty)
		}

		blocked, _ := g.IsBlocked(entity)
		if blocked {
			t.Errorf("hit %d: entity should not be blocked", i)
		}
	}
}

// TestFloodGuard_Tier1At10Hits verifies tier 1 penalty at 10 hits
func TestFloodGuard_Tier1At10Hits(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-entity-t1"

	// First 9 hits: no penalty
	for i := 1; i <= 9; i++ {
		penalty := g.RecordUnauthorizedHit(entity)
		if penalty != 0 {
			t.Errorf("hit %d: got penalty %v, want 0", i, penalty)
		}
	}

	// 10th hit: tier 1 penalty (5 seconds)
	penalty := g.RecordUnauthorizedHit(entity)
	if penalty != 5*time.Second {
		t.Errorf("hit 10: got penalty %v, want %v", penalty, 5*time.Second)
	}

	blocked, retryAfter := g.IsBlocked(entity)
	if !blocked {
		t.Error("entity should be blocked after 10 hits")
	}
	if retryAfter < 1 || retryAfter > 5 {
		t.Errorf("retryAfter = %d, want 1-5", retryAfter)
	}
}

// TestFloodGuard_Tier2At20Hits verifies tier 2 penalty at 20 hits
func TestFloodGuard_Tier2At20Hits(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-entity-t2"

	// Record 19 hits
	recordNHits(g, entity, 19)

	// 20th hit: tier 2 penalty (30 seconds)
	penalty := g.RecordUnauthorizedHit(entity)
	if penalty != 30*time.Second {
		t.Errorf("hit 20: got penalty %v, want %v", penalty, 30*time.Second)
	}
}

// TestFloodGuard_Tier3At40Hits verifies tier 3 penalty at 40 hits
func TestFloodGuard_Tier3At40Hits(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-entity-t3"

	recordNHits(g, entity, 39)

	penalty := g.RecordUnauthorizedHit(entity)
	if penalty != 2*time.Minute {
		t.Errorf("hit 40: got penalty %v, want %v", penalty, 2*time.Minute)
	}
}

// TestFloodGuard_Tier4At60Hits verifies tier 4 penalty at 60 hits
func TestFloodGuard_Tier4At60Hits(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-entity-t4"

	recordNHits(g, entity, 59)

	penalty := g.RecordUnauthorizedHit(entity)
	if penalty != 10*time.Minute {
		t.Errorf("hit 60: got penalty %v, want %v", penalty, 10*time.Minute)
	}
}

// TestFloodGuard_Tier5At80Hits verifies tier 5 penalty at 80 hits
func TestFloodGuard_Tier5At80Hits(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-entity-t5"

	recordNHits(g, entity, 79)

	penalty := g.RecordUnauthorizedHit(entity)
	if penalty != 1*time.Hour {
		t.Errorf("hit 80: got penalty %v, want %v", penalty, 1*time.Hour)
	}
}

// TestFloodGuard_BlockedRequestsStillEscalate verifies that hits while blocked
// continue to escalate the window hit count
func TestFloodGuard_BlockedRequestsStillEscalate(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-entity-escalate"

	// Get to tier 1 (10 hits)
	recordNHits(g, entity, 10)

	blocked, _ := g.IsBlocked(entity)
	if !blocked {
		t.Fatal("entity should be blocked at tier 1")
	}

	// Record 10 more hits while blocked (simulating blocked requests)
	recordNHits(g, entity, 10)

	// Now at 20 window hits total, should be tier 2
	// Check the tracker directly
	g.mu.Lock()
	tracker := g.trackers[entity]
	if tracker == nil {
		g.mu.Unlock()
		t.Fatal("tracker should exist")
	}
	if tracker.windowHits != 20 {
		t.Errorf("windowHits = %d, want 20", tracker.windowHits)
	}
	if tracker.peakTier != 2 {
		t.Errorf("peakTier = %d, want 2", tracker.peakTier)
	}
	g.mu.Unlock()
}

// TestFloodGuard_WindowReset verifies that window hits reset after the window
// expires, and a fresh entity at tier 0 gets no penalty
func TestFloodGuard_WindowReset(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-entity-window"

	// Record 9 hits (just under threshold)
	recordNHits(g, entity, 9)

	// Simulate time passing beyond the window
	g.mu.Lock()
	tracker := g.trackers[entity]
	tracker.firstHit = time.Now().Add(-floodWindow - 1*time.Second)
	tracker.lastHit = time.Now().Add(-floodWindow - 1*time.Second)
	g.mu.Unlock()

	// Next hit should be in a new window, starting from 1
	penalty := g.RecordUnauthorizedHit(entity)
	if penalty != 0 {
		t.Errorf("first hit in new window: got penalty %v, want 0 (peakTier was 0)", penalty)
	}

	g.mu.Lock()
	if tracker.windowHits != 1 {
		t.Errorf("windowHits = %d, want 1 (window should have reset)", tracker.windowHits)
	}
	g.mu.Unlock()
}

// TestFloodGuard_PeakTierPersistsAcrossWindows verifies that the remembered
// peak tier causes immediate penalties in a new window
func TestFloodGuard_PeakTierPersistsAcrossWindows(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-entity-persist"

	// Get to tier 2 (20 hits)
	recordNHits(g, entity, 20)

	g.mu.Lock()
	tracker := g.trackers[entity]
	if tracker.peakTier != 2 {
		t.Errorf("peakTier = %d, want 2", tracker.peakTier)
	}

	// Simulate window expiry (but NOT enough time for tier decay)
	tracker.firstHit = time.Now().Add(-floodWindow - 1*time.Second)
	tracker.lastHit = time.Now().Add(-floodWindow - 1*time.Second)
	tracker.penaltyUntil = time.Time{} // penalty expired
	g.mu.Unlock()

	// First hit in new window: should get tier 2 penalty immediately
	penalty := g.RecordUnauthorizedHit(entity)
	if penalty != 30*time.Second {
		t.Errorf("first hit in new window: got penalty %v, want %v (remembered tier 2)",
			penalty, 30*time.Second)
	}
}

// TestFloodGuard_TierDecayAfterSilence verifies that peak tier decays after
// periods of silence
func TestFloodGuard_TierDecayAfterSilence(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-entity-decay"

	// Get to tier 3 (40 hits)
	recordNHits(g, entity, 40)

	g.mu.Lock()
	tracker := g.trackers[entity]
	if tracker.peakTier != 3 {
		t.Errorf("peakTier = %d, want 3", tracker.peakTier)
	}

	// Simulate 2 hours of silence (2 decay periods = 2 tier drops: 3 -> 1)
	pastTime := time.Now().Add(-2*tierDecayPeriod - 1*time.Second)
	tracker.firstHit = pastTime
	tracker.lastHit = pastTime
	tracker.penaltyUntil = time.Time{}
	g.mu.Unlock()

	// First hit in new window: should get tier 1 penalty (decayed from tier 3)
	penalty := g.RecordUnauthorizedHit(entity)
	if penalty != 5*time.Second {
		t.Errorf("after 2h silence: got penalty %v, want %v (tier 3 decayed to tier 1)",
			penalty, 5*time.Second)
	}

	// Verify peak tier was updated to decayed value
	g.mu.Lock()
	if tracker.peakTier != 1 {
		t.Errorf("peakTier after decay = %d, want 1", tracker.peakTier)
	}
	g.mu.Unlock()
}

// TestFloodGuard_FullResetAfter6Hours verifies complete tier reset after
// extended silence
func TestFloodGuard_FullResetAfter6Hours(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-entity-fullreset"

	// Get to tier 5 (80 hits)
	recordNHits(g, entity, 80)

	g.mu.Lock()
	tracker := g.trackers[entity]
	if tracker.peakTier != 5 {
		t.Errorf("peakTier = %d, want 5", tracker.peakTier)
	}

	// Simulate 6+ hours of silence
	pastTime := time.Now().Add(-tierFullResetPeriod - 1*time.Second)
	tracker.firstHit = pastTime
	tracker.lastHit = pastTime
	tracker.penaltyUntil = time.Time{}
	g.mu.Unlock()

	// First hit in new window: should have no penalty (full reset)
	penalty := g.RecordUnauthorizedHit(entity)
	if penalty != 0 {
		t.Errorf("after 6h silence: got penalty %v, want 0 (full reset)", penalty)
	}

	g.mu.Lock()
	if tracker.peakTier != 0 {
		t.Errorf("peakTier after full reset = %d, want 0", tracker.peakTier)
	}
	if tracker.windowHits != 1 {
		t.Errorf("windowHits = %d, want 1", tracker.windowHits)
	}
	g.mu.Unlock()
}

// TestFloodGuard_MultipleEntitiesIndependent verifies that different entities
// are tracked independently
func TestFloodGuard_MultipleEntitiesIndependent(t *testing.T) {
	g := newTestFloodGuard()
	entityA := "test-entity-A"
	entityB := "test-entity-B"

	// Entity A: 15 hits (tier 1)
	recordNHits(g, entityA, 15)

	// Entity B: 5 hits (no penalty)
	recordNHits(g, entityB, 5)

	blockedA, _ := g.IsBlocked(entityA)
	blockedB, _ := g.IsBlocked(entityB)

	if !blockedA {
		t.Error("entity A should be blocked (15 hits)")
	}
	if blockedB {
		t.Error("entity B should NOT be blocked (5 hits)")
	}
}

// TestFloodGuard_IsBlocked_NotBlocked verifies IsBlocked returns false for
// unknown and unpenalized entities
func TestFloodGuard_IsBlocked_NotBlocked(t *testing.T) {
	g := newTestFloodGuard()

	// Unknown entity
	blocked, retryAfter := g.IsBlocked("nonexistent")
	if blocked {
		t.Error("unknown entity should not be blocked")
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter = %d, want 0", retryAfter)
	}

	// Entity with hits but under threshold
	recordNHits(g, "low-hits", 5)
	blocked, _ = g.IsBlocked("low-hits")
	if blocked {
		t.Error("entity with 5 hits should not be blocked")
	}
}

// TestFloodGuard_IsBlocked_ExpiredPenalty verifies IsBlocked returns false
// when the penalty has expired
func TestFloodGuard_IsBlocked_ExpiredPenalty(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-entity-expired"

	// Get to tier 1
	recordNHits(g, entity, 10)

	blocked, _ := g.IsBlocked(entity)
	if !blocked {
		t.Fatal("entity should be blocked initially")
	}

	// Simulate penalty expiry
	g.mu.Lock()
	tracker := g.trackers[entity]
	tracker.penaltyUntil = time.Now().Add(-1 * time.Second)
	g.mu.Unlock()

	blocked, _ = g.IsBlocked(entity)
	if blocked {
		t.Error("entity should not be blocked after penalty expires")
	}
}

// TestFloodGuard_Cleanup verifies that stale entries are removed
func TestFloodGuard_Cleanup(t *testing.T) {
	g := newTestFloodGuard()

	// Create entries for multiple entities
	recordNHits(g, "stale-entity-1", 5)
	recordNHits(g, "stale-entity-2", 15) // tier 1, will have a penalty
	recordNHits(g, "active-entity", 5)

	// Age the stale entries beyond the full reset period
	g.mu.Lock()
	pastTime := time.Now().Add(-tierFullResetPeriod - 1*time.Hour)
	for _, entityID := range []string{"stale-entity-1", "stale-entity-2"} {
		tracker := g.trackers[entityID]
		tracker.lastHit = pastTime
		tracker.penaltyUntil = time.Time{} // penalty expired
	}
	g.mu.Unlock()

	// Run cleanup
	g.cleanup()

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.trackers["stale-entity-1"]; exists {
		t.Error("stale-entity-1 should have been cleaned up")
	}
	if _, exists := g.trackers["stale-entity-2"]; exists {
		t.Error("stale-entity-2 should have been cleaned up")
	}
	if _, exists := g.trackers["active-entity"]; !exists {
		t.Error("active-entity should NOT have been cleaned up")
	}
}

// TestFloodGuard_CleanupPreservesActivePenalty verifies that cleanup does not
// remove entries with active penalties
func TestFloodGuard_CleanupPreservesActivePenalty(t *testing.T) {
	g := newTestFloodGuard()

	recordNHits(g, "penalized-entity", 80) // tier 5: 1 hour penalty

	// Age the lastHit, but keep penalty active
	g.mu.Lock()
	tracker := g.trackers["penalized-entity"]
	tracker.lastHit = time.Now().Add(-tierFullResetPeriod - 1*time.Hour)
	// penaltyUntil is still in the future (set by RecordUnauthorizedHit)
	g.mu.Unlock()

	g.cleanup()

	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.trackers["penalized-entity"]; !exists {
		t.Error("entity with active penalty should NOT have been cleaned up")
	}
}

// TestFloodGuard_ProgressiveEscalationWithinWindow verifies that penalty
// increases as hits accumulate within a single window
func TestFloodGuard_ProgressiveEscalationWithinWindow(t *testing.T) {
	g := newTestFloodGuard()
	entity := "test-escalation"

	// Track penalties at each tier crossing
	type checkpoint struct {
		hitCount    int
		wantPenalty time.Duration
	}

	checkpoints := []checkpoint{
		{10, 5 * time.Second},
		{20, 30 * time.Second},
		{40, 2 * time.Minute},
		{60, 10 * time.Minute},
		{80, 1 * time.Hour},
	}

	hitsSoFar := 0
	for _, cp := range checkpoints {
		// Record hits up to this checkpoint
		remaining := cp.hitCount - hitsSoFar
		for i := 0; i < remaining-1; i++ {
			g.RecordUnauthorizedHit(entity)
		}

		// The checkpoint hit
		penalty := g.RecordUnauthorizedHit(entity)
		hitsSoFar = cp.hitCount

		if penalty != cp.wantPenalty {
			t.Errorf("at %d hits: got penalty %v, want %v",
				cp.hitCount, penalty, cp.wantPenalty)
		}
	}
}

// TestFloodGuard_DecayTier verifies the decayTier function directly
func TestFloodGuard_DecayTier(t *testing.T) {
	tests := []struct {
		name          string
		peakTier      int
		silencePeriod time.Duration
		wantTier      int
	}{
		{"no decay within 1h", 3, 30 * time.Minute, 3},
		{"1 tier drop at 1h", 3, 1*time.Hour + 1*time.Second, 2},
		{"2 tier drop at 2h", 3, 2*time.Hour + 1*time.Second, 1},
		{"3 tier drop at 3h (floors at 0)", 3, 3*time.Hour + 1*time.Second, 0},
		{"full reset at 6h", 5, 6*time.Hour + 1*time.Second, 0},
		{"tier 1 drops to 0 at 1h", 1, 1*time.Hour + 1*time.Second, 0},
		{"tier 0 stays at 0", 0, 10 * time.Hour, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tracker := &floodTracker{
				peakTier: tc.peakTier,
				lastHit:  time.Now().Add(-tc.silencePeriod),
			}

			decayTier(tracker, time.Now())

			if tracker.peakTier != tc.wantTier {
				t.Errorf("decayTier: peakTier = %d, want %d", tracker.peakTier, tc.wantTier)
			}
		})
	}
}

// TestFloodGuard_ExemptPaths verifies that health probe paths are exempt
func TestFloodGuard_ExemptPaths(t *testing.T) {
	tests := []struct {
		path       string
		wantExempt bool
	}{
		{"/healthz", true},
		{"/readyz", true},
		{"/api/files", false},
		{"/wp-admin/", false},
		{"/healthz/extra", false}, // only exact match
		{"/", false},
	}

	for _, tc := range tests {
		got := isFloodGuardExemptPath(tc.path)
		if got != tc.wantExempt {
			t.Errorf("isFloodGuardExemptPath(%q) = %v, want %v", tc.path, got, tc.wantExempt)
		}
	}
}
