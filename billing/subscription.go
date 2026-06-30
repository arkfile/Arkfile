package billing

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/entitlements"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
)

// SettleUserAccumulator drains pending usage for one user without running a
// full sweep. Used before pausing the meter on subscribe.
func SettleUserAccumulator(db *sql.DB, username string, now time.Time) error {
	if !paygMeteringEnabled() {
		return nil
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	rate, err := ResolveRate(db, cfg.Billing)
	if err != nil {
		return err
	}
	var unbilledF float64
	var lastBilledAt sql.NullString
	err = db.QueryRow(`
		SELECT unbilled_microcents, last_billed_at
		FROM storage_usage_accumulator WHERE username = ?`, username).Scan(&unbilledF, &lastBilledAt)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	unbilled := int64(unbilledF)
	if unbilled <= 0 {
		return nil
	}
	_, err = settleOneUser(db, rate, now, username, unbilled, lastBilledAt)
	return err
}

// FinalizePaygBeforeSubscribe runs a final tick (if needed) and settles any
// pending accumulator before subscription metering pauses.
func FinalizePaygBeforeSubscribe(db *sql.DB, username string) error {
	if !paygMeteringEnabled() {
		return nil
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	rate, err := ResolveRate(db, cfg.Billing)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if err := TickUser(db, username, rate, now, cfg.Billing.FreeBaselineBytes); err != nil {
		return fmt.Errorf("final tick before subscribe: %w", err)
	}
	return SettleUserAccumulator(db, username, now)
}

func ProcessEntitlementCallback(db *sql.DB, payload *entitlements.CallbackPayload) error {
	if payload == nil {
		return errors.New("nil entitlement payload")
	}
	if payload.Protocol != "entitlement-bridge" || payload.Version != 1 {
		return errors.New("unsupported entitlement protocol")
	}
	body, _ := json.Marshal(payload)
	hash := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(hash[:])

	exists, err := models.SubscriptionEventExists(db, payload.EventID)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	var username string
	sub, err := models.GetUserSubscriptionByEntitlementRef(db, payload.EntitlementRef)
	if err == nil {
		username = sub.Username
	} else if payload.CheckoutID != "" {
		checkout, cerr := models.GetSubscriptionCheckout(db, payload.CheckoutID)
		if cerr != nil {
			return fmt.Errorf("resolve checkout %s: %w", payload.CheckoutID, cerr)
		}
		username = checkout.Username
	} else {
		return fmt.Errorf("cannot resolve username for entitlement event")
	}

	if payload.EventType == "entitlement.activated" {
		if err := FinalizePaygBeforeSubscribe(db, username); err != nil {
			return err
		}
	}

	if err := applyEntitlementState(db, username, payload); err != nil {
		return err
	}

	return models.InsertSubscriptionEvent(db,
		payload.EventID, payload.EventType, payload.EntitlementRef,
		payload.CheckoutID, username, payload.PlanID, payloadHash,
	)
}

func applyEntitlementState(db *sql.DB, username string, payload *entitlements.CallbackPayload) error {
	periodStart, err := time.Parse(time.RFC3339, payload.CurrentPeriodStart)
	if err != nil {
		return fmt.Errorf("invalid current_period_start: %w", err)
	}
	periodEnd, err := time.Parse(time.RFC3339, payload.CurrentPeriodEnd)
	if err != nil {
		return fmt.Errorf("invalid current_period_end: %w", err)
	}

	existing, err := models.GetUserSubscriptionByEntitlementRef(db, payload.EntitlementRef)
	if err == sql.ErrNoRows {
		checkout, cerr := models.GetSubscriptionCheckout(db, payload.CheckoutID)
		if cerr != nil {
			return cerr
		}
		if checkout.Username != username {
			return errors.New("checkout username mismatch")
		}
		sub := &models.UserSubscription{
			Username:           username,
			PlanID:             payload.PlanID,
			CheckoutID:         payload.CheckoutID,
			EntitlementRef:     payload.EntitlementRef,
			Status:             payload.Status,
			Source:             "bridge",
			CurrentPeriodStart: periodStart.UTC(),
			CurrentPeriodEnd:   periodEnd.UTC(),
			CancelAtPeriodEnd:  payload.CancelAtPeriodEnd,
		}
		if payload.Status == "past_due" {
			now := time.Now().UTC()
			sub.PastDueSince = &now
		}
		if err := models.InsertUserSubscription(db, sub); err != nil {
			return err
		}
		return models.UpdateSubscriptionCheckout(db, payload.CheckoutID, "completed", payload.EntitlementRef)
	}
	if err != nil {
		return err
	}

	existing.PlanID = payload.PlanID
	existing.Status = payload.Status
	existing.CurrentPeriodStart = periodStart.UTC()
	existing.CurrentPeriodEnd = periodEnd.UTC()
	existing.CancelAtPeriodEnd = payload.CancelAtPeriodEnd

	switch payload.EventType {
	case "entitlement.past_due":
		if existing.PastDueSince == nil {
			now := time.Now().UTC()
			existing.PastDueSince = &now
		}
	case "entitlement.renewed", "entitlement.activated":
		existing.PastDueSince = nil
	case "entitlement.canceled":
		now := time.Now().UTC()
		existing.CanceledAt = &now
	case "entitlement.expired":
		existing.Status = "expired"
	}

	return models.UpdateUserSubscription(db, existing)
}

func ReconcileEntitlementFromBridge(db *sql.DB, entitlementRef string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	snap, err := entitlements.FetchEntitlementSnapshot(cfg.Subscriptions.BridgeURL, cfg.Subscriptions.WebhookSecret, entitlementRef)
	if err != nil {
		return err
	}
	snap.EventID = "sync_" + uuid.New().String()
	snap.EventType = "entitlement.sync"
	return ProcessEntitlementCallback(db, snap)
}

func GrantGiftSubscription(db *sql.DB, username, planID string, days int, note, adminUsername string) (*models.UserSubscription, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	if days <= 0 {
		days = cfg.Subscriptions.GiftDefaultDays
	}
	if days > cfg.Subscriptions.GiftMaxDays {
		return nil, fmt.Errorf("gift duration exceeds maximum of %d days", cfg.Subscriptions.GiftMaxDays)
	}

	if _, err := models.GetSubscriptionPlan(db, planID); err != nil {
		return nil, fmt.Errorf("plan not found: %w", err)
	}

	active, err := GetActiveSubscription(db, username)
	if err != nil {
		return nil, err
	}
	if active != nil {
		return nil, fmt.Errorf("user already has an active subscription")
	}

	if err := FinalizePaygBeforeSubscribe(db, username); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	checkoutID := "subchk_gift_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	entRef := "ent_gift_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	end := now.Add(time.Duration(days) * 24 * time.Hour)

	if err := models.CreateSubscriptionCheckout(db, &models.SubscriptionCheckout{
		CheckoutID: checkoutID,
		Username:   username,
		PlanID:     planID,
		Status:     "completed",
	}); err != nil {
		return nil, err
	}
	if err := models.UpdateSubscriptionCheckout(db, checkoutID, "completed", entRef); err != nil {
		return nil, err
	}

	sub := &models.UserSubscription{
		Username:           username,
		PlanID:             planID,
		CheckoutID:         checkoutID,
		EntitlementRef:     entRef,
		Status:             "active",
		Source:             "gift",
		CurrentPeriodStart: now,
		CurrentPeriodEnd:   end,
		GiftNote:           note,
	}
	if err := models.InsertUserSubscription(db, sub); err != nil {
		return nil, err
	}

	eventID := "gift_" + uuid.New().String()
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", username, planID, days)))
	_ = models.InsertSubscriptionEvent(db, eventID, "gift.granted", entRef, checkoutID, username, planID, hex.EncodeToString(hash[:]))
	_ = adminUsername

	return models.GetUserSubscriptionByEntitlementRef(db, entRef)
}

func CancelGiftSubscription(db *sql.DB, username string, immediate bool) error {
	sub, err := GetActiveSubscription(db, username)
	if err != nil {
		return err
	}
	if sub == nil {
		return sql.ErrNoRows
	}
	if sub.Source != "gift" {
		return errors.New("paid subscriptions must be canceled via the billing portal or processor dashboard")
	}
	if immediate {
		return models.ExpireUserSubscription(db, sub.EntitlementRef)
	}
	now := time.Now().UTC()
	sub.Status = "canceled"
	sub.CanceledAt = &now
	sub.CancelAtPeriodEnd = true
	return models.UpdateUserSubscription(db, sub)
}

func ExpireDueGiftSubscriptions(db *sql.DB) (int, error) {
	subs, err := models.ListExpiredGiftSubscriptions(db)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, sub := range subs {
		if err := models.ExpireUserSubscription(db, sub.EntitlementRef); err != nil {
			logging.ErrorLogger.Printf("expire gift subscription %s: %v", sub.EntitlementRef, err)
			continue
		}
		count++
	}
	return count, nil
}

func ReconcileBridgeSubscriptions(db *sql.DB, withinDays int) (int, error) {
	subs, err := models.ListBridgeSubscriptionsForReconcile(db, withinDays)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, sub := range subs {
		if err := ReconcileEntitlementFromBridge(db, sub.EntitlementRef); err != nil {
			logging.ErrorLogger.Printf("reconcile entitlement %s: %v", sub.EntitlementRef, err)
			continue
		}
		count++
	}
	return count, nil
}

func CreateCheckoutURL(cfg config.SubscriptionsConfig, checkoutID, planID, returnURL string) (string, error) {
	exp := time.Now().UTC().Add(entitlements.TokenLifetime).Unix()
	token, err := entitlements.SignToken(cfg.WebhookSecret, entitlements.StartTokenPayload{
		CheckoutID: checkoutID,
		PlanID:     planID,
		ReturnURL:  returnURL,
		Exp:        exp,
	})
	if err != nil {
		return "", err
	}
	return cfg.BridgeURL + "/v1/start?token=" + token, nil
}

func CreatePortalURL(cfg config.SubscriptionsConfig, entitlementRef, returnURL string) (string, error) {
	exp := time.Now().UTC().Add(entitlements.TokenLifetime).Unix()
	token, err := entitlements.SignToken(cfg.WebhookSecret, entitlements.PortalTokenPayload{
		EntitlementRef: entitlementRef,
		ReturnURL:      returnURL,
		Exp:            exp,
	})
	if err != nil {
		return "", err
	}
	return cfg.BridgeURL + "/v1/portal?token=" + token, nil
}
