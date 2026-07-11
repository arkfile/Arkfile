package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	"github.com/arkfile/Arkfile/subbridge"
)

var subscriptionMutationMu sync.Mutex

var ErrInvalidSubscriptionBridgePayload = errors.New("invalid subscription bridge payload")

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

func ProcessSubscriptionBridgeCallback(db *sql.DB, payload *subbridge.CallbackPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return ProcessSubscriptionBridgeCallbackBody(db, payload, body)
}

func ProcessSubscriptionBridgeCallbackBody(db *sql.DB, payload *subbridge.CallbackPayload, body []byte) error {
	subscriptionMutationMu.Lock()
	defer subscriptionMutationMu.Unlock()

	var decoded subbridge.CallbackPayload
	if err := subbridge.DecodeCallback(body, &decoded); err != nil || payload == nil || decoded != *payload {
		return invalidSubscriptionBridgePayload("callback body does not match decoded payload")
	}
	periodStart, periodEnd, stateChangedAt, err := validateSubscriptionBridgePayload(payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSubscriptionBridgePayload, err)
	}
	return applySubscriptionBridgeState(db, payload, body, periodStart, periodEnd, stateChangedAt)
}

func ProcessSubscriptionBridgeSnapshot(db *sql.DB, snapshot *subbridge.SnapshotPayload, body []byte) error {
	subscriptionMutationMu.Lock()
	defer subscriptionMutationMu.Unlock()

	var decoded subbridge.SnapshotPayload
	if err := subbridge.DecodeSnapshot(body, &decoded); err != nil || snapshot == nil || decoded != *snapshot {
		return invalidSubscriptionBridgePayload("snapshot body does not match decoded payload")
	}
	periodStart, periodEnd, stateChangedAt, err := validateSubscriptionBridgeSnapshot(snapshot)
	if err != nil {
		return err
	}
	snapshotHash := sha256.Sum256(body)
	payload := &subbridge.CallbackPayload{
		Protocol:           snapshot.Protocol,
		Version:            snapshot.Version,
		EventID:            "evt_sync_" + hex.EncodeToString(snapshotHash[:]),
		EventType:          "subscription.sync",
		CheckoutID:         snapshot.CheckoutID,
		SubscriptionRef:    snapshot.SubscriptionRef,
		PlanID:             snapshot.PlanID,
		StateVersion:       snapshot.StateVersion,
		Status:             snapshot.Status,
		CurrentPeriodStart: snapshot.CurrentPeriodStart,
		CurrentPeriodEnd:   snapshot.CurrentPeriodEnd,
		CancelAtPeriodEnd:  snapshot.CancelAtPeriodEnd,
		StateChangedAt:     snapshot.StateChangedAt,
	}
	return applySubscriptionBridgeState(db, payload, body, periodStart, periodEnd, stateChangedAt)
}

func applySubscriptionBridgeState(db *sql.DB, payload *subbridge.CallbackPayload, body []byte, periodStart, periodEnd, stateChangedAt time.Time) error {
	hash := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(hash[:])

	var username string
	sub, err := models.GetUserSubscriptionBySubscriptionRef(db, payload.SubscriptionRef)
	if err == nil {
		username = sub.Username
		if payload.CheckoutID != sub.CheckoutID {
			return invalidSubscriptionBridgePayload("subscription checkout mismatch")
		}
		if payload.EventType != "subscription.plan_changed" && payload.EventType != "subscription.sync" && payload.PlanID != sub.PlanID {
			return invalidSubscriptionBridgePayload("subscription plan mismatch")
		}
	} else if err == sql.ErrNoRows && payload.CheckoutID != "" {
		checkout, cerr := models.GetSubscriptionCheckout(db, payload.CheckoutID)
		if cerr != nil {
			return fmt.Errorf("resolve checkout %s: %w", payload.CheckoutID, cerr)
		}
		if payload.EventType != "subscription.plan_changed" && payload.PlanID != checkout.PlanID {
			return invalidSubscriptionBridgePayload("checkout plan mismatch")
		}
		username = checkout.Username
	} else {
		return fmt.Errorf("resolve subscription reference: %w", err)
	}

	if sub == nil && payload.Status != "expired" {
		if err := FinalizePaygBeforeSubscribe(db, username); err != nil {
			return err
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existing, err := models.GetUserSubscriptionBySubscriptionRefTx(tx, payload.SubscriptionRef)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if existing != nil {
		if payload.CheckoutID != existing.CheckoutID {
			return invalidSubscriptionBridgePayload("subscription checkout mismatch")
		}
		if payload.EventType != "subscription.plan_changed" && payload.EventType != "subscription.sync" && payload.PlanID != existing.PlanID {
			return invalidSubscriptionBridgePayload("subscription plan mismatch")
		}
		if payload.StateVersion > existing.StateVersion {
			if existing.Status == "expired" {
				return invalidSubscriptionBridgePayload("subscription bridge attempted to regress a terminal state")
			}
			if existing.StateChangedAt != nil && stateChangedAt.Before(*existing.StateChangedAt) {
				return invalidSubscriptionBridgePayload("subscription bridge state_changed_at regressed")
			}
			if periodStart.Before(existing.CurrentPeriodStart) || periodEnd.Before(existing.CurrentPeriodEnd) {
				return invalidSubscriptionBridgePayload("subscription bridge period boundary regressed")
			}
		}
	}
	disposition := "applied"
	if existing != nil && payload.StateVersion <= existing.StateVersion {
		disposition = "ignored_stale"
	}

	inserted, err := models.TryInsertSubscriptionEventTx(tx,
		payload.EventID, payload.EventType, payload.SubscriptionRef,
		payload.CheckoutID, username, payload.PlanID, payload.StateVersion,
		&stateChangedAt, disposition, "", payloadHash,
	)
	if err != nil {
		return err
	}
	if !inserted {
		var storedPayloadHash string
		if err := tx.QueryRow(`SELECT payload_hash FROM subscription_events WHERE event_id = ?`, payload.EventID).Scan(&storedPayloadHash); err != nil {
			return err
		}
		if !hmac.Equal([]byte(storedPayloadHash), []byte(payloadHash)) {
			return invalidSubscriptionBridgePayload("subscription bridge event_id reused with different payload")
		}
		return tx.Commit()
	}
	if disposition == "ignored_stale" {
		return tx.Commit()
	}

	if existing == nil {
		checkout, cerr := models.GetSubscriptionCheckoutTx(tx, payload.CheckoutID)
		if cerr != nil {
			return cerr
		}
		if checkout.Username != username {
			return invalidSubscriptionBridgePayload("checkout username mismatch")
		}
		sub := &models.UserSubscription{
			Username:           username,
			PlanID:             payload.PlanID,
			CheckoutID:         payload.CheckoutID,
			SubscriptionRef:    payload.SubscriptionRef,
			IsCurrent:          payload.Status != "expired",
			Status:             payload.Status,
			Source:             "bridge",
			StateVersion:       payload.StateVersion,
			StateChangedAt:     &stateChangedAt,
			CurrentPeriodStart: periodStart.UTC(),
			CurrentPeriodEnd:   periodEnd.UTC(),
			CancelAtPeriodEnd:  payload.CancelAtPeriodEnd,
		}
		if payload.Status == "past_due" {
			sub.PastDueSince = &stateChangedAt
		}
		if payload.Status == "canceled" {
			sub.CanceledAt = &stateChangedAt
		}
		if err := models.InsertUserSubscriptionTx(tx, sub); err != nil {
			return err
		}
		if err := models.UpdateSubscriptionCheckoutTx(tx, payload.CheckoutID, "completed", payload.SubscriptionRef); err != nil {
			return err
		}
		return tx.Commit()
	}

	existing.PlanID = payload.PlanID
	existing.IsCurrent = payload.Status != "expired"
	existing.Status = payload.Status
	existing.StateVersion = payload.StateVersion
	existing.StateChangedAt = &stateChangedAt
	existing.CurrentPeriodStart = periodStart.UTC()
	existing.CurrentPeriodEnd = periodEnd.UTC()
	existing.CancelAtPeriodEnd = payload.CancelAtPeriodEnd

	switch payload.Status {
	case "past_due":
		if existing.PastDueSince == nil {
			existing.PastDueSince = &stateChangedAt
		}
	case "active", "trialing":
		existing.PastDueSince = nil
		existing.CanceledAt = nil
	}
	if payload.Status == "canceled" && existing.CanceledAt == nil {
		existing.CanceledAt = &stateChangedAt
	}
	if err := models.UpdateUserSubscriptionTx(tx, existing); err != nil {
		return err
	}
	return tx.Commit()
}

func invalidSubscriptionBridgePayload(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidSubscriptionBridgePayload, message)
}

func validateSubscriptionBridgePayload(payload *subbridge.CallbackPayload) (time.Time, time.Time, time.Time, error) {
	if payload == nil {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("nil subscription bridge payload")
	}
	if payload.Protocol != subbridge.ProtocolName || payload.Version != subbridge.ProtocolVersion {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("unsupported subscription bridge protocol")
	}
	if !validBridgeIdentifier(payload.EventID, "evt_") ||
		!validBridgeIdentifier(payload.CheckoutID, "subchk_") ||
		!validBridgeIdentifier(payload.SubscriptionRef, "sub_") {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("invalid subscription bridge identifier")
	}
	if strings.TrimSpace(payload.PlanID) == "" || len(payload.PlanID) > 128 || payload.StateVersion < 1 {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("invalid subscription bridge state metadata")
	}
	if !eventStatusCompatible(payload.EventType, payload.Status) {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("invalid subscription bridge event transition")
	}
	return validateSubscriptionBridgeState(
		payload.Status, payload.CurrentPeriodStart, payload.CurrentPeriodEnd,
		payload.StateChangedAt, payload.CancelAtPeriodEnd,
	)
}

func validateSubscriptionBridgeSnapshot(snapshot *subbridge.SnapshotPayload) (time.Time, time.Time, time.Time, error) {
	if snapshot == nil {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("nil subscription bridge snapshot")
	}
	if snapshot.Protocol != subbridge.ProtocolName || snapshot.Version != subbridge.ProtocolVersion {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("unsupported subscription bridge protocol")
	}
	if !validBridgeIdentifier(snapshot.CheckoutID, "subchk_") ||
		!validBridgeIdentifier(snapshot.SubscriptionRef, "sub_") ||
		strings.TrimSpace(snapshot.PlanID) == "" || len(snapshot.PlanID) > 128 ||
		snapshot.StateVersion < 1 {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("invalid subscription bridge snapshot metadata")
	}
	return validateSubscriptionBridgeState(
		snapshot.Status, snapshot.CurrentPeriodStart, snapshot.CurrentPeriodEnd,
		snapshot.StateChangedAt, snapshot.CancelAtPeriodEnd,
	)
}

func validateSubscriptionBridgeState(status, periodStartValue, periodEndValue, stateChangedValue string, cancelAtPeriodEnd bool) (time.Time, time.Time, time.Time, error) {
	allowedStatus := map[string]bool{"active": true, "trialing": true, "past_due": true, "canceled": true, "expired": true}
	if !allowedStatus[status] || (status == "canceled") != cancelAtPeriodEnd {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("invalid subscription bridge state")
	}
	periodStart, err := subbridge.ParseUTCSecond(periodStartValue)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("invalid current_period_start: %w", err)
	}
	periodEnd, err := subbridge.ParseUTCSecond(periodEndValue)
	if err != nil || !periodEnd.After(periodStart) {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("invalid current_period_end")
	}
	stateChangedAt, err := subbridge.ParseUTCSecond(stateChangedValue)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("invalid state_changed_at: %w", err)
	}
	return periodStart, periodEnd, stateChangedAt, nil
}

func validBridgeIdentifier(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) <= len(prefix) || len(value) > 160 {
		return false
	}
	for _, char := range value[len(prefix):] {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_' || char == '-') {
			return false
		}
	}
	return true
}

func eventStatusCompatible(eventType, status string) bool {
	switch eventType {
	case "subscription.activated":
		return status == "active" || status == "trialing"
	case "subscription.renewed":
		return status == "active"
	case "subscription.past_due":
		return status == "past_due"
	case "subscription.canceled":
		return status == "canceled"
	case "subscription.expired":
		return status == "expired"
	case "subscription.plan_changed":
		return status == "active"
	default:
		return false
	}
}

func ReconcileSubscriptionFromBridge(db *sql.DB, subscriptionRef string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	if !cfg.Subscriptions.Enabled || !cfg.Subscriptions.BridgeEnabled {
		return errors.New("subscription bridge is disabled")
	}
	keys, err := subbridge.DeriveKeys(cfg.Subscriptions.BridgePairingRoot)
	if err != nil {
		return err
	}
	snapshot, err := subbridge.FetchSubscriptionSnapshot(cfg.Subscriptions.BridgeURL, keys.Reconcile, subscriptionRef)
	if err != nil {
		return err
	}
	return ProcessSubscriptionBridgeSnapshot(db, &snapshot.Payload, snapshot.Body)
}

func GrantGiftSubscription(db *sql.DB, username, planID string, days int, note, adminUsername string) (*models.UserSubscription, error) {
	subscriptionMutationMu.Lock()
	defer subscriptionMutationMu.Unlock()

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
	if active, err := models.GetActiveUserSubscription(db, username); err != nil && err != sql.ErrNoRows {
		return nil, err
	} else if active != nil {
		return nil, fmt.Errorf("user already has an active subscription")
	}

	if err := FinalizePaygBeforeSubscribe(db, username); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	checkoutID := "subchk_gift_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	subRef := "sub_gift_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	end := now.Add(time.Duration(days) * 24 * time.Hour)

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	active, err := models.GetActiveUserSubscriptionTx(tx, username)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if active != nil {
		return nil, fmt.Errorf("user already has an active subscription")
	}

	if err := models.CreateSubscriptionCheckoutTx(tx, &models.SubscriptionCheckout{
		CheckoutID: checkoutID,
		Username:   username,
		PlanID:     planID,
		Status:     "completed",
	}); err != nil {
		return nil, err
	}
	if err := models.UpdateSubscriptionCheckoutTx(tx, checkoutID, "completed", subRef); err != nil {
		return nil, err
	}

	sub := &models.UserSubscription{
		Username:           username,
		PlanID:             planID,
		CheckoutID:         checkoutID,
		SubscriptionRef:    subRef,
		IsCurrent:          true,
		Status:             "active",
		Source:             "gift",
		StateChangedAt:     &now,
		CurrentPeriodStart: now,
		CurrentPeriodEnd:   end,
		GiftNote:           note,
	}
	if err := models.InsertUserSubscriptionTx(tx, sub); err != nil {
		return nil, err
	}

	eventID := "gift_" + uuid.New().String()
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", username, planID, days)))
	if err := models.InsertSubscriptionEventTx(tx, eventID, "gift.granted", subRef, checkoutID, username, planID, 0, &now, "applied", adminUsername, hex.EncodeToString(hash[:])); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return models.GetUserSubscriptionBySubscriptionRef(db, subRef)
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
		return models.ExpireUserSubscription(db, sub.SubscriptionRef)
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
		if err := models.ExpireUserSubscription(db, sub.SubscriptionRef); err != nil {
			logging.ErrorLogger.Printf("expire gift subscription %s: %v", sub.SubscriptionRef, err)
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
		if err := ReconcileSubscriptionFromBridge(db, sub.SubscriptionRef); err != nil {
			logging.ErrorLogger.Printf("reconcile subscription %s: %v", sub.SubscriptionRef, err)
			continue
		}
		count++
	}
	return count, nil
}

func CreateCheckoutURL(cfg config.SubscriptionsConfig, checkoutID, planID, returnURL string) (string, error) {
	if !cfg.Enabled || !cfg.BridgeEnabled {
		return "", errors.New("subscription bridge is disabled")
	}
	keys, err := subbridge.DeriveKeys(cfg.BridgePairingRoot)
	if err != nil {
		return "", err
	}
	normalizedReturnURL, err := subbridge.NormalizeReturnURL(returnURL)
	if err != nil {
		return "", err
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	token, err := subbridge.SignStartToken(keys.Token, subbridge.StartTokenPayload{
		CheckoutID: checkoutID,
		PlanID:     planID,
		ReturnURL:  normalizedReturnURL,
		Iat:        issuedAt.Unix(),
		Exp:        issuedAt.Add(subbridge.TokenLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	return cfg.BridgeURL + "/v1/start?token=" + url.QueryEscape(token), nil
}

func CreatePortalURL(cfg config.SubscriptionsConfig, subscriptionRef, returnURL string) (string, error) {
	if !cfg.Enabled || !cfg.BridgeEnabled {
		return "", errors.New("subscription bridge is disabled")
	}
	keys, err := subbridge.DeriveKeys(cfg.BridgePairingRoot)
	if err != nil {
		return "", err
	}
	normalizedReturnURL, err := subbridge.NormalizeReturnURL(returnURL)
	if err != nil {
		return "", err
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	token, err := subbridge.SignPortalToken(keys.Token, subbridge.PortalTokenPayload{
		SubscriptionRef: subscriptionRef,
		ReturnURL:       normalizedReturnURL,
		Iat:             issuedAt.Unix(),
		Exp:             issuedAt.Add(subbridge.TokenLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	return cfg.BridgeURL + "/v1/portal?token=" + url.QueryEscape(token), nil
}
