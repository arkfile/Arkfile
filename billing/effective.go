package billing

import (
	"database/sql"
	"time"

	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/models"
)

type BillingMode string

const (
	BillingModeFree       BillingMode = "free"
	BillingModePayg       BillingMode = "payg"
	BillingModeSubscribed BillingMode = "subscribed"
)

func subscriptionsEnabled() bool {
	cfg, err := config.LoadConfig()
	return err == nil && cfg.Subscriptions.Enabled
}

func paygMeteringEnabled() bool {
	cfg, err := config.LoadConfig()
	return err == nil && cfg.Billing.Enabled && cfg.Billing.PaygEnabled
}

func pastDueGraceDuration() time.Duration {
	cfg, err := config.LoadConfig()
	if err != nil || cfg.Subscriptions.PastDueGraceDays <= 0 {
		return 7 * 24 * time.Hour
	}
	return time.Duration(cfg.Subscriptions.PastDueGraceDays) * 24 * time.Hour
}

// SubscriptionMeterPaused reports whether hourly metering and daily settlement
// should be skipped for the user because of an active paid or gift subscription.
func SubscriptionMeterPaused(sub *models.UserSubscription) bool {
	if sub == nil {
		return false
	}
	switch sub.Status {
	case "active", "trialing", "past_due":
		return true
	case "canceled":
		return sub.CurrentPeriodEnd.After(time.Now().UTC())
	default:
		return false
	}
}

// SubscriptionBlocksTopUp reports whether BTCPay top-ups must be rejected.
func SubscriptionBlocksTopUp(sub *models.UserSubscription) bool {
	if sub == nil {
		return false
	}
	switch sub.Status {
	case "active", "trialing":
		return true
	case "canceled", "past_due":
		return sub.CurrentPeriodEnd.After(time.Now().UTC())
	default:
		return false
	}
}

// SubscriptionBlocksUpload reports whether subscription state blocks uploads
// (past_due after grace). Does not cover storage cap or PAYG debt.
func SubscriptionBlocksUpload(sub *models.UserSubscription) bool {
	if sub == nil || sub.Status != "past_due" {
		return false
	}
	if sub.PastDueSince == nil {
		return true
	}
	return time.Since(sub.PastDueSince.UTC()) > pastDueGraceDuration()
}

func GetActiveSubscription(db *sql.DB, username string) (*models.UserSubscription, error) {
	sub, err := models.GetActiveUserSubscription(db, username)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return sub, err
}

func EffectiveBillingMode(db *sql.DB, username string) BillingMode {
	sub, err := GetActiveSubscription(db, username)
	if err != nil {
		return BillingModeFree
	}
	if sub != nil && SubscriptionMeterPaused(sub) && subscriptionsEnabled() {
		return BillingModeSubscribed
	}
	if !paygMeteringEnabled() {
		return BillingModeFree
	}
	user, err := models.GetUserByUsername(db, username)
	if err != nil {
		return BillingModeFree
	}
	freeBaseline := configFreeBaselineBytes()
	if user.TotalStorageBytes <= freeBaseline {
		return BillingModeFree
	}
	return BillingModePayg
}

func configFreeBaselineBytes() int64 {
	cfg, err := config.LoadConfig()
	if err != nil {
		return models.DefaultStorageLimit
	}
	return cfg.Billing.FreeBaselineBytes
}

func EffectiveStorageLimit(db *sql.DB, username string) (int64, error) {
	user, err := models.GetUserByUsername(db, username)
	if err != nil {
		return 0, err
	}
	baseline := user.StorageLimitBytes
	sub, err := GetActiveSubscription(db, username)
	if err != nil {
		return baseline, err
	}
	if sub != nil && SubscriptionMeterPaused(sub) {
		if sub.PlanStorageBytes > baseline {
			return sub.PlanStorageBytes, nil
		}
	}
	return baseline, nil
}

func EffectiveFreeBaseline(db *sql.DB, username string) int64 {
	sub, err := GetActiveSubscription(db, username)
	if err != nil || sub == nil || !SubscriptionMeterPaused(sub) {
		return configFreeBaselineBytes()
	}
	if sub.PlanStorageBytes > configFreeBaselineBytes() {
		return sub.PlanStorageBytes
	}
	return configFreeBaselineBytes()
}

func ShouldMeter(db *sql.DB, username string) bool {
	if !paygMeteringEnabled() {
		return false
	}
	sub, err := GetActiveSubscription(db, username)
	if err != nil {
		return true
	}
	return !SubscriptionMeterPaused(sub)
}

func ShouldApplyPaygUploadCap(db *sql.DB, username string) bool {
	if !paygMeteringEnabled() {
		return false
	}
	sub, err := GetActiveSubscription(db, username)
	if err != nil {
		return true
	}
	return !SubscriptionMeterPaused(sub)
}

func ShouldAllowTopUp(db *sql.DB, username string) bool {
	sub, err := GetActiveSubscription(db, username)
	if err != nil {
		return true
	}
	return !SubscriptionBlocksTopUp(sub)
}

func CheckStorageAvailable(db *sql.DB, username string, additionalBytes int64) (bool, error) {
	limit, err := EffectiveStorageLimit(db, username)
	if err != nil {
		return false, err
	}
	user, err := models.GetUserByUsername(db, username)
	if err != nil {
		return false, err
	}
	return (user.TotalStorageBytes + additionalBytes) <= limit, nil
}

func SubscriptionUploadBlocked(db *sql.DB, username string) (bool, error) {
	sub, err := GetActiveSubscription(db, username)
	if err != nil {
		return false, err
	}
	return SubscriptionBlocksUpload(sub), nil
}
