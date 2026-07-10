package models

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	DevSubscriptionPlanID = "plan_dev_250gb"
	DevPlanStorageBytes   = int64(250) << 30 // 250 GiB
)

type SubscriptionPlan struct {
	PlanID            string    `json:"plan_id"`
	Name              string    `json:"name"`
	Description       string    `json:"description,omitempty"`
	PriceUSDCents     int       `json:"price_usd_cents"`
	StorageLimitBytes int64     `json:"storage_limit_bytes"`
	SortOrder         int       `json:"sort_order"`
	IsActive          bool      `json:"is_active"`
	IsPublic          bool      `json:"is_public"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	UpdatedBy         string    `json:"updated_by,omitempty"`
}

type SubscriptionCheckout struct {
	CheckoutID      string    `json:"checkout_id"`
	Username        string    `json:"username"`
	PlanID          string    `json:"plan_id"`
	Status          string    `json:"status"`
	SubscriptionRef string    `json:"subscription_ref,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type UserSubscription struct {
	ID                 int64      `json:"id"`
	Username           string     `json:"username"`
	PlanID             string     `json:"plan_id"`
	CheckoutID         string     `json:"checkout_id"`
	SubscriptionRef    string     `json:"subscription_ref"`
	Status             string     `json:"status"`
	Source             string     `json:"source"`
	CurrentPeriodStart time.Time  `json:"current_period_start"`
	CurrentPeriodEnd   time.Time  `json:"current_period_end"`
	CancelAtPeriodEnd  bool       `json:"cancel_at_period_end"`
	CanceledAt         *time.Time `json:"canceled_at,omitempty"`
	PastDueSince       *time.Time `json:"past_due_since,omitempty"`
	GiftNote           string     `json:"gift_note,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	PlanName           string     `json:"plan_name,omitempty"`
	PlanPriceUSDCents  int        `json:"plan_price_usd_cents,omitempty"`
	PlanStorageBytes   int64      `json:"plan_storage_limit_bytes,omitempty"`
}

func ListPublicSubscriptionPlans(db *sql.DB) ([]SubscriptionPlan, error) {
	rows, err := db.Query(`
		SELECT plan_id, name, COALESCE(description,''), price_usd_cents, storage_limit_bytes,
		       sort_order, is_active, is_public, created_at, updated_at, COALESCE(updated_by,'')
		FROM subscription_plans
		WHERE is_active = 1 AND is_public = 1
		ORDER BY sort_order ASC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var plans []SubscriptionPlan
	for rows.Next() {
		var p SubscriptionPlan
		if err := scanSubscriptionPlan(rows, &p); err != nil {
			return nil, err
		}
		plans = append(plans, p)
	}
	return plans, rows.Err()
}

func ListAllSubscriptionPlans(db *sql.DB) ([]SubscriptionPlan, error) {
	rows, err := db.Query(`
		SELECT plan_id, name, COALESCE(description,''), price_usd_cents, storage_limit_bytes,
		       sort_order, is_active, is_public, created_at, updated_at, COALESCE(updated_by,'')
		FROM subscription_plans
		ORDER BY sort_order ASC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var plans []SubscriptionPlan
	for rows.Next() {
		var p SubscriptionPlan
		if err := scanSubscriptionPlan(rows, &p); err != nil {
			return nil, err
		}
		plans = append(plans, p)
	}
	return plans, rows.Err()
}

func GetSubscriptionPlan(db *sql.DB, planID string) (*SubscriptionPlan, error) {
	var p SubscriptionPlan
	row := db.QueryRow(`
		SELECT plan_id, name, COALESCE(description,''), price_usd_cents, storage_limit_bytes,
		       sort_order, is_active, is_public, created_at, updated_at, COALESCE(updated_by,'')
		FROM subscription_plans WHERE plan_id = ?`, planID)
	if err := scanSubscriptionPlan(row, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

type subscriptionPlanScanner interface {
	Scan(dest ...interface{}) error
}

func scanSubscriptionPlan(scanner subscriptionPlanScanner, p *SubscriptionPlan) error {
	var priceRaw, storageRaw, sortRaw interface{}
	var isActiveRaw, isPublicRaw interface{}
	var createdAtStr, updatedAtStr string
	if err := scanner.Scan(
		&p.PlanID, &p.Name, &p.Description, &priceRaw, &storageRaw,
		&sortRaw, &isActiveRaw, &isPublicRaw, &createdAtStr, &updatedAtStr, &p.UpdatedBy,
	); err != nil {
		return err
	}
	p.PriceUSDCents = ScanInt(priceRaw)
	p.StorageLimitBytes = ScanInt64(storageRaw)
	p.SortOrder = ScanInt(sortRaw)
	p.IsActive = ScanBool(isActiveRaw)
	p.IsPublic = ScanBool(isPublicRaw)
	p.CreatedAt = parseDBTimestamp(createdAtStr)
	p.UpdatedAt = parseDBTimestamp(updatedAtStr)
	return nil
}

func UpsertSubscriptionPlan(db *sql.DB, p *SubscriptionPlan) error {
	active := 0
	if p.IsActive {
		active = 1
	}
	public := 0
	if p.IsPublic {
		public = 1
	}
	_, err := db.Exec(`
		INSERT INTO subscription_plans
		  (plan_id, name, description, price_usd_cents, storage_limit_bytes,
		   sort_order, is_active, is_public, updated_by, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(plan_id) DO UPDATE SET
		  name = excluded.name,
		  description = excluded.description,
		  price_usd_cents = excluded.price_usd_cents,
		  storage_limit_bytes = excluded.storage_limit_bytes,
		  sort_order = excluded.sort_order,
		  is_active = excluded.is_active,
		  is_public = excluded.is_public,
		  updated_by = excluded.updated_by,
		  updated_at = CURRENT_TIMESTAMP`,
		p.PlanID, p.Name, p.Description, p.PriceUSDCents, p.StorageLimitBytes,
		p.SortOrder, active, public, p.UpdatedBy,
	)
	return err
}

func SeedDevSubscriptionPlan(db *sql.DB) error {
	p := &SubscriptionPlan{
		PlanID:            DevSubscriptionPlanID,
		Name:              "250 GB",
		Description:       "Dev/e2e subscription tier",
		PriceUSDCents:     500,
		StorageLimitBytes: DevPlanStorageBytes,
		SortOrder:         0,
		IsActive:          true,
		IsPublic:          true,
		UpdatedBy:         "system",
	}
	return UpsertSubscriptionPlan(db, p)
}

func CreateSubscriptionCheckout(db *sql.DB, checkout *SubscriptionCheckout) error {
	_, err := db.Exec(`
		INSERT INTO subscription_checkouts (checkout_id, username, plan_id, status)
		VALUES (?, ?, ?, ?)`,
		checkout.CheckoutID, checkout.Username, checkout.PlanID, checkout.Status,
	)
	return err
}

func GetSubscriptionCheckout(db *sql.DB, checkoutID string) (*SubscriptionCheckout, error) {
	var c SubscriptionCheckout
	var createdAtStr, updatedAtStr string
	err := db.QueryRow(`
		SELECT checkout_id, username, plan_id, status,
		       COALESCE(subscription_ref,''), created_at, updated_at
		FROM subscription_checkouts WHERE checkout_id = ?`, checkoutID).Scan(
		&c.CheckoutID, &c.Username, &c.PlanID, &c.Status,
		&c.SubscriptionRef, &createdAtStr, &updatedAtStr,
	)
	if err != nil {
		return nil, err
	}
	c.CreatedAt = parseDBTimestamp(createdAtStr)
	c.UpdatedAt = parseDBTimestamp(updatedAtStr)
	return &c, nil
}

func UpdateSubscriptionCheckout(db *sql.DB, checkoutID, status, subscriptionRef string) error {
	_, err := db.Exec(`
		UPDATE subscription_checkouts
		SET status = ?, subscription_ref = COALESCE(NULLIF(?, ''), subscription_ref),
		    updated_at = CURRENT_TIMESTAMP
		WHERE checkout_id = ?`,
		status, subscriptionRef, checkoutID,
	)
	return err
}

func activeSubscriptionQuery() string {
	return `
		SELECT us.id, us.username, us.plan_id, us.checkout_id, us.subscription_ref,
		       us.status, us.source, us.current_period_start, us.current_period_end,
		       us.cancel_at_period_end, us.canceled_at, us.past_due_since,
		       COALESCE(us.gift_note,''), us.created_at, us.updated_at,
		       sp.name, sp.price_usd_cents, sp.storage_limit_bytes
		FROM user_subscriptions us
		JOIN subscription_plans sp ON sp.plan_id = us.plan_id
		WHERE (
			us.status IN ('active', 'trialing', 'past_due')
			OR (us.status = 'canceled' AND us.current_period_end > datetime('now'))
		)`
}

func GetActiveUserSubscription(db *sql.DB, username string) (*UserSubscription, error) {
	return scanUserSubscription(db.QueryRow(activeSubscriptionQuery()+` AND us.username = ?
		ORDER BY us.updated_at DESC LIMIT 1`, username))
}

func GetUserSubscriptionBySubscriptionRef(db *sql.DB, subscriptionRef string) (*UserSubscription, error) {
	return scanUserSubscription(db.QueryRow(activeSubscriptionQuery()+` AND us.subscription_ref = ?`, subscriptionRef))
}

type userSubscriptionScanner interface {
	Scan(dest ...interface{}) error
}

func scanUserSubscription(row *sql.Row) (*UserSubscription, error) {
	return scanUserSubscriptionFields(row)
}

func scanUserSubscriptionFields(scanner userSubscriptionScanner) (*UserSubscription, error) {
	var s UserSubscription
	var idRaw interface{}
	var cancelAtPeriodEnd interface{}
	var canceledAt, pastDueSince sql.NullString
	var periodStartStr, periodEndStr, createdAtStr, updatedAtStr string
	var planPriceRaw, planStorageRaw interface{}
	err := scanner.Scan(
		&idRaw, &s.Username, &s.PlanID, &s.CheckoutID, &s.SubscriptionRef,
		&s.Status, &s.Source, &periodStartStr, &periodEndStr,
		&cancelAtPeriodEnd, &canceledAt, &pastDueSince,
		&s.GiftNote, &createdAtStr, &updatedAtStr,
		&s.PlanName, &planPriceRaw, &planStorageRaw,
	)
	if err != nil {
		return nil, err
	}
	s.ID = ScanInt64(idRaw)
	s.CurrentPeriodStart = parseDBTimestamp(periodStartStr)
	s.CurrentPeriodEnd = parseDBTimestamp(periodEndStr)
	s.CreatedAt = parseDBTimestamp(createdAtStr)
	s.UpdatedAt = parseDBTimestamp(updatedAtStr)
	s.PlanPriceUSDCents = ScanInt(planPriceRaw)
	s.PlanStorageBytes = ScanInt64(planStorageRaw)
	s.CancelAtPeriodEnd = ScanBool(cancelAtPeriodEnd)
	if canceledAt.Valid && canceledAt.String != "" {
		if t, err := parseFlexibleTime(canceledAt.String); err == nil {
			s.CanceledAt = &t
		}
	}
	if pastDueSince.Valid && pastDueSince.String != "" {
		if t, err := parseFlexibleTime(pastDueSince.String); err == nil {
			s.PastDueSince = &t
		}
	}
	return &s, nil
}

func parseFlexibleTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, errors.New("unparseable time")
}

func InsertUserSubscription(db *sql.DB, s *UserSubscription) error {
	cancelAt := 0
	if s.CancelAtPeriodEnd {
		cancelAt = 1
	}
	var canceledAt, pastDueSince interface{}
	if s.CanceledAt != nil {
		canceledAt = s.CanceledAt.UTC()
	}
	if s.PastDueSince != nil {
		pastDueSince = s.PastDueSince.UTC()
	}
	_, err := db.Exec(`
		INSERT INTO user_subscriptions
		  (username, plan_id, checkout_id, subscription_ref, status, source,
		   current_period_start, current_period_end, cancel_at_period_end,
		   canceled_at, past_due_since, gift_note)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.Username, s.PlanID, s.CheckoutID, s.SubscriptionRef, s.Status, s.Source,
		s.CurrentPeriodStart.UTC(), s.CurrentPeriodEnd.UTC(), cancelAt,
		canceledAt, pastDueSince, s.GiftNote,
	)
	return err
}

func UpdateUserSubscription(db *sql.DB, s *UserSubscription) error {
	cancelAt := 0
	if s.CancelAtPeriodEnd {
		cancelAt = 1
	}
	var canceledAt, pastDueSince interface{}
	if s.CanceledAt != nil {
		canceledAt = s.CanceledAt.UTC()
	}
	if s.PastDueSince != nil {
		pastDueSince = s.PastDueSince.UTC()
	}
	res, err := db.Exec(`
		UPDATE user_subscriptions SET
		  plan_id = ?, status = ?, current_period_start = ?, current_period_end = ?,
		  cancel_at_period_end = ?, canceled_at = ?, past_due_since = ?,
		  gift_note = COALESCE(NULLIF(?, ''), gift_note),
		  updated_at = CURRENT_TIMESTAMP
		WHERE subscription_ref = ?`,
		s.PlanID, s.Status, s.CurrentPeriodStart.UTC(), s.CurrentPeriodEnd.UTC(),
		cancelAt, canceledAt, pastDueSince, s.GiftNote, s.SubscriptionRef,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func ExpireUserSubscription(db *sql.DB, subscriptionRef string) error {
	_, err := db.Exec(`
		UPDATE user_subscriptions SET status = 'expired', updated_at = CURRENT_TIMESTAMP
		WHERE subscription_ref = ?`, subscriptionRef)
	return err
}

func ListBridgeSubscriptionsForReconcile(db *sql.DB, withinDays int) ([]UserSubscription, error) {
	rows, err := db.Query(`
		SELECT us.id, us.username, us.plan_id, us.checkout_id, us.subscription_ref,
		       us.status, us.source, us.current_period_start, us.current_period_end,
		       us.cancel_at_period_end, us.canceled_at, us.past_due_since,
		       COALESCE(us.gift_note,''), us.created_at, us.updated_at,
		       sp.name, sp.price_usd_cents, sp.storage_limit_bytes
		FROM user_subscriptions us
		JOIN subscription_plans sp ON sp.plan_id = us.plan_id
		WHERE us.source = 'bridge'
		  AND us.status IN ('active', 'trialing', 'past_due', 'canceled')
		  AND us.current_period_end <= datetime('now', ?)`,
		fmt.Sprintf("+%d days", withinDays))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UserSubscription
	for rows.Next() {
		s, err := scanUserSubscriptionFields(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

func ListExpiredGiftSubscriptions(db *sql.DB) ([]UserSubscription, error) {
	rows, err := db.Query(`
		SELECT us.id, us.username, us.plan_id, us.checkout_id, us.subscription_ref,
		       us.status, us.source, us.current_period_start, us.current_period_end,
		       us.cancel_at_period_end, us.canceled_at, us.past_due_since,
		       COALESCE(us.gift_note,''), us.created_at, us.updated_at,
		       sp.name, sp.price_usd_cents, sp.storage_limit_bytes
		FROM user_subscriptions us
		JOIN subscription_plans sp ON sp.plan_id = us.plan_id
		WHERE us.source = 'gift'
		  AND us.status IN ('active', 'trialing', 'past_due', 'canceled')
		  AND us.current_period_end <= datetime('now')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UserSubscription
	for rows.Next() {
		s, err := scanUserSubscriptionFields(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

func SubscriptionEventExists(db *sql.DB, eventID string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(1) FROM subscription_events WHERE event_id = ?`, eventID).Scan(&n)
	return n > 0, err
}

func InsertSubscriptionEvent(db *sql.DB, eventID, eventType, subscriptionRef, checkoutID, username, planID, payloadHash string) error {
	_, err := db.Exec(`
		INSERT INTO subscription_events
		  (event_id, event_type, subscription_ref, checkout_id, username, plan_id, payload_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		eventID, eventType, subscriptionRef, checkoutID, username, planID, payloadHash,
	)
	return err
}

func FormatPlanPriceUSD(cents int) string {
	return fmt.Sprintf("%.2f", float64(cents)/100.0)
}
