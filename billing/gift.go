package billing

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
)

// GiftCredits adds positive microcent credit to a user's balance and records
// it as a typed 'gift' transaction in the audit log. This is the canonical
// path for any admin-initiated positive balance adjustment, distinct from
// future paid top-ups (which will use payment_* transaction types).
//
// Validation:
//   - amountUSDMicrocents must be > 0.
//   - reason must be non-empty.
//   - adminUsername must be non-empty.
//
// The credit_transactions row's metadata is empty for gifts -- gifts carry
// the operator's reason in the reason column and the responsible admin in
// admin_username, with no other observable per-gift state.
//
// On a successful gift, emits a logging.LogSecurityEvent so the operation
// shows up in the security event log alongside admin actions.
func GiftCredits(db *sql.DB, username string, amountUSDMicrocents int64, reason, adminUsername string) (*models.CreditTransaction, error) {
	if username == "" {
		return nil, errors.New("billing.GiftCredits: empty target username")
	}
	if amountUSDMicrocents <= 0 {
		return nil, errors.New("billing.GiftCredits: amount must be positive microcents")
	}
	if reason == "" {
		return nil, errors.New("billing.GiftCredits: reason is required")
	}
	if adminUsername == "" {
		return nil, errors.New("billing.GiftCredits: admin username is required")
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("billing.GiftCredits: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Ensure user_credits row exists (create with zero balance if not).
	// rqlite float64 scan for BIGINT balance column.
	var currentBalanceF float64
	err = tx.QueryRow(
		`SELECT balance_usd_microcents FROM user_credits WHERE username = ?`,
		username,
	).Scan(&currentBalanceF)
	currentBalance := int64(currentBalanceF)
	if err == sql.ErrNoRows {
		_, insErr := tx.Exec(
			`INSERT INTO user_credits (username, balance_usd_microcents, created_at, updated_at)
			 VALUES (?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			username,
		)
		if insErr != nil {
			return nil, fmt.Errorf("billing.GiftCredits: create user_credits: %w", insErr)
		}
		currentBalance = 0
	} else if err != nil {
		return nil, fmt.Errorf("billing.GiftCredits: read balance: %w", err)
	}

	newBalance := currentBalance + amountUSDMicrocents
	_, err = tx.Exec(
		`UPDATE user_credits SET balance_usd_microcents = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE username = ?`,
		newBalance, username,
	)
	if err != nil {
		return nil, fmt.Errorf("billing.GiftCredits: update balance: %w", err)
	}

	res, err := tx.Exec(`
		INSERT INTO credit_transactions
		  (username, amount_usd_microcents, balance_after_usd_microcents,
		   transaction_type, reason, admin_username, created_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		username, amountUSDMicrocents, newBalance, models.TransactionTypeGift, reason, adminUsername,
	)
	if err != nil {
		return nil, fmt.Errorf("billing.GiftCredits: insert transaction: %w", err)
	}
	id, _ := res.LastInsertId()

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("billing.GiftCredits: commit: %w", err)
	}

	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":         "billing_gift",
			"target_username":   username,
			"amount_microcents": amountUSDMicrocents,
			"new_balance":       newBalance,
		},
	)

	reasonCopy := reason
	adminCopy := adminUsername
	return &models.CreditTransaction{
		ID:                        id,
		Username:                  username,
		AmountUSDMicrocents:       amountUSDMicrocents,
		BalanceAfterUSDMicrocents: newBalance,
		TransactionType:           models.TransactionTypeGift,
		Reason:                    &reasonCopy,
		AdminUsername:             &adminCopy,
		CreatedAt:                 time.Now().UTC(),
	}, nil
}
