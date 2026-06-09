package billing

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
)

// ProcessPayment processes the credit ledger payment settlement securely within a strict SQLite transaction bracket.
// It locks the user_credits record, inserts the transaction row ensuring uniqueness of the transaction_id, and adds the balance.
func ProcessPayment(db *sql.DB, username string, amountMicrocents int64, providerTxID string, paymentType string) (*models.CreditTransaction, error) {
	if username == "" {
		return nil, errors.New("billing.ProcessPayment: empty target username")
	}
	if amountMicrocents <= 0 {
		return nil, errors.New("billing.ProcessPayment: amount must be positive microcents")
	}
	if providerTxID == "" {
		return nil, errors.New("billing.ProcessPayment: provider transaction ID is required")
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("billing.ProcessPayment: begin tx: %w", err)
	}
	defer tx.Rollback()

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
			return nil, fmt.Errorf("billing.ProcessPayment: create user_credits: %w", insErr)
		}
		currentBalance = 0
	} else if err != nil {
		return nil, fmt.Errorf("billing.ProcessPayment: read balance: %w", err)
	}

	newBalance := currentBalance + amountMicrocents
	_, err = tx.Exec(
		`UPDATE user_credits SET balance_usd_microcents = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE username = ?`,
		newBalance, username,
	)
	if err != nil {
		return nil, fmt.Errorf("billing.ProcessPayment: update balance: %w", err)
	}

	reason := fmt.Sprintf("Payment top-up via %s", paymentType)
	res, err := tx.Exec(`
		INSERT INTO credit_transactions
		  (transaction_id, username, amount_usd_microcents, balance_after_usd_microcents,
		   transaction_type, reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		providerTxID, username, amountMicrocents, newBalance, "gift", reason,
	)
	if err != nil {
		return nil, fmt.Errorf("billing.ProcessPayment: insert transaction (likely duplicate transaction_id): %w", err)
	}
	id, _ := res.LastInsertId()

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("billing.ProcessPayment: commit: %w", err)
	}

	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&username,
		nil,
		map[string]interface{}{
			"operation":         "billing_payment",
			"target_username":   username,
			"amount_microcents": amountMicrocents,
			"new_balance":       newBalance,
			"transaction_id":    providerTxID,
			"payment_type":      paymentType,
		},
	)

	return &models.CreditTransaction{
		ID:                        id,
		TransactionID:             &providerTxID,
		Username:                  username,
		AmountUSDMicrocents:       amountMicrocents,
		BalanceAfterUSDMicrocents: newBalance,
		TransactionType:           "gift",
		Reason:                    &reason,
		CreatedAt:                 time.Now().UTC(),
	}, nil
}
