package billing

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
)

// ProcessPayment credits a user's balance for a provider-settled top-up.
// The provider invoice ID is stored as credit_transactions.transaction_id for idempotency.
func ProcessPayment(db *sql.DB, username string, amountMicrocents int64, providerTxID string, paymentType string) (*models.CreditTransaction, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("billing.ProcessPayment: begin tx: %w", err)
	}
	defer tx.Rollback()

	creditTx, err := processPaymentInTx(tx, username, amountMicrocents, providerTxID, paymentType)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("billing.ProcessPayment: commit: %w", err)
	}
	return creditTx, nil
}

func processPaymentInTx(tx *sql.Tx, username string, amountMicrocents int64, providerTxID string, paymentType string) (*models.CreditTransaction, error) {
	if username == "" {
		return nil, errors.New("billing.ProcessPayment: empty target username")
	}
	if amountMicrocents <= 0 {
		return nil, errors.New("billing.ProcessPayment: amount must be positive microcents")
	}
	if providerTxID == "" {
		return nil, errors.New("billing.ProcessPayment: provider transaction ID is required")
	}

	var currentBalanceF float64
	err := tx.QueryRow(
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
		providerTxID, username, amountMicrocents, newBalance, models.TransactionTypePayment, reason,
	)
	if err != nil {
		return nil, fmt.Errorf("billing.ProcessPayment: insert transaction (likely duplicate transaction_id): %w", err)
	}
	id, _ := res.LastInsertId()

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
		TransactionType:           models.TransactionTypePayment,
		Reason:                    &reason,
		CreatedAt:                 time.Now().UTC(),
	}, nil
}

// SettlePaymentInvoice credits the user and marks the local invoice paid in one transaction.
// If the invoice is already paid but lacks a matching credit row, only the credit is applied.
func SettlePaymentInvoice(db *sql.DB, invoice *models.PaymentInvoice, paymentType string) (*models.CreditTransaction, error) {
	if invoice == nil {
		return nil, errors.New("billing.SettlePaymentInvoice: nil invoice")
	}
	if invoice.ProviderInvoiceID == "" {
		return nil, errors.New("billing.SettlePaymentInvoice: missing provider invoice ID")
	}

	hasCredit, err := models.CreditTransactionExistsForProviderID(db, invoice.ProviderInvoiceID)
	if err != nil {
		return nil, fmt.Errorf("billing.SettlePaymentInvoice: check existing credit: %w", err)
	}
	if hasCredit {
		if invoice.Status != "paid" {
			if err := models.UpdatePaymentInvoiceStatus(db, invoice.InvoiceID, "paid"); err != nil {
				return nil, fmt.Errorf("billing.SettlePaymentInvoice: mark paid: %w", err)
			}
		}
		return nil, nil
	}

	if invoice.Status == "paid" {
		return ProcessPayment(db, invoice.Username, invoice.AmountUSDMicrocents, invoice.ProviderInvoiceID, paymentType)
	}
	if invoice.Status != "pending" {
		return nil, fmt.Errorf("billing.SettlePaymentInvoice: cannot settle invoice in status %s", invoice.Status)
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("billing.SettlePaymentInvoice: begin tx: %w", err)
	}
	defer tx.Rollback()

	creditTx, err := processPaymentInTx(tx, invoice.Username, invoice.AmountUSDMicrocents, invoice.ProviderInvoiceID, paymentType)
	if err != nil {
		if !isDuplicateTransactionIDError(err) {
			return nil, err
		}
		exists, chkErr := models.CreditTransactionExistsForProviderIDTx(tx, invoice.ProviderInvoiceID)
		if chkErr != nil {
			return nil, chkErr
		}
		if !exists {
			return nil, err
		}
		creditTx = nil
	}

	res, err := tx.Exec(
		`UPDATE payment_invoices SET status = 'paid', updated_at = CURRENT_TIMESTAMP
		 WHERE invoice_id = ? AND status = 'pending'`,
		invoice.InvoiceID,
	)
	if err != nil {
		return nil, fmt.Errorf("billing.SettlePaymentInvoice: update invoice status: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return nil, fmt.Errorf("billing.SettlePaymentInvoice: invoice %s is no longer pending", invoice.InvoiceID)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("billing.SettlePaymentInvoice: commit: %w", err)
	}
	return creditTx, nil
}

func isDuplicateTransactionIDError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate transaction_id")
}
