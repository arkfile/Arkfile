package models

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/84adam/arkfile/logging"
)

// UserCredit represents a user's credit balance
type UserCredit struct {
	ID              int64     `json:"id"`
	Username        string    `json:"username"`
	BalanceUSDCents int64     `json:"balance_usd_cents"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// CreditTransaction represents a credit transaction record
type CreditTransaction struct {
	ID                   int64     `json:"id"`
	TransactionID        *string   `json:"transaction_id,omitempty"`
	Username             string    `json:"username"`
	AmountUSDCents       int64     `json:"amount_usd_cents"`
	BalanceAfterUSDCents int64     `json:"balance_after_usd_cents"`
	TransactionType      string    `json:"transaction_type"`
	Reason               *string   `json:"reason,omitempty"`
	AdminUsername        *string   `json:"admin_username,omitempty"`
	Metadata             *string   `json:"metadata,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

// Transaction types
const (
	TransactionTypeCredit     = "credit"
	TransactionTypeDebit      = "debit"
	TransactionTypeAdjustment = "adjustment"
	TransactionTypeRefund     = "refund"
)

// GetOrCreateUserCredits gets existing credits or creates a new record with 0 balance
func GetOrCreateUserCredits(db *sql.DB, username string) (*UserCredit, error) {
	// Try to get existing record
	credits, err := GetUserCredits(db, username)
	if err == nil {
		return credits, nil
	}

	// If not found, create new record
	if err == sql.ErrNoRows {
		return CreateUserCredits(db, username)
	}

	// Other error occurred
	return nil, fmt.Errorf("failed to get or create user credits: %w", err)
}

// GetUserCredits retrieves a user's credit balance
func GetUserCredits(db *sql.DB, username string) (*UserCredit, error) {
	credits := &UserCredit{}
	var createdAtStr, updatedAtStr string

	query := `SELECT id, username, balance_usd_cents, created_at, updated_at
	          FROM user_credits WHERE username = ?`

	err := db.QueryRow(query, username).Scan(
		&credits.ID, &credits.Username, &credits.BalanceUSDCents,
		&createdAtStr, &updatedAtStr,
	)

	if err != nil {
		return nil, err
	}

	// Parse timestamps
	if createdAtStr != "" {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", createdAtStr); parseErr == nil {
			credits.CreatedAt = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
			credits.CreatedAt = parsedTime
		}
	}

	if updatedAtStr != "" {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", updatedAtStr); parseErr == nil {
			credits.UpdatedAt = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, updatedAtStr); parseErr == nil {
			credits.UpdatedAt = parsedTime
		}
	}

	return credits, nil
}

// CreateUserCredits creates a new user credit record with 0 balance
func CreateUserCredits(db *sql.DB, username string) (*UserCredit, error) {
	now := time.Now()

	result, err := db.Exec(
		`INSERT INTO user_credits (username, balance_usd_cents, created_at, updated_at)
		 VALUES (?, 0, ?, ?)`,
		username, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user credits: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get credit record ID: %w", err)
	}

	return &UserCredit{
		ID:              id,
		Username:        username,
		BalanceUSDCents: 0,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// AddCredits adds credits to a user's balance (creates transaction record)
func AddCredits(db *sql.DB, username string, amountCents int64, transactionType, reason string, transactionID *string, adminUsername *string) (*CreditTransaction, error) {
	if amountCents <= 0 {
		return nil, errors.New("credit amount must be positive")
	}

	// Start transaction to ensure atomicity
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Get or create user credits
	credits, err := GetOrCreateUserCredits(db, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credits: %w", err)
	}

	// Calculate new balance
	newBalance := credits.BalanceUSDCents + amountCents

	// Update user credits balance
	_, err = tx.Exec(
		`UPDATE user_credits SET balance_usd_cents = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
		newBalance, username,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update user credits: %w", err)
	}

	// Create transaction record
	transactionResult, err := tx.Exec(`
		INSERT INTO credit_transactions 
		(transaction_id, username, amount_usd_cents, balance_after_usd_cents, 
		 transaction_type, reason, admin_username, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		transactionID, username, amountCents, newBalance, transactionType, reason, adminUsername,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction record: %w", err)
	}

	transactionRecordID, err := transactionResult.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction record ID: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit credit transaction: %w", err)
	}

	// Log the credit addition
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		adminUsername,
		nil,
		map[string]interface{}{
			"operation":        "credit_addition",
			"target_username":  username,
			"amount_cents":     amountCents,
			"new_balance":      newBalance,
			"transaction_type": transactionType,
			"transaction_id":   transactionID,
		},
	)

	return &CreditTransaction{
		ID:                   transactionRecordID,
		TransactionID:        transactionID,
		Username:             username,
		AmountUSDCents:       amountCents,
		BalanceAfterUSDCents: newBalance,
		TransactionType:      transactionType,
		Reason:               &reason,
		AdminUsername:        adminUsername,
		CreatedAt:            time.Now(),
	}, nil
}

// DebitCredits removes credits from a user's balance (creates transaction record)
func DebitCredits(db *sql.DB, username string, amountCents int64, transactionType, reason string, transactionID *string, adminUsername *string) (*CreditTransaction, error) {
	if amountCents <= 0 {
		return nil, errors.New("debit amount must be positive")
	}

	// Start transaction to ensure atomicity
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Get user credits
	credits, err := GetUserCredits(db, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user has no credit balance")
		}
		return nil, fmt.Errorf("failed to get user credits: %w", err)
	}

	// Check if sufficient balance
	newBalance := credits.BalanceUSDCents - amountCents
	if newBalance < 0 {
		return nil, fmt.Errorf("insufficient credits: balance %d cents, requested %d cents", credits.BalanceUSDCents, amountCents)
	}

	// Update user credits balance
	_, err = tx.Exec(
		`UPDATE user_credits SET balance_usd_cents = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
		newBalance, username,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update user credits: %w", err)
	}

	// Create transaction record (negative amount for debit)
	transactionResult, err := tx.Exec(`
		INSERT INTO credit_transactions 
		(transaction_id, username, amount_usd_cents, balance_after_usd_cents, 
		 transaction_type, reason, admin_username, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		transactionID, username, -amountCents, newBalance, transactionType, reason, adminUsername,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction record: %w", err)
	}

	transactionRecordID, err := transactionResult.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction record ID: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit debit transaction: %w", err)
	}

	// Log the credit debit
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		adminUsername,
		nil,
		map[string]interface{}{
			"operation":        "credit_debit",
			"target_username":  username,
			"amount_cents":     amountCents,
			"new_balance":      newBalance,
			"transaction_type": transactionType,
			"transaction_id":   transactionID,
		},
	)

	return &CreditTransaction{
		ID:                   transactionRecordID,
		TransactionID:        transactionID,
		Username:             username,
		AmountUSDCents:       -amountCents, // Negative for debit
		BalanceAfterUSDCents: newBalance,
		TransactionType:      transactionType,
		Reason:               &reason,
		AdminUsername:        adminUsername,
		CreatedAt:            time.Now(),
	}, nil
}

// SetCredits sets a user's credit balance to a specific amount (admin only)
func SetCredits(db *sql.DB, username string, newBalanceCents int64, reason string, adminUsername string) (*CreditTransaction, error) {
	if newBalanceCents < 0 {
		return nil, errors.New("balance cannot be negative")
	}

	// Start transaction to ensure atomicity
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Get or create user credits
	credits, err := GetOrCreateUserCredits(db, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credits: %w", err)
	}

	// Calculate the adjustment amount
	adjustmentAmount := newBalanceCents - credits.BalanceUSDCents

	// Update user credits balance
	_, err = tx.Exec(
		`UPDATE user_credits SET balance_usd_cents = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`,
		newBalanceCents, username,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update user credits: %w", err)
	}

	// Create transaction record
	transactionResult, err := tx.Exec(`
		INSERT INTO credit_transactions 
		(username, amount_usd_cents, balance_after_usd_cents, 
		 transaction_type, reason, admin_username, created_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		username, adjustmentAmount, newBalanceCents, TransactionTypeAdjustment, reason, adminUsername,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction record: %w", err)
	}

	transactionRecordID, err := transactionResult.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction record ID: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit balance adjustment: %w", err)
	}

	// Log the balance adjustment
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":         "credit_balance_adjustment",
			"target_username":   username,
			"old_balance":       credits.BalanceUSDCents,
			"new_balance":       newBalanceCents,
			"adjustment_amount": adjustmentAmount,
		},
	)

	return &CreditTransaction{
		ID:                   transactionRecordID,
		Username:             username,
		AmountUSDCents:       adjustmentAmount,
		BalanceAfterUSDCents: newBalanceCents,
		TransactionType:      TransactionTypeAdjustment,
		Reason:               &reason,
		AdminUsername:        &adminUsername,
		CreatedAt:            time.Now(),
	}, nil
}

// GetUserTransactions retrieves credit transactions for a user
func GetUserTransactions(db *sql.DB, username string, limit int, offset int) ([]*CreditTransaction, error) {
	if limit <= 0 {
		limit = 50 // Default limit
	}

	query := `SELECT id, transaction_id, username, amount_usd_cents, 
	                 balance_after_usd_cents, transaction_type, reason, 
	                 admin_username, metadata, created_at
	          FROM credit_transactions 
	          WHERE username = ? 
	          ORDER BY created_at DESC 
	          LIMIT ? OFFSET ?`

	rows, err := db.Query(query, username, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query user transactions: %w", err)
	}
	defer rows.Close()

	var transactions []*CreditTransaction
	for rows.Next() {
		transaction := &CreditTransaction{}
		var transactionID, reason, adminUsername, metadata sql.NullString
		var createdAtStr string

		err := rows.Scan(
			&transaction.ID, &transactionID, &transaction.Username,
			&transaction.AmountUSDCents, &transaction.BalanceAfterUSDCents,
			&transaction.TransactionType, &reason, &adminUsername,
			&metadata, &createdAtStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan transaction row: %w", err)
		}

		// Handle nullable fields
		if transactionID.Valid {
			transaction.TransactionID = &transactionID.String
		}
		if reason.Valid {
			transaction.Reason = &reason.String
		}
		if adminUsername.Valid {
			transaction.AdminUsername = &adminUsername.String
		}
		if metadata.Valid {
			transaction.Metadata = &metadata.String
		}

		// Parse timestamp
		if createdAtStr != "" {
			if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", createdAtStr); parseErr == nil {
				transaction.CreatedAt = parsedTime
			} else if parsedTime, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
				transaction.CreatedAt = parsedTime
			}
		}

		transactions = append(transactions, transaction)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating transaction rows: %w", err)
	}

	return transactions, nil
}

// GetAllUserCredits retrieves all user credit balances (admin only)
func GetAllUserCredits(db *sql.DB) ([]*UserCredit, error) {
	query := `SELECT id, username, balance_usd_cents, created_at, updated_at
	          FROM user_credits 
	          ORDER BY username ASC`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all user credits: %w", err)
	}
	defer rows.Close()

	var credits []*UserCredit
	for rows.Next() {
		credit := &UserCredit{}
		var createdAtStr, updatedAtStr string

		err := rows.Scan(
			&credit.ID, &credit.Username, &credit.BalanceUSDCents,
			&createdAtStr, &updatedAtStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credit row: %w", err)
		}

		// Parse timestamps
		if createdAtStr != "" {
			if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", createdAtStr); parseErr == nil {
				credit.CreatedAt = parsedTime
			} else if parsedTime, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
				credit.CreatedAt = parsedTime
			}
		}

		if updatedAtStr != "" {
			if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", updatedAtStr); parseErr == nil {
				credit.UpdatedAt = parsedTime
			} else if parsedTime, parseErr := time.Parse(time.RFC3339, updatedAtStr); parseErr == nil {
				credit.UpdatedAt = parsedTime
			}
		}

		credits = append(credits, credit)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating credit rows: %w", err)
	}

	return credits, nil
}

// Helper functions for displaying credits in human-readable format

// FormatCreditsUSD formats credit cents as USD string (e.g., 1234 cents -> "$12.34")
func FormatCreditsUSD(cents int64) string {
	dollars := cents / 100
	remainingCents := cents % 100
	return fmt.Sprintf("$%d.%02d", dollars, remainingCents)
}

// ParseCreditsFromUSD parses USD string to cents (e.g., "12.34" -> 1234 cents)
func ParseCreditsFromUSD(usdAmount string) (int64, error) {
	// Remove $ if present
	if len(usdAmount) > 0 && usdAmount[0] == '$' {
		usdAmount = usdAmount[1:]
	}

	// Parse as float then convert to cents
	var dollars float64
	_, err := fmt.Sscanf(usdAmount, "%f", &dollars)
	if err != nil {
		return 0, fmt.Errorf("invalid USD amount format: %w", err)
	}

	if dollars < 0 {
		return 0, errors.New("amount cannot be negative")
	}

	// Convert to cents, round to avoid floating point precision issues
	cents := int64(dollars*100 + 0.5)
	return cents, nil
}

// CreditsSummaryResponse represents a summary of user's credit status
type CreditsSummaryResponse struct {
	Username           string               `json:"username"`
	Balance            *UserCredit          `json:"balance"`
	RecentTransactions []*CreditTransaction `json:"recent_transactions"`
	FormattedBalance   string               `json:"formatted_balance"`
}

// GetUserCreditsSummary gets a complete summary of user's credit status
func GetUserCreditsSummary(db *sql.DB, username string) (*CreditsSummaryResponse, error) {
	// Get user credits
	credits, err := GetOrCreateUserCredits(db, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credits: %w", err)
	}

	// Get recent transactions (limit 10)
	transactions, err := GetUserTransactions(db, username, 10, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent transactions: %w", err)
	}

	return &CreditsSummaryResponse{
		Username:           username,
		Balance:            credits,
		RecentTransactions: transactions,
		FormattedBalance:   FormatCreditsUSD(credits.BalanceUSDCents),
	}, nil
}
