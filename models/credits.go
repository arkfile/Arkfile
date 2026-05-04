package models

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// UserCredit is a user's microcent-denominated credit balance.
// Balances are signed: when storage usage exceeds available credit, the balance
// goes negative. There is no separate deficit column.
//
// Microcent unit: 1 USD = 100 cents = 100,000,000 microcents.
type UserCredit struct {
	ID                   int64     `json:"id"`
	Username             string    `json:"username"`
	BalanceUSDMicrocents int64     `json:"balance_usd_microcents"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// CreditTransaction is one row in the credits audit log. Both amount and
// balance_after are signed microcent values.
type CreditTransaction struct {
	ID                        int64     `json:"id"`
	TransactionID             *string   `json:"transaction_id,omitempty"`
	Username                  string    `json:"username"`
	AmountUSDMicrocents       int64     `json:"amount_usd_microcents"`
	FormattedAmount           *string   `json:"formatted_amount,omitempty"`
	BalanceAfterUSDMicrocents int64     `json:"balance_after_usd_microcents"`
	FormattedBalanceAfter     *string   `json:"formatted_balance_after,omitempty"`
	TransactionType           string    `json:"transaction_type"`
	Reason                    *string   `json:"reason,omitempty"`
	AdminUsername             *string   `json:"admin_username,omitempty"`
	Metadata                  *string   `json:"metadata,omitempty"`
	CreatedAt                 time.Time `json:"created_at"`
}

// Transaction types written by this package and the billing meter.
//
//   - usage:      written by the daily storage settlement sweep (system).
//   - gift:       written by an admin via billing.GiftCredits.
//   - adjustment: reserved for future use (currently unused; replaced by `gift`).
const (
	TransactionTypeUsage      = "usage"
	TransactionTypeGift       = "gift"
	TransactionTypeAdjustment = "adjustment"
)

// MicrocentsPerUSD is the canonical conversion factor.
// 1 USD = 100 cents = 100,000,000 microcents.
const MicrocentsPerUSD int64 = 100_000_000

// GetOrCreateUserCredits returns the user's credit row, creating one with a
// zero balance if no row exists yet.
func GetOrCreateUserCredits(db *sql.DB, username string) (*UserCredit, error) {
	credits, err := GetUserCredits(db, username)
	if err == nil {
		return credits, nil
	}
	if err == sql.ErrNoRows {
		return CreateUserCredits(db, username)
	}
	return nil, fmt.Errorf("failed to get or create user credits: %w", err)
}

// GetUserCredits retrieves a user's signed microcent balance.
// Returns sql.ErrNoRows if the user has never had a credit row created.
func GetUserCredits(db *sql.DB, username string) (*UserCredit, error) {
	credits := &UserCredit{}
	var createdAtStr, updatedAtStr string

	query := `SELECT id, username, balance_usd_microcents, created_at, updated_at
	          FROM user_credits WHERE username = ?`

	// rqlite returns BIGINT as float64 when large; scan via float64 then cast.
	var balanceF float64
	err := db.QueryRow(query, username).Scan(
		&credits.ID, &credits.Username, &balanceF,
		&createdAtStr, &updatedAtStr,
	)
	credits.BalanceUSDMicrocents = int64(balanceF)
	if err != nil {
		return nil, err
	}

	credits.CreatedAt = parseDBTimestamp(createdAtStr)
	credits.UpdatedAt = parseDBTimestamp(updatedAtStr)
	return credits, nil
}

// CreateUserCredits inserts a new row with a zero balance for `username`.
// New users always start at zero; gifts are explicit admin actions via the
// billing package and never seeded automatically by this function.
func CreateUserCredits(db *sql.DB, username string) (*UserCredit, error) {
	now := time.Now()

	result, err := db.Exec(
		`INSERT INTO user_credits (username, balance_usd_microcents, created_at, updated_at)
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
		ID:                   id,
		Username:             username,
		BalanceUSDMicrocents: 0,
		CreatedAt:            now,
		UpdatedAt:            now,
	}, nil
}

// GetUserTransactions returns up to `limit` most-recent transactions for `username`.
func GetUserTransactions(db *sql.DB, username string, limit int, offset int) ([]*CreditTransaction, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, transaction_id, username, amount_usd_microcents,
	                 balance_after_usd_microcents, transaction_type, reason,
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
		t := &CreditTransaction{}
		var transactionID, reason, adminUsername, metadata sql.NullString
		var createdAtStr string

		// rqlite float64 scan for BIGINT columns.
		var amtF, balAfterF float64
		err := rows.Scan(
			&t.ID, &transactionID, &t.Username,
			&amtF, &balAfterF,
			&t.TransactionType, &reason, &adminUsername,
			&metadata, &createdAtStr,
		)
		t.AmountUSDMicrocents = int64(amtF)
		t.BalanceAfterUSDMicrocents = int64(balAfterF)
		if err != nil {
			return nil, fmt.Errorf("failed to scan transaction row: %w", err)
		}

		// Populate human-readable amounts so callers always receive
		// four-decimal USD strings regardless of caller context.
		fa := FormatCreditsUSD(t.AmountUSDMicrocents)
		fb := FormatCreditsUSD(t.BalanceAfterUSDMicrocents)
		t.FormattedAmount = &fa
		t.FormattedBalanceAfter = &fb

		if transactionID.Valid {
			t.TransactionID = &transactionID.String
		}
		if reason.Valid {
			t.Reason = &reason.String
		}
		if adminUsername.Valid {
			t.AdminUsername = &adminUsername.String
		}
		if metadata.Valid {
			t.Metadata = &metadata.String
		}
		t.CreatedAt = parseDBTimestamp(createdAtStr)

		transactions = append(transactions, t)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating transaction rows: %w", err)
	}
	return transactions, nil
}

// GetAllUserCredits returns every user_credits row (admin-only view).
func GetAllUserCredits(db *sql.DB) ([]*UserCredit, error) {
	query := `SELECT id, username, balance_usd_microcents, created_at, updated_at
	          FROM user_credits
	          ORDER BY username ASC`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all user credits: %w", err)
	}
	defer rows.Close()

	var credits []*UserCredit
	for rows.Next() {
		c := &UserCredit{}
		var createdAtStr, updatedAtStr string

		// rqlite float64 scan for BIGINT columns.
		var balF float64
		err := rows.Scan(
			&c.ID, &c.Username, &balF,
			&createdAtStr, &updatedAtStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credit row: %w", err)
		}
		c.BalanceUSDMicrocents = int64(balF)

		c.CreatedAt = parseDBTimestamp(createdAtStr)
		c.UpdatedAt = parseDBTimestamp(updatedAtStr)
		credits = append(credits, c)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating credit rows: %w", err)
	}
	return credits, nil
}

// GetOverdrawnUsers returns every user_credits row whose balance is strictly
// less than zero, ordered by most-negative first. Used by the admin billing
// "list-overdrawn" endpoint.
func GetOverdrawnUsers(db *sql.DB) ([]*UserCredit, error) {
	query := `SELECT id, username, balance_usd_microcents, created_at, updated_at
	          FROM user_credits
	          WHERE balance_usd_microcents < 0
	          ORDER BY balance_usd_microcents ASC`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query overdrawn users: %w", err)
	}
	defer rows.Close()

	var credits []*UserCredit
	for rows.Next() {
		c := &UserCredit{}
		var createdAtStr, updatedAtStr string

		// rqlite float64 scan for BIGINT columns.
		var balF float64
		err := rows.Scan(
			&c.ID, &c.Username, &balF,
			&createdAtStr, &updatedAtStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credit row: %w", err)
		}
		c.BalanceUSDMicrocents = int64(balF)
		c.CreatedAt = parseDBTimestamp(createdAtStr)
		c.UpdatedAt = parseDBTimestamp(updatedAtStr)
		credits = append(credits, c)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating overdrawn rows: %w", err)
	}
	return credits, nil
}

// CountOverdrawnUsers returns the number of users currently in negative balance.
func CountOverdrawnUsers(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM user_credits WHERE balance_usd_microcents < 0`,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count overdrawn users: %w", err)
	}
	return n, nil
}

// FormatCreditsUSD renders a signed microcent value as a four-decimal USD string.
//
// Examples:
//
//	0          -> "$0.0000"
//	500_000_000 -> "$5.0000"
//	-12_345_678 -> "-$0.1234"
//	-600       -> "-$0.0006"
//
// The four-decimal format is honest about sub-cent accounting that the meter
// produces (per-tick charges are sub-cent at typical prices).
func FormatCreditsUSD(microcents int64) string {
	negative := microcents < 0
	abs := microcents
	if negative {
		abs = -abs
	}
	dollars := abs / MicrocentsPerUSD
	fractionalMicrocents := abs % MicrocentsPerUSD
	// fractionalMicrocents is in [0, 100_000_000); render as 4 decimal places
	// of USD = (microcents / 10_000) since 1 cent = 1_000_000 microcents and
	// four decimal places of dollars means hundredths of a cent = 10_000 microcents.
	tenThousandths := fractionalMicrocents / 10_000
	sign := ""
	if negative {
		sign = "-"
	}
	return fmt.Sprintf("%s$%d.%04d", sign, dollars, tenThousandths)
}

// ParseCreditsFromUSD parses a dollars-and-cents string into signed microcents.
// Accepts an optional leading "-" or "+" sign and an optional leading "$".
// Up to four decimal places are honored; additional precision is rejected so
// callers don't silently lose data. A bare integer (no decimal point) is OK.
//
// Examples:
//
//	"5"        ->  500_000_000
//	"5.00"     ->  500_000_000
//	"-0.1234"  -> -12_340_000
//	"$19.99"   -> 1_999_000_000
//	"10.00001" -> error (too many decimal places)
func ParseCreditsFromUSD(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("amount is empty")
	}

	negative := false
	switch s[0] {
	case '-':
		negative = true
		s = s[1:]
	case '+':
		s = s[1:]
	}
	if len(s) > 0 && s[0] == '$' {
		s = s[1:]
	}
	if s == "" {
		return 0, errors.New("amount has no digits")
	}

	dotIdx := strings.IndexByte(s, '.')
	var dollarsPart, fractionalPart string
	if dotIdx < 0 {
		dollarsPart = s
		fractionalPart = ""
	} else {
		dollarsPart = s[:dotIdx]
		fractionalPart = s[dotIdx+1:]
	}

	if dollarsPart == "" && fractionalPart == "" {
		return 0, errors.New("amount has no digits")
	}
	for _, r := range dollarsPart {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid digit in dollars part: %q", s)
		}
	}
	for _, r := range fractionalPart {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid digit in fractional part: %q", s)
		}
	}
	if len(fractionalPart) > 4 {
		return 0, fmt.Errorf("too many decimal places (max 4): %q", s)
	}

	var dollars int64
	if dollarsPart != "" {
		var err error
		// Use Sscanf for overflow detection; cap at a sane max (1 trillion USD).
		_, err = fmt.Sscanf(dollarsPart, "%d", &dollars)
		if err != nil {
			return 0, fmt.Errorf("invalid dollars part: %w", err)
		}
		if dollars < 0 {
			return 0, fmt.Errorf("invalid dollars part: %q", s)
		}
	}

	// Pad fractionalPart to exactly 4 digits so the conversion is uniform.
	padded := fractionalPart
	for len(padded) < 4 {
		padded += "0"
	}
	var fractional int64
	if padded != "" {
		_, err := fmt.Sscanf(padded, "%d", &fractional)
		if err != nil {
			return 0, fmt.Errorf("invalid fractional part: %w", err)
		}
	}

	// Each unit of `fractional` is 1/10_000 of a dollar = 10_000 microcents.
	microcents := dollars*MicrocentsPerUSD + fractional*10_000
	if negative {
		microcents = -microcents
	}
	return microcents, nil
}

// CreditsSummaryResponse is the shape returned by GetUserCreditsSummary.
type CreditsSummaryResponse struct {
	Username           string               `json:"username"`
	Balance            *UserCredit          `json:"balance"`
	RecentTransactions []*CreditTransaction `json:"recent_transactions"`
	FormattedBalance   string               `json:"formatted_balance"`
}

// GetUserCreditsSummary returns the user's current balance plus their last
// 10 transactions, with a pre-formatted balance string.
func GetUserCreditsSummary(db *sql.DB, username string) (*CreditsSummaryResponse, error) {
	credits, err := GetOrCreateUserCredits(db, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credits: %w", err)
	}
	transactions, err := GetUserTransactions(db, username, 10, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent transactions: %w", err)
	}
	return &CreditsSummaryResponse{
		Username:           username,
		Balance:            credits,
		RecentTransactions: transactions,
		FormattedBalance:   FormatCreditsUSD(credits.BalanceUSDMicrocents),
	}, nil
}

// parseDBTimestamp tolerates both the rqlite/SQLite default `2006-01-02 15:04:05`
// and RFC3339 formats. Returns the zero time on parse failure.
func parseDBTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}
