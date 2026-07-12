package models

import (
	"database/sql"
	"time"
)

type PaymentInvoice struct {
	InvoiceID           string    `json:"invoice_id"`
	Username            string    `json:"username"`
	AmountUSDMicrocents int64     `json:"amount_usd_microcents"`
	Status              string    `json:"status"`
	Provider            string    `json:"provider"`
	ProviderInvoiceID   string    `json:"provider_invoice_id,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

func CreatePaymentInvoice(db DBTX, invoice *PaymentInvoice) error {
	_, err := db.Exec(`
		INSERT INTO payment_invoices (invoice_id, username, amount_usd_microcents, status, provider, provider_invoice_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, invoice.InvoiceID, invoice.Username, invoice.AmountUSDMicrocents, invoice.Status, invoice.Provider, invoice.ProviderInvoiceID)
	return err
}

func GetPaymentInvoice(db DBTX, invoiceID string) (*PaymentInvoice, error) {
	invoice := &PaymentInvoice{}
	var createdAtStr, updatedAtStr string
	var amountF float64

	err := db.QueryRow(`
		SELECT invoice_id, username, amount_usd_microcents, status, provider, COALESCE(provider_invoice_id, ''), created_at, updated_at
		FROM payment_invoices WHERE invoice_id = ?
	`, invoiceID).Scan(&invoice.InvoiceID, &invoice.Username, &amountF, &invoice.Status, &invoice.Provider, &invoice.ProviderInvoiceID, &createdAtStr, &updatedAtStr)
	if err != nil {
		return nil, err
	}

	invoice.AmountUSDMicrocents = int64(amountF)

	// Parse timestamps
	if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
		invoice.CreatedAt = t
	} else if t, err := time.Parse("2006-01-02 15:04:05", createdAtStr); err == nil {
		invoice.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
		invoice.UpdatedAt = t
	} else if t, err := time.Parse("2006-01-02 15:04:05", updatedAtStr); err == nil {
		invoice.UpdatedAt = t
	}

	return invoice, nil
}

func GetPaymentInvoiceByProviderID(db DBTX, providerInvoiceID string) (*PaymentInvoice, error) {
	invoice := &PaymentInvoice{}
	var createdAtStr, updatedAtStr string
	var amountF float64

	err := db.QueryRow(`
		SELECT invoice_id, username, amount_usd_microcents, status, provider, COALESCE(provider_invoice_id, ''), created_at, updated_at
		FROM payment_invoices WHERE provider_invoice_id = ?
	`, providerInvoiceID).Scan(&invoice.InvoiceID, &invoice.Username, &amountF, &invoice.Status, &invoice.Provider, &invoice.ProviderInvoiceID, &createdAtStr, &updatedAtStr)
	if err != nil {
		return nil, err
	}

	invoice.AmountUSDMicrocents = int64(amountF)

	// Parse timestamps
	if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
		invoice.CreatedAt = t
	} else if t, err := time.Parse("2006-01-02 15:04:05", createdAtStr); err == nil {
		invoice.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
		invoice.UpdatedAt = t
	} else if t, err := time.Parse("2006-01-02 15:04:05", updatedAtStr); err == nil {
		invoice.UpdatedAt = t
	}

	return invoice, nil
}

func UpdatePaymentInvoiceStatus(db DBTX, invoiceID, status string) error {
	_, err := db.Exec(`
		UPDATE payment_invoices SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE invoice_id = ?
	`, status, invoiceID)
	return err
}

// AttachPaymentProviderInvoice completes the local-before-remote creation
// transition. It is safe to repeat with the same provider invoice ID.
func AttachPaymentProviderInvoice(db DBTX, invoiceID, providerInvoiceID string) error {
	if invoiceID == "" || providerInvoiceID == "" {
		return sql.ErrNoRows
	}
	result, err := db.Exec(`
		UPDATE payment_invoices
		SET provider_invoice_id = ?, status = 'pending', updated_at = CURRENT_TIMESTAMP
		WHERE invoice_id = ?
		  AND status IN ('creating', 'pending')
		  AND (provider_invoice_id IS NULL OR provider_invoice_id = '' OR provider_invoice_id = ?)
	`, providerInvoiceID, invoiceID, providerInvoiceID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	return nil
}

// ListPendingPaymentInvoices returns a bounded oldest-first reconciliation batch.
func ListPendingPaymentInvoices(db *sql.DB, provider string, limit int) ([]*PaymentInvoice, error) {
	if limit < 1 || limit > 500 {
		return nil, sql.ErrNoRows
	}
	rows, err := db.Query(`
		SELECT invoice_id, username, amount_usd_microcents, status, provider,
		       COALESCE(provider_invoice_id, ''), created_at, updated_at
		FROM payment_invoices
		WHERE status = 'pending' AND provider = ?
		  AND provider_invoice_id IS NOT NULL AND provider_invoice_id != ''
		ORDER BY created_at ASC
		LIMIT ?
	`, provider, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invoices []*PaymentInvoice
	for rows.Next() {
		invoice := &PaymentInvoice{}
		var amountF float64
		var createdAt, updatedAt string
		if err := rows.Scan(
			&invoice.InvoiceID, &invoice.Username, &amountF, &invoice.Status,
			&invoice.Provider, &invoice.ProviderInvoiceID, &createdAt, &updatedAt,
		); err != nil {
			return nil, err
		}
		invoice.AmountUSDMicrocents = int64(amountF)
		invoice.CreatedAt = parsePaymentTimestamp(createdAt)
		invoice.UpdatedAt = parsePaymentTimestamp(updatedAt)
		invoices = append(invoices, invoice)
	}
	return invoices, rows.Err()
}

func parsePaymentTimestamp(value string) time.Time {
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed
	}
	parsed, _ := time.Parse("2006-01-02 15:04:05", value)
	return parsed
}

func ListPaymentInvoices(db DBTX, username string, status string) ([]*PaymentInvoice, error) {
	var rows *sql.Rows
	var err error

	if username != "" && status != "" {
		rows, err = db.Query(`
			SELECT invoice_id, username, amount_usd_microcents, status, provider, COALESCE(provider_invoice_id, ''), created_at, updated_at
			FROM payment_invoices WHERE username = ? AND status = ? ORDER BY created_at DESC
		`, username, status)
	} else if username != "" {
		rows, err = db.Query(`
			SELECT invoice_id, username, amount_usd_microcents, status, provider, COALESCE(provider_invoice_id, ''), created_at, updated_at
			FROM payment_invoices WHERE username = ? ORDER BY created_at DESC
		`, username)
	} else if status != "" {
		rows, err = db.Query(`
			SELECT invoice_id, username, amount_usd_microcents, status, provider, COALESCE(provider_invoice_id, ''), created_at, updated_at
			FROM payment_invoices WHERE status = ? ORDER BY created_at DESC
		`, status)
	} else {
		rows, err = db.Query(`
			SELECT invoice_id, username, amount_usd_microcents, status, provider, COALESCE(provider_invoice_id, ''), created_at, updated_at
			FROM payment_invoices ORDER BY created_at DESC
		`)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invoices []*PaymentInvoice
	for rows.Next() {
		invoice := &PaymentInvoice{}
		var createdAtStr, updatedAtStr string
		var amountF float64

		err = rows.Scan(&invoice.InvoiceID, &invoice.Username, &amountF, &invoice.Status, &invoice.Provider, &invoice.ProviderInvoiceID, &createdAtStr, &updatedAtStr)
		if err != nil {
			return nil, err
		}

		invoice.AmountUSDMicrocents = int64(amountF)

		if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			invoice.CreatedAt = t
		} else if t, err := time.Parse("2006-01-02 15:04:05", createdAtStr); err == nil {
			invoice.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
			invoice.UpdatedAt = t
		} else if t, err := time.Parse("2006-01-02 15:04:05", updatedAtStr); err == nil {
			invoice.UpdatedAt = t
		}

		invoices = append(invoices, invoice)
	}

	return invoices, nil
}

// CreditTransactionExistsForProviderID reports whether a credit_transactions row
// exists for the given provider invoice ID (stored as transaction_id).
func CreditTransactionExistsForProviderID(db DBTX, providerInvoiceID string) (bool, error) {
	if providerInvoiceID == "" {
		return false, nil
	}
	var count int
	err := db.QueryRow(
		`SELECT COUNT(1) FROM credit_transactions WHERE transaction_id = ?`,
		providerInvoiceID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CreditTransactionExistsForProviderIDTx is the transactional variant.
func CreditTransactionExistsForProviderIDTx(tx *sql.Tx, providerInvoiceID string) (bool, error) {
	return CreditTransactionExistsForProviderID(tx, providerInvoiceID)
}

// ListPaidInvoicesWithoutCredit returns paid invoices that have no matching ledger credit row.
func ListPaidInvoicesWithoutCredit(db *sql.DB) ([]*PaymentInvoice, error) {
	rows, err := db.Query(`
		SELECT pi.invoice_id, pi.username, pi.amount_usd_microcents, pi.status, pi.provider,
		       COALESCE(pi.provider_invoice_id, ''), pi.created_at, pi.updated_at
		FROM payment_invoices pi
		LEFT JOIN credit_transactions ct ON ct.transaction_id = pi.provider_invoice_id
		WHERE pi.status = 'paid'
		  AND pi.provider_invoice_id IS NOT NULL
		  AND pi.provider_invoice_id != ''
		  AND ct.id IS NULL
		ORDER BY pi.created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invoices []*PaymentInvoice
	for rows.Next() {
		invoice := &PaymentInvoice{}
		var createdAtStr, updatedAtStr string
		var amountF float64

		if err := rows.Scan(
			&invoice.InvoiceID, &invoice.Username, &amountF, &invoice.Status, &invoice.Provider,
			&invoice.ProviderInvoiceID, &createdAtStr, &updatedAtStr,
		); err != nil {
			return nil, err
		}
		invoice.AmountUSDMicrocents = int64(amountF)

		if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			invoice.CreatedAt = t
		} else if t, err := time.Parse("2006-01-02 15:04:05", createdAtStr); err == nil {
			invoice.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
			invoice.UpdatedAt = t
		} else if t, err := time.Parse("2006-01-02 15:04:05", updatedAtStr); err == nil {
			invoice.UpdatedAt = t
		}

		invoices = append(invoices, invoice)
	}
	return invoices, rows.Err()
}
