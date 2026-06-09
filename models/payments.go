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
