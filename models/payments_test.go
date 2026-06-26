package models

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func openPaymentInvoicesTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		t.Fatalf("enable foreign keys: %v", err)
	}
	schema := `
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			username_folded TEXT UNIQUE NOT NULL,
			total_storage_bytes BIGINT NOT NULL DEFAULT 0,
			storage_limit_bytes BIGINT NOT NULL DEFAULT 1073741824,
			is_approved BOOLEAN NOT NULL DEFAULT 1,
			is_admin BOOLEAN NOT NULL DEFAULT 0
		);
		CREATE TABLE payment_invoices (
			invoice_id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			amount_usd_microcents BIGINT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			provider TEXT NOT NULL,
			provider_invoice_id TEXT UNIQUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(username) REFERENCES users(username) ON DELETE RESTRICT,
			CHECK(status IN ('pending', 'paid', 'expired', 'failed')),
			CHECK(provider IN ('btcpay'))
		);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (username, username_folded) VALUES ('alice', 'alice'), ('bob', 'bob')`); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	return db
}

func TestPaymentInvoiceCRUD(t *testing.T) {
	db := openPaymentInvoicesTestDB(t)
	defer db.Close()

	inv := &PaymentInvoice{
		InvoiceID:           "inv_test001",
		Username:            "alice",
		AmountUSDMicrocents: 500_000_000,
		Status:              "pending",
		Provider:            "btcpay",
		ProviderInvoiceID:   "prov_001",
	}
	if err := CreatePaymentInvoice(db, inv); err != nil {
		t.Fatalf("CreatePaymentInvoice: %v", err)
	}

	got, err := GetPaymentInvoice(db, "inv_test001")
	if err != nil {
		t.Fatalf("GetPaymentInvoice: %v", err)
	}
	if got.Status != "pending" || got.Username != "alice" || got.AmountUSDMicrocents != 500_000_000 {
		t.Errorf("unexpected invoice: %+v", got)
	}

	byProv, err := GetPaymentInvoiceByProviderID(db, "prov_001")
	if err != nil {
		t.Fatalf("GetPaymentInvoiceByProviderID: %v", err)
	}
	if byProv.InvoiceID != "inv_test001" {
		t.Errorf("provider lookup invoice_id = %q", byProv.InvoiceID)
	}

	if err := UpdatePaymentInvoiceStatus(db, "inv_test001", "paid"); err != nil {
		t.Fatalf("UpdatePaymentInvoiceStatus: %v", err)
	}
	got, err = GetPaymentInvoice(db, "inv_test001")
	if err != nil {
		t.Fatalf("GetPaymentInvoice after update: %v", err)
	}
	if got.Status != "paid" {
		t.Errorf("status = %q, want paid", got.Status)
	}
}

func TestListPaymentInvoices_Filters(t *testing.T) {
	db := openPaymentInvoicesTestDB(t)
	defer db.Close()

	seed := []PaymentInvoice{
		{InvoiceID: "inv_a1", Username: "alice", AmountUSDMicrocents: 100, Status: "pending", Provider: "btcpay", ProviderInvoiceID: "p1"},
		{InvoiceID: "inv_a2", Username: "alice", AmountUSDMicrocents: 200, Status: "paid", Provider: "btcpay", ProviderInvoiceID: "p2"},
		{InvoiceID: "inv_b1", Username: "bob", AmountUSDMicrocents: 300, Status: "pending", Provider: "btcpay", ProviderInvoiceID: "p3"},
	}
	for i := range seed {
		if err := CreatePaymentInvoice(db, &seed[i]); err != nil {
			t.Fatalf("seed invoice %d: %v", i, err)
		}
	}

	pendingAlice, err := ListPaymentInvoices(db, "alice", "pending")
	if err != nil {
		t.Fatalf("ListPaymentInvoices: %v", err)
	}
	if len(pendingAlice) != 1 || pendingAlice[0].InvoiceID != "inv_a1" {
		t.Errorf("pending alice = %+v, want inv_a1 only", pendingAlice)
	}

	allPending, err := ListPaymentInvoices(db, "", "pending")
	if err != nil {
		t.Fatalf("ListPaymentInvoices pending: %v", err)
	}
	if len(allPending) != 2 {
		t.Errorf("pending count = %d, want 2", len(allPending))
	}
}
