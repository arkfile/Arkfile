package models

import (
	"database/sql"
	"testing"
	"time"

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
			status TEXT NOT NULL DEFAULT 'creating',
			provider TEXT NOT NULL,
			provider_invoice_id TEXT UNIQUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_checked_at TIMESTAMP,
			FOREIGN KEY(username) REFERENCES users(username) ON DELETE RESTRICT,
			CHECK(status IN ('creating', 'pending', 'confirming', 'paid', 'expired', 'failed'))
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
		Provider:            "testprov",
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

func TestCreatePaymentInvoice_ManyWithoutProviderID(t *testing.T) {
	db := openPaymentInvoicesTestDB(t)
	defer db.Close()

	for _, id := range []string{"inv_n1", "inv_n2", "inv_n3"} {
		inv := &PaymentInvoice{InvoiceID: id, Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusCreating, Provider: "testprov"}
		if err := CreatePaymentInvoice(db, inv); err != nil {
			t.Fatalf("%s: invoices awaiting a provider id must not collide: %v", id, err)
		}
	}
	got, err := GetPaymentInvoice(db, "inv_n2")
	if err != nil || got.ProviderInvoiceID != "" {
		t.Errorf("provider id = %q, %v; want empty", got.ProviderInvoiceID, err)
	}
}

func TestListPaymentInvoices_Filters(t *testing.T) {
	db := openPaymentInvoicesTestDB(t)
	defer db.Close()

	seed := []PaymentInvoice{
		{InvoiceID: "inv_a1", Username: "alice", AmountUSDMicrocents: 100, Status: "pending", Provider: "testprov", ProviderInvoiceID: "p1"},
		{InvoiceID: "inv_a2", Username: "alice", AmountUSDMicrocents: 200, Status: "paid", Provider: "testprov", ProviderInvoiceID: "p2"},
		{InvoiceID: "inv_b1", Username: "bob", AmountUSDMicrocents: 300, Status: "pending", Provider: "testprov", ProviderInvoiceID: "p3"},
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

func TestAdvancePaymentInvoiceStatus_Guarded(t *testing.T) {
	db := openPaymentInvoicesTestDB(t)
	defer db.Close()

	inv := &PaymentInvoice{InvoiceID: "inv_adv", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusPending, Provider: "testprov", ProviderInvoiceID: "p_adv"}
	if err := CreatePaymentInvoice(db, inv); err != nil {
		t.Fatalf("seed: %v", err)
	}

	moved, err := AdvancePaymentInvoiceStatus(db, "inv_adv", []string{PaymentStatusPending}, PaymentStatusConfirming)
	if err != nil || !moved {
		t.Fatalf("pending to confirming: moved=%v err=%v", moved, err)
	}
	moved, err = AdvancePaymentInvoiceStatus(db, "inv_adv", []string{PaymentStatusPending}, PaymentStatusExpired)
	if err != nil || moved {
		t.Fatalf("guard should block confirming to expired: moved=%v err=%v", moved, err)
	}
	got, err := GetPaymentInvoice(db, "inv_adv")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != PaymentStatusConfirming {
		t.Errorf("status = %q, want confirming", got.Status)
	}
}

func setInvoiceTimes(t *testing.T, db *sql.DB, invoiceID, createdModifier, checkedModifier string) {
	t.Helper()
	if createdModifier != "" {
		if _, err := db.Exec(`UPDATE payment_invoices SET created_at = datetime('now', ?) WHERE invoice_id = ?`, createdModifier, invoiceID); err != nil {
			t.Fatal(err)
		}
	}
	if checkedModifier != "" {
		if _, err := db.Exec(`UPDATE payment_invoices SET last_checked_at = datetime('now', ?) WHERE invoice_id = ?`, checkedModifier, invoiceID); err != nil {
			t.Fatal(err)
		}
	}
}

func invoiceIDs(invoices []*PaymentInvoice) []string {
	ids := make([]string, 0, len(invoices))
	for _, inv := range invoices {
		ids = append(ids, inv.InvoiceID)
	}
	return ids
}

func TestListPaymentInvoicesToReconcile_Selection(t *testing.T) {
	db := openPaymentInvoicesTestDB(t)
	defer db.Close()

	seed := []PaymentInvoice{
		{InvoiceID: "inv_p", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusPending, Provider: "testprov", ProviderInvoiceID: "pp"},
		{InvoiceID: "inv_c", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusConfirming, Provider: "testprov", ProviderInvoiceID: "pc"},
		{InvoiceID: "inv_d", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusPaid, Provider: "testprov", ProviderInvoiceID: "pd"},
		{InvoiceID: "inv_o", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusPending, Provider: "other", ProviderInvoiceID: "po"},
		{InvoiceID: "inv_e_new", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusExpired, Provider: "testprov", ProviderInvoiceID: "pe1"},
		{InvoiceID: "inv_e_recent_check", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusExpired, Provider: "testprov", ProviderInvoiceID: "pe2"},
		{InvoiceID: "inv_f_old", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusFailed, Provider: "testprov", ProviderInvoiceID: "pf1"},
		{InvoiceID: "inv_creating", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusCreating, Provider: "testprov"},
	}
	for i := range seed {
		if err := CreatePaymentInvoice(db, &seed[i]); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	setInvoiceTimes(t, db, "inv_e_recent_check", "", "-5 minutes")
	setInvoiceTimes(t, db, "inv_f_old", "-4 days", "")

	got, err := ListPaymentInvoicesToReconcile(db, "testprov", 10, 72*time.Hour, 30*time.Minute)
	if err != nil {
		t.Fatalf("ListPaymentInvoicesToReconcile: %v", err)
	}
	ids := invoiceIDs(got)
	want := map[string]bool{"inv_p": true, "inv_c": true, "inv_e_new": true}
	if len(ids) != len(want) {
		t.Fatalf("selected %v, want pending, confirming and the recently expired invoice", ids)
	}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("unexpected invoice %s selected (all: %v)", id, ids)
		}
	}
}

func TestListPaymentInvoicesToReconcile_LeastRecentlyCheckedFirst(t *testing.T) {
	db := openPaymentInvoicesTestDB(t)
	defer db.Close()

	for _, id := range []string{"inv_1", "inv_2", "inv_3"} {
		inv := &PaymentInvoice{InvoiceID: id, Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusPending, Provider: "testprov", ProviderInvoiceID: "p" + id}
		if err := CreatePaymentInvoice(db, inv); err != nil {
			t.Fatal(err)
		}
	}
	setInvoiceTimes(t, db, "inv_1", "", "-1 minutes")
	setInvoiceTimes(t, db, "inv_2", "", "-10 minutes")

	got, err := ListPaymentInvoicesToReconcile(db, "testprov", 2, 72*time.Hour, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ids := invoiceIDs(got)
	if len(ids) != 2 || ids[0] != "inv_3" || ids[1] != "inv_2" {
		t.Errorf("order = %v, want never-checked inv_3 then oldest-checked inv_2", ids)
	}

	if err := MarkPaymentInvoiceChecked(db, "inv_3"); err != nil {
		t.Fatal(err)
	}
	if err := MarkPaymentInvoiceChecked(db, "inv_2"); err != nil {
		t.Fatal(err)
	}
	got, err = ListPaymentInvoicesToReconcile(db, "testprov", 1, 72*time.Hour, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ids := invoiceIDs(got); len(ids) != 1 || ids[0] != "inv_1" {
		t.Errorf("after marking, next = %v, want inv_1", ids)
	}
}

func TestCloseStalePaymentInvoice(t *testing.T) {
	db := openPaymentInvoicesTestDB(t)
	defer db.Close()

	seed := []PaymentInvoice{
		{InvoiceID: "inv_old_p", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusPending, Provider: "testprov", ProviderInvoiceID: "p1"},
		{InvoiceID: "inv_old_c", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusConfirming, Provider: "testprov", ProviderInvoiceID: "p2"},
		{InvoiceID: "inv_new_p", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusPending, Provider: "testprov", ProviderInvoiceID: "p3"},
		{InvoiceID: "inv_old_paid", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusPaid, Provider: "testprov", ProviderInvoiceID: "p4"},
	}
	for i := range seed {
		if err := CreatePaymentInvoice(db, &seed[i]); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"inv_old_p", "inv_old_c", "inv_old_paid"} {
		setInvoiceTimes(t, db, id, "-3 days", "")
	}

	cases := map[string]string{
		"inv_old_p":    PaymentStatusExpired,
		"inv_old_c":    PaymentStatusFailed,
		"inv_new_p":    "",
		"inv_old_paid": "",
	}
	for id, want := range cases {
		got, err := CloseStalePaymentInvoice(db, id, 48*time.Hour)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if got != want {
			t.Errorf("%s closed to %q, want %q", id, got, want)
		}
	}
	if inv, _ := GetPaymentInvoice(db, "inv_old_paid"); inv.Status != PaymentStatusPaid {
		t.Errorf("paid invoice changed to %s", inv.Status)
	}
}

func TestFailStaleCreatingPaymentInvoices(t *testing.T) {
	db := openPaymentInvoicesTestDB(t)
	defer db.Close()

	for _, id := range []string{"inv_stuck", "inv_fresh"} {
		inv := &PaymentInvoice{InvoiceID: id, Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusCreating, Provider: "testprov", ProviderInvoiceID: "p" + id}
		if err := CreatePaymentInvoice(db, inv); err != nil {
			t.Fatal(err)
		}
	}
	setInvoiceTimes(t, db, "inv_stuck", "-1 hours", "")

	n, err := FailStaleCreatingPaymentInvoices(db, 15*time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("failed %d invoices, err %v; want 1", n, err)
	}
	if inv, _ := GetPaymentInvoice(db, "inv_stuck"); inv.Status != PaymentStatusFailed {
		t.Errorf("stuck invoice status = %s, want failed", inv.Status)
	}
	if inv, _ := GetPaymentInvoice(db, "inv_fresh"); inv.Status != PaymentStatusCreating {
		t.Errorf("fresh invoice status = %s, want creating", inv.Status)
	}
}

func TestCountUnpaidPaymentInvoicesForUser(t *testing.T) {
	db := openPaymentInvoicesTestDB(t)
	defer db.Close()

	seed := []PaymentInvoice{
		{InvoiceID: "inv_1", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusCreating, Provider: "testprov", ProviderInvoiceID: "p1"},
		{InvoiceID: "inv_2", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusPending, Provider: "testprov", ProviderInvoiceID: "p2"},
		{InvoiceID: "inv_3", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusConfirming, Provider: "testprov", ProviderInvoiceID: "p3"},
		{InvoiceID: "inv_4", Username: "alice", AmountUSDMicrocents: 100, Status: PaymentStatusExpired, Provider: "testprov", ProviderInvoiceID: "p4"},
		{InvoiceID: "inv_5", Username: "bob", AmountUSDMicrocents: 100, Status: PaymentStatusPending, Provider: "testprov", ProviderInvoiceID: "p5"},
	}
	for i := range seed {
		if err := CreatePaymentInvoice(db, &seed[i]); err != nil {
			t.Fatal(err)
		}
	}
	n, err := CountUnpaidPaymentInvoicesForUser(db, "alice")
	if err != nil || n != 2 {
		t.Errorf("alice unpaid = %d, %v; want 2 (creating and pending)", n, err)
	}
}
