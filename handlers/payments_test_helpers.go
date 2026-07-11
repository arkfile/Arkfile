package handlers

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/billing"
	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3"
)

const (
	paymentsTestUser        = "pay-test-user"
	paymentsTestOtherUser   = "pay-other-user"
	paymentsWebhookSecret   = "test_webhook_secret"
	paymentsStoreID         = "test_store_id"
	subscriptionsTestSecret = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	subscriptionsTestPlanID = "plan_dev_250gb"
)

func setupPaymentsSQLiteDB(t *testing.T) *sql.DB {
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
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			total_storage_bytes BIGINT NOT NULL DEFAULT 0,
			storage_limit_bytes BIGINT NOT NULL DEFAULT 1073741824,
			is_approved BOOLEAN NOT NULL DEFAULT 1,
			approved_by TEXT,
			approved_at TIMESTAMP,
			is_admin BOOLEAN NOT NULL DEFAULT 0,
			deleted_at TIMESTAMP DEFAULT NULL
		);
		CREATE TABLE user_credits (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			balance_usd_microcents BIGINT NOT NULL DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
		);
		CREATE TABLE credit_transactions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			transaction_id TEXT UNIQUE DEFAULT NULL,
			username TEXT NOT NULL,
			amount_usd_microcents BIGINT NOT NULL,
			balance_after_usd_microcents BIGINT NOT NULL,
			transaction_type TEXT NOT NULL CHECK (transaction_type IN ('usage', 'gift', 'adjustment', 'payment')),
			reason TEXT,
			admin_username TEXT,
			metadata TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
		);
		CREATE TABLE storage_usage_accumulator (
			username TEXT PRIMARY KEY,
			unbilled_microcents BIGINT NOT NULL DEFAULT 0,
			last_tick_at DATETIME,
			last_billed_at DATETIME,
			FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
		);
		CREATE TABLE billing_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_by TEXT
		);
		CREATE TABLE upload_sessions (
			id TEXT PRIMARY KEY,
			file_id VARCHAR(36) NOT NULL UNIQUE,
			encrypted_filename TEXT NOT NULL,
			filename_nonce TEXT NOT NULL,
			encrypted_sha256sum TEXT NOT NULL,
			sha256sum_nonce TEXT NOT NULL,
			owner_username TEXT NOT NULL,
			total_size BIGINT NOT NULL,
			chunk_size INTEGER NOT NULL,
			total_chunks INTEGER NOT NULL,
			password_hint TEXT,
			password_type TEXT NOT NULL,
			storage_upload_id TEXT,
			storage_id VARCHAR(36),
			padded_size BIGINT,
			status TEXT NOT NULL DEFAULT 'in_progress',
			encrypted_hash CHAR(64),
			encrypted_fek TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP,
			FOREIGN KEY (owner_username) REFERENCES users(username) ON DELETE CASCADE
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
		CREATE TABLE subscription_plans (
			plan_id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			price_usd_cents INTEGER NOT NULL,
			storage_limit_bytes BIGINT NOT NULL,
			sort_order INTEGER NOT NULL DEFAULT 0,
			is_active INTEGER NOT NULL DEFAULT 1,
			is_public INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_by TEXT
		);
		CREATE TABLE subscription_checkouts (
			checkout_id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			plan_id TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			subscription_ref TEXT UNIQUE,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE user_subscriptions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			plan_id TEXT NOT NULL,
			checkout_id TEXT NOT NULL,
			subscription_ref TEXT UNIQUE NOT NULL,
			is_current BOOLEAN NOT NULL DEFAULT 1,
			status TEXT NOT NULL,
			source TEXT NOT NULL,
			state_version BIGINT NOT NULL DEFAULT 0,
			state_changed_at DATETIME,
			current_period_start DATETIME NOT NULL,
			current_period_end DATETIME NOT NULL,
			cancel_at_period_end BOOLEAN NOT NULL DEFAULT 0,
			canceled_at DATETIME,
			past_due_since DATETIME,
			gift_note TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE subscription_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_id TEXT UNIQUE NOT NULL,
			event_type TEXT NOT NULL,
			subscription_ref TEXT,
			checkout_id TEXT,
			username TEXT,
			plan_id TEXT,
			state_version BIGINT NOT NULL DEFAULT 0,
			state_changed_at DATETIME,
			disposition TEXT NOT NULL DEFAULT 'applied',
			admin_username TEXT,
			payload_hash TEXT NOT NULL,
			processed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE UNIQUE INDEX idx_user_subscriptions_one_current
			ON user_subscriptions(username) WHERE is_current = 1;
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	for _, u := range []struct{ name, folded string }{
		{paymentsTestUser, paymentsTestUser},
		{paymentsTestOtherUser, paymentsTestOtherUser},
	} {
		if _, err := db.Exec(
			`INSERT INTO users (username, username_folded, is_approved, approved_by, approved_at)
			 VALUES (?, ?, 1, 'admin', CURRENT_TIMESTAMP)`,
			u.name, u.folded,
		); err != nil {
			t.Fatalf("seed user %s: %v", u.name, err)
		}
	}
	return db
}

func withPaymentsTestEnv(t *testing.T, btcpayURL string, paymentsEnabled bool) (*sql.DB, func()) {
	t.Helper()
	logging.InitFallbackConsoleLogging()
	crypto.SetUserSecretMasterForTest(make([]byte, 32))

	db := setupPaymentsSQLiteDB(t)
	origDB := database.DB
	database.DB = db

	origProcessPayment := ProcessPaymentFunc
	SetProcessPaymentFunc(billing.ProcessPayment)
	origSettle := SettlePaymentInvoiceFunc
	SetSettlePaymentInvoiceFunc(billing.SettlePaymentInvoice)

	config.ResetConfigForTest()
	t.Setenv("ARKFILE_PAYMENTS_ENABLED", "false")
	if paymentsEnabled {
		t.Setenv("ARKFILE_PAYMENTS_ENABLED", "true")
	}
	// The upload soft-block now gates on Billing.Enabled with a configurable
	// PAYG negative-balance cap. Enable billing for the payments/billing test
	// suite so the gate is exercised; the cap defaults to $10.00.
	t.Setenv("ARKFILE_BILLING_ENABLED", "true")
	t.Setenv("ARKFILE_PAYG_NEGATIVE_BALANCE_LIMIT_USD", "10.00")
	t.Setenv("ARKFILE_BTCPAY_SERVER_URL", btcpayURL)
	t.Setenv("ARKFILE_BTCPAY_STORE_ID", paymentsStoreID)
	t.Setenv("ARKFILE_BTCPAY_API_KEY", "test_api_key")
	t.Setenv("ARKFILE_BTCPAY_WEBHOOK_SECRET", paymentsWebhookSecret)
	t.Setenv("ARKFILE_MIN_TOP_UP_USD", "0.50")
	t.Setenv("ARKFILE_MAX_TOP_UP_USD", "1000.00")
	t.Setenv("ARKFILE_SERVER_BASE_URL", "https://arkfile.test")

	if _, err := config.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	cleanup := func() {
		database.DB = origDB
		SetProcessPaymentFunc(origProcessPayment)
		SetSettlePaymentInvoiceFunc(origSettle)
		config.ResetConfigForTest()
		db.Close()
	}
	return db, cleanup
}

func withSubscriptionsTestEnv(t *testing.T, btcpayURL string) (*sql.DB, func()) {
	t.Helper()
	db, cleanup := withPaymentsTestEnv(t, btcpayURL, true)

	t.Setenv("ARKFILE_SUBSCRIPTIONS_ENABLED", "true")
	t.Setenv("ARKFILE_SUBSCRIPTION_BRIDGE_ENABLED", "true")
	t.Setenv("ARKFILE_SUBSCRIPTION_BRIDGE_URL", "http://127.0.0.1:8081")
	t.Setenv("ARKFILE_SUBSCRIPTION_BRIDGE_PAIRING_ROOT", subscriptionsTestSecret)
	t.Setenv("ARKFILE_SUBSCRIPTION_RETURN_URL", "https://arkfile.test/?subscription=return")
	t.Setenv("ARKFILE_BILLING_PAYG_ENABLED", "true")
	t.Setenv("ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH", "10.00")
	t.Setenv("JWT_SECRET", "test-jwt-secret")
	t.Setenv("STORAGE_PROVIDER_1", "generic-s3")
	t.Setenv("STORAGE_1_ENDPOINT", "http://localhost:9332")
	t.Setenv("STORAGE_1_ACCESS_KEY", "test")
	t.Setenv("STORAGE_1_SECRET_KEY", "test")
	t.Setenv("STORAGE_1_BUCKET", "test-bucket")
	config.ResetConfigForTest()
	t.Setenv("ARKFILE_PAYMENTS_ENABLED", "true")
	t.Setenv("ARKFILE_BILLING_ENABLED", "true")
	t.Setenv("ARKFILE_PAYG_NEGATIVE_BALANCE_LIMIT_USD", "10.00")
	t.Setenv("ARKFILE_BTCPAY_SERVER_URL", btcpayURL)
	t.Setenv("ARKFILE_BTCPAY_STORE_ID", paymentsStoreID)
	t.Setenv("ARKFILE_BTCPAY_API_KEY", "test_api_key")
	t.Setenv("ARKFILE_BTCPAY_WEBHOOK_SECRET", paymentsWebhookSecret)
	t.Setenv("ARKFILE_MIN_TOP_UP_USD", "0.50")
	t.Setenv("ARKFILE_MAX_TOP_UP_USD", "1000.00")
	t.Setenv("ARKFILE_SERVER_BASE_URL", "https://arkfile.test")
	if _, err := config.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	planBytes := int64(250) << 30
	if _, err := db.Exec(
		`INSERT INTO subscription_plans (plan_id, name, price_usd_cents, storage_limit_bytes, is_active, is_public)
		 VALUES (?, '250 GB Dev', 500, ?, 1, 1)`,
		subscriptionsTestPlanID, planBytes,
	); err != nil {
		t.Fatalf("seed subscription plan: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO billing_settings (key, value) VALUES ('customer_price_usd_per_tb_per_month', '10.00')`); err != nil {
		t.Fatalf("seed billing settings: %v", err)
	}

	origCleanup := cleanup
	cleanup = func() {
		origCleanup()
	}
	return db, cleanup
}

func seedHandlerGiftSubscription(t *testing.T, db *sql.DB, username string) {
	t.Helper()
	checkoutID := "subchk_gift_" + username
	entRef := "sub_gift_" + username
	if _, err := db.Exec(
		`INSERT INTO subscription_checkouts (checkout_id, username, plan_id, status, subscription_ref)
		 VALUES (?, ?, ?, 'completed', ?)`,
		checkoutID, username, subscriptionsTestPlanID, entRef,
	); err != nil {
		t.Fatalf("seed checkout: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO user_subscriptions
		  (username, plan_id, checkout_id, subscription_ref, status, source, current_period_start, current_period_end)
		VALUES (?, ?, ?, ?, 'active', 'gift', datetime('now'), datetime('now', '+30 days'))`,
		username, subscriptionsTestPlanID, checkoutID, entRef,
	); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}
}

func newPaymentsEchoContext(t *testing.T, method, path string, body io.Reader, username string) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if username != "" {
		claims := &auth.Claims{Username: username}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		c.Set("user", token)
	}
	return c, rec
}

func parseJSONResponse(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", rec.Body.String(), err)
	}
	return resp
}

// startMockBTCPayServer returns a server that handles invoice create (POST) and
// optional per-provider-ID GET status lookups.
func startMockBTCPayServer(t *testing.T, getStatus map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/stores/"+paymentsStoreID+"/invoices":
			if r.Header.Get("Authorization") != "token test_api_key" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var payload struct {
				Metadata map[string]string `json:"metadata"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id":           "btcpay_mock_" + payload.Metadata["invoice_id"],
				"checkoutLink": "https://btcpay.test/checkout/" + payload.Metadata["invoice_id"],
			})
		case r.Method == http.MethodGet:
			// /api/v1/stores/{store}/invoices/{providerID}
			parts := splitPath(r.URL.Path)
			if len(parts) >= 6 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "stores" && parts[4] == "invoices" {
				providerID := parts[5]
				status := getStatus[providerID]
				if status == "" {
					status = "Processing"
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
				return
			}
			http.NotFound(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
}

func splitPath(p string) []string {
	if p == "" || p == "/" {
		return nil
	}
	if p[0] == '/' {
		p = p[1:]
	}
	out := []string{}
	cur := ""
	for _, ch := range p {
		if ch == '/' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(ch)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func seedPendingInvoice(t *testing.T, db *sql.DB, invoiceID, username, providerID string, amount int64) {
	t.Helper()
	inv := &models.PaymentInvoice{
		InvoiceID:           invoiceID,
		Username:            username,
		AmountUSDMicrocents: amount,
		Status:              "pending",
		Provider:            "btcpay",
		ProviderInvoiceID:   providerID,
	}
	if err := models.CreatePaymentInvoice(db, inv); err != nil {
		t.Fatalf("seed invoice: %v", err)
	}
}
