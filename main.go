package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/billing"
	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/handlers"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	"github.com/arkfile/Arkfile/storage"
	"github.com/arkfile/Arkfile/utils"
)

func setupRoutes(e *echo.Echo) {
	// Liveness probe: is the process alive?
	e.GET("/healthz", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status": "alive",
		})
	})

	// Readiness probe: can we serve traffic? Checks all dependencies.
	e.GET("/readyz", func(c echo.Context) error {
		checks := map[string]string{}
		allReady := true

		// Check rqlite connectivity
		if err := database.DB.Ping(); err != nil {
			checks["rqlite"] = fmt.Sprintf("not ready: %v", err)
			allReady = false
		} else {
			checks["rqlite"] = "ok"
		}

		// Check storage connectivity
		if storage.Registry == nil || storage.Registry.Primary() == nil {
			checks["storage"] = "not initialized"
			allReady = false
		} else {
			checks["storage"] = "ok"
		}

		checks["status"] = "ready"
		if !allReady {
			checks["status"] = "not ready"
			return c.JSON(http.StatusServiceUnavailable, checks)
		}
		return c.JSON(http.StatusOK, checks)
	})

	// Set the global Echo instance for handlers
	handlers.Echo = e

	// Set up auth Echo instance
	auth.Echo = e.Group("")
	auth.Echo.Use(auth.JWTMiddleware())
	auth.Echo.Use(auth.TokenRevocationMiddleware(database.DB))
	auth.Echo.Use(handlers.RequireApproved)

	// Register all routes
	handlers.RegisterRoutes()
}

func main() {
	// Load environment variables from .env file if it exists
	// This allows flexibility - the app can work with systemd EnvironmentFile
	// or with a local .env file for development
	if err := godotenv.Load(); err != nil {
		// This is expected behavior in production with systemd - log as info, not warning
		log.Printf("Info: No .env file found (%v), using system environment variables", err)
	}

	// Load configuration - this must happen after environment variables are loaded
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate production configuration
	if err := config.ValidateProductionConfig(); err != nil {
		log.Fatalf("Production configuration validation failed: %v", err)
	}

	// CRITICAL SECURITY: Prevent DEBUG_MODE in production
	if utils.IsProductionEnvironment() {
		debugMode := strings.ToLower(os.Getenv("DEBUG_MODE"))
		if debugMode == "true" || debugMode == "1" {
			log.Fatal("CRITICAL SECURITY: DEBUG_MODE cannot be enabled in production environment. " +
				"Debug mode exposes sensitive cryptographic information in logs and enables admin endpoints. " +
				"Set DEBUG_MODE=false or remove it from environment variables.")
		}
	}

	log.Printf("Arkfile %s starting", config.Version)
	log.Printf("Configuration loaded successfully")

	// Initialize console-only logging for systemd compatibility
	// This ensures all logs go to stderr and are captured by systemd/journalctl
	log.Printf("Initializing console-only logging for systemd compatibility")
	logging.InitFallbackConsoleLogging()

	// Set debug logging if configured
	if strings.ToLower(cfg.Server.LogLevel) == "debug" {
		log.Printf("Debug logging enabled - all debug messages will be visible in journalctl")
		// The logging package will handle debug level filtering
	}

	// Initialize database
	database.InitDB()
	defer database.DB.Close()

	// Initialize KeyManager (required for all system secrets)
	if err := crypto.InitKeyManager(database.DB); err != nil {
		log.Fatalf("Failed to initialize KeyManager: %v", err)
	}

	// Initialize user-secret master
	if err := crypto.LoadUserSecretMaster(); err != nil {
		log.Fatalf("Failed to load user-secret master key: %v", err)
	}

	// Rate limiting schema is now included in unified_schema.sql
	// No separate application needed

	// Initialize OPAQUE server keys first (required for real OPAQUE provider)
	if err := auth.SetupServerKeys(database.DB); err != nil {
		log.Fatalf("Failed to setup OPAQUE server keys: %v", err)
	}

	// Verify OPAQUE is available
	if !auth.IsOPAQUEAvailable() {
		log.Fatalf("OPAQUE not available")
	}
	logging.InfoLogger.Printf("OPAQUE initialized successfully")

	// Start session cleanup goroutine
	go func() {
		// Perform initial cleanup on startup
		if err := auth.CleanupExpiredSessions(database.DB); err != nil {
			logging.ErrorLogger.Printf("Failed to perform initial session cleanup: %v", err)
		}

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if err := auth.CleanupExpiredSessions(database.DB); err != nil {
				logging.ErrorLogger.Printf("Failed to cleanup expired sessions: %v", err)
			}
		}
	}()

	// Start MFA usage-log cleanup routine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if err := auth.CleanupMFALogs(database.DB); err != nil {
				logging.ErrorLogger.Printf("Failed to cleanup MFA logs: %v", err)
			}
		}
	}()

	// Initialize Entity ID service for rate limiting
	entityIDConfig := logging.EntityIDConfig{
		RotationPeriod:    24 * time.Hour, // Daily rotation
		RetentionDays:     90,             // 90 days retention
		CleanupInterval:   24 * time.Hour, // Daily cleanup
		EmergencyRotation: true,           // Enable emergency rotation
	}
	if err := logging.InitializeEntityIDService(entityIDConfig); err != nil {
		log.Fatalf("Failed to initialize Entity ID service: %v", err)
	}
	logging.InfoLogger.Printf("Entity ID service initialized successfully")

	// Initialize security event logger (requires database + Entity ID service)
	securityEventConfig := logging.SecurityEventConfig{
		MaxRetentionDays: 90,
	}
	if err := logging.InitializeSecurityEventLogger(securityEventConfig); err != nil {
		log.Fatalf("Failed to initialize security event logger: %v", err)
	}
	logging.InfoLogger.Printf("Security event logger initialized successfully")

	// Initialize storage
	if err := storage.InitS3(); err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Safe migration: add stored_blob_sha256sum column if missing (for existing deployments).
	// Handles databases created before the column was added to the CREATE TABLE definition.
	// Silently ignored if the column already exists (fresh installs).
	runSchemaMigrations()

	// Register storage providers in the database and backfill location records
	registerAndBackfillStorageProviders()

	// Initialize background task runner for admin copy operations
	handlers.InitTaskRunner(2)

	// Run storage verification in the background (logs result, does not block startup)
	// Use the registry's primary provider ID (which reflects DB role reconciliation
	// from swap-providers/set-primary, not just env var ordering).
	storage.RunStartupVerification(storage.Registry.PrimaryID())

	// Check for bootstrap condition (Zero Users)
	if err := auth.CheckAndGenerateBootstrapToken(database.DB); err != nil {
		log.Fatalf("Failed to check/generate bootstrap token: %v", err)
	}

	// Initialize admin user if needed (Dev/Test only)
	if err := initializeAdminUser(); err != nil {
		log.Printf("Warning: Failed to initialize admin user: %v", err)
		log.Printf("Application will continue running without admin user setup")
		// Don't crash the app - admin user can be set up manually later
	}

	// Start the billing scheduler (storage credits / usage metering).
	// When cfg.Billing.Enabled=false, the scheduler exits cleanly without
	// touching the meter -- handy for dev-reset.sh which avoids time-dependent
	// test flakiness by disabling billing by default.
	billingCtx, cancelBilling := context.WithCancel(context.Background())
	defer cancelBilling()
	startBillingScheduler(billingCtx, cfg)

	// Create Echo instance
	e := echo.New()

	// Pin IP extraction to the kernel-reported transport peer address.
	// Echo's default c.RealIP() walks the X-Forwarded-For chain, which is
	// client-controllable and therefore unsafe for any authorization
	// decision (admin localhost gate, bootstrap localhost gate). Caddy
	// terminates TLS on this same host and reverse-proxies over loopback,
	// so the only "real" peer Arkfile sees is 127.0.0.1 from Caddy. The
	// public client's IP is propagated by Caddy in the X-Arkfile-Peer
	// header (set via header_up in the Caddyfile) and is read separately
	// by handlers.publicClientIP / logging.GetOrCreateEntityID for
	// rate-limiting and EntityID HMAC binning -- never for authz.
	e.IPExtractor = echo.ExtractIPDirect()

	// Basic security middleware first
	e.Use(middleware.Recover())
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "SAMEORIGIN",
		HSTSMaxAge:         63072000, // 2 years
		HSTSPreloadEnabled: true,
		// CSP is handled by CSPMiddleware below
	}))

	// Force HTTPS and check TLS version
	e.Pre(middleware.HTTPSRedirect())
	e.Use(handlers.TLSVersionCheck)

	// Enhanced security middleware
	e.Use(handlers.CSPMiddleware)
	// Note: ShareRateLimitMiddleware and TimingProtectionMiddleware are applied
	// specifically to share endpoints in route_config.go, not globally

	// Privacy-preserving request logger (no raw IP addresses)
	e.Use(handlers.PrivacyRequestLogger)

	// Unauthorized flood guard: progressive rate limiting for entities that
	// generate excessive 401/404 responses (vulnerability scanners, path probers)
	e.Use(handlers.FloodGuardMiddleware)

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     cfg.Server.AllowedOrigins,
		AllowMethods:     []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization, "X-Requested-With"},
		AllowCredentials: true,
		MaxAge:           300, // 5 minutes
	}))

	// Common routes setup
	setupRoutes(e)

	// Start server with TLS support
	port := cfg.Server.Port
	tlsPort := cfg.Server.TLSPort
	tlsEnabled := cfg.Server.TLSEnabled

	// Override with legacy environment variables if present
	if prodPort := os.Getenv("PROD_PORT"); prodPort != "" {
		port = prodPort
	}
	if testPort := os.Getenv("TEST_PORT"); testPort != "" {
		testDomain := os.Getenv("TEST_DOMAIN")
		host := os.Getenv("HOST")
		if host == testDomain {
			port = testPort
		}
	}

	if port == "" {
		port = "8080" // Default fallback
	}

	if tlsEnabled {
		// Get TLS certificate paths
		certFile := os.Getenv("TLS_CERT_FILE")
		keyFile := os.Getenv("TLS_KEY_FILE")

		if certFile == "" || keyFile == "" {
			log.Printf("TLS enabled but certificate files not specified, falling back to HTTP only")
			tlsEnabled = false
		}

		if tlsEnabled {
			if tlsPort == "" {
				tlsPort = "8443" // Default HTTPS port for demo
			}

			// Enforce TLS 1.3 only (PQ key exchange via X25519MLKEM768 requires TLS 1.3)
			e.TLSServer.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS13,
			}

			// Start HTTPS server in goroutine
			go func() {
				bindAddr := cfg.Server.Host + ":" + tlsPort
				log.Printf("Starting HTTPS server on %s (TLS 1.3 only)", bindAddr)
				if err := e.StartTLS(bindAddr, certFile, keyFile); err != nil {
					logging.ErrorLogger.Printf("Failed to start HTTPS server: %v", err)
				}
			}()

			// Add a small delay to let HTTPS server start
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Start HTTP server
	bindAddr := cfg.Server.Host + ":" + port
	log.Printf("Starting HTTP server on %s", bindAddr)
	if err := e.Start(bindAddr); err != nil {
		logging.ErrorLogger.Printf("Failed to start HTTP server: %v", err)
	}
}

// startBillingScheduler launches the storage credits / usage metering scheduler
// in a background goroutine. When cfg.Billing.Enabled=false the scheduler exits
// cleanly without touching the meter (handy for dev-reset.sh which avoids
// time-dependent test flakiness by disabling billing by default).
//
// Wires the handler-side projection seam (handlers.SetBillingProjectionSeams)
// so /api/credits and admin endpoints can render rate-aware fields. The seam
// is wired even when billing is disabled, so the response shape stays stable
// (just with rate-unavailable fallback values).
func startBillingScheduler(ctx context.Context, cfg *config.Config) {
	// Wire the handler projection seam regardless of billing enabled state.
	// When disabled, the resolved rate is the fallback "rate not available"
	// path -- responses still include the structurally-identical block.
	handlers.SetBillingProjectionSeams(
		func() int64 { return cfg.Billing.FreeBaselineBytes },
		func(db *sql.DB) (int64, string, bool) {
			if cached := billing.CachedRate(); cached != nil {
				return cached.MicrocentsPerGiBPerHour, cached.CustomerPriceUSDPerTBPerMonth, true
			}
			rate, err := billing.ResolveRate(db, cfg.Billing)
			if err != nil || rate == nil {
				return 0, "", false
			}
			return rate.MicrocentsPerGiBPerHour, rate.CustomerPriceUSDPerTBPerMonth, true
		},
	)
	// Expose the gift function to handlers without an import cycle.
	handlers.SetBillingGiftFunc(billing.GiftCredits)
	// Expose the set-customer-price function to handlers.
	handlers.SetBillingSetPriceFunc(func(db *sql.DB, priceStr, updatedBy string) (int64, string, error) {
		rate, err := billing.SetCustomerPrice(db, priceStr, updatedBy)
		if err != nil {
			return 0, "", err
		}
		return rate.MicrocentsPerGiBPerHour, rate.CustomerPriceUSDPerTBPerMonth, nil
	})
	// Expose tick-now and sweep-now for the dev-test endpoint.
	handlers.SetBillingTickNowFunc(func(db *sql.DB) error {
		rate := billing.CachedRate()
		if rate == nil {
			r, err := billing.ResolveRate(db, cfg.Billing)
			if err != nil {
				return err
			}
			rate = r
		}
		_, _, err := billing.TickAllActiveUsers(db, rate, time.Now().UTC(), cfg.Billing)
		return err
	})
	handlers.SetBillingSweepNowFunc(func(db *sql.DB) error {
		rate := billing.CachedRate()
		if rate == nil {
			r, err := billing.ResolveRate(db, cfg.Billing)
			if err != nil {
				return err
			}
			rate = r
		}
		_, err := billing.SweepAllUsers(db, rate, time.Now().UTC())
		return err
	})
	handlers.SetProcessPaymentFunc(billing.ProcessPayment)
	handlers.SetSettlePaymentInvoiceFunc(billing.SettlePaymentInvoice)

	if !cfg.Billing.Enabled {
		logging.InfoLogger.Print("billing scheduler disabled (ARKFILE_BILLING_ENABLED=false)")
		return
	}

	scheduler := billing.NewScheduler(database.DB, cfg.Billing)
	go func() {
		if err := scheduler.Run(ctx); err != nil && err != context.Canceled {
			logging.ErrorLogger.Printf("billing scheduler exited: %v", err)
		}
	}()
}

// runSchemaMigrations applies one-shot schema migrations that cannot be expressed in
// the unified_schema.sql file (because ALTER TABLE statements fail if the column
// already exists or is already renamed, and rqlite treats that as a fatal error
// when executing the schema as a single operation). Each migration is attempted
// individually and idempotent-when-already-applied error messages are silently ignored.
//
// Two classes of migrations live here:
//   - Additive (ADD COLUMN): tolerated error is "duplicate column".
//   - Renames (RENAME COLUMN): tolerated errors are "no such column" (old column already
//     renamed away) or "duplicate column"/"already exists" (target name already present).
func runSchemaMigrations() {
	migrations := []struct {
		description string
		sql         string
	}{
		{
			description: "Add stored_blob_sha256sum to file_metadata",
			sql:         "ALTER TABLE file_metadata ADD COLUMN stored_blob_sha256sum CHAR(64)",
		},
		// Storage credits / billing meter (v2): rename _cents columns to _microcents.
		// These run once on first startup after upgrading; safe no-op on subsequent runs
		// and on fresh installs (where the unified schema already declares _microcents).
		{
			description: "Rename user_credits.balance_usd_cents to balance_usd_microcents",
			sql:         "ALTER TABLE user_credits RENAME COLUMN balance_usd_cents TO balance_usd_microcents",
		},
		{
			description: "Rename credit_transactions.amount_usd_cents to amount_usd_microcents",
			sql:         "ALTER TABLE credit_transactions RENAME COLUMN amount_usd_cents TO amount_usd_microcents",
		},
		{
			description: "Rename credit_transactions.balance_after_usd_cents to balance_after_usd_microcents",
			sql:         "ALTER TABLE credit_transactions RENAME COLUMN balance_after_usd_cents TO balance_after_usd_microcents",
		},
	}

	for _, m := range migrations {
		_, err := database.DB.Exec(m.sql)
		if err != nil {
			errStr := strings.ToLower(err.Error())
			switch {
			case strings.Contains(errStr, "duplicate column"),
				strings.Contains(errStr, "already exists"):
				log.Printf("Migration: %s (already applied)", m.description)
			case strings.Contains(errStr, "no such column"):
				// Old column name not present - either the rename has already been
				// applied previously or this is a fresh install where the unified
				// schema declared the new column name from the start.
				log.Printf("Migration: %s (already applied or fresh install)", m.description)
			default:
				log.Printf("Migration: %s failed: %v", m.description, err)
			}
		} else {
			log.Printf("Migration: %s applied successfully", m.description)
		}
	}

	migrateCreditTransactionsPaymentType()
}

// migrateCreditTransactionsPaymentType rebuilds credit_transactions when the CHECK
// constraint does not yet allow transaction_type = 'payment'.
func migrateCreditTransactionsPaymentType() {
	const desc = "Add payment to credit_transactions.transaction_type CHECK constraint"
	var createSQL string
	err := database.DB.QueryRow(
		`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'credit_transactions'`,
	).Scan(&createSQL)
	if err != nil {
		log.Printf("Migration: %s skipped (table missing): %v", desc, err)
		return
	}
	if strings.Contains(createSQL, "'payment'") {
		log.Printf("Migration: %s (already applied)", desc)
		return
	}

	rebuildSQL := `
		CREATE TABLE credit_transactions_new (
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
		INSERT INTO credit_transactions_new
			(id, transaction_id, username, amount_usd_microcents, balance_after_usd_microcents,
			 transaction_type, reason, admin_username, metadata, created_at)
		SELECT id, transaction_id, username, amount_usd_microcents, balance_after_usd_microcents,
		       transaction_type, reason, admin_username, metadata, created_at
		FROM credit_transactions;
		DROP TABLE credit_transactions;
		ALTER TABLE credit_transactions_new RENAME TO credit_transactions;
		CREATE INDEX IF NOT EXISTS idx_credit_transactions_username ON credit_transactions(username);
		CREATE INDEX IF NOT EXISTS idx_credit_transactions_transaction_id ON credit_transactions(transaction_id);
		CREATE INDEX IF NOT EXISTS idx_credit_transactions_type ON credit_transactions(transaction_type);
		CREATE INDEX IF NOT EXISTS idx_credit_transactions_created_at ON credit_transactions(created_at);
		CREATE INDEX IF NOT EXISTS idx_credit_transactions_admin ON credit_transactions(admin_username);
	`

	if _, err := database.DB.Exec(rebuildSQL); err != nil {
		log.Printf("Migration: %s failed: %v", desc, err)
		return
	}
	log.Printf("Migration: %s applied successfully", desc)
}

type configuredStorageProvider struct {
	provider     storage.ObjectStorageProvider
	providerID   string
	providerType string
	bucket       string
	endpoint     string
	region       string
	envPrefix    string
	defaultRole  string
}

func configuredStorageProvidersFromEnv(reg *storage.ProviderRegistry) []configuredStorageProvider {
	providers := []configuredStorageProvider{}
	addProvider := func(provider storage.ObjectStorageProvider, providerID, providerType, bucket, endpoint, region, envPrefix, defaultRole string) {
		if provider == nil || providerID == "" {
			return
		}
		if region == "" {
			region = "us-east-1"
		}
		providers = append(providers, configuredStorageProvider{
			provider:     provider,
			providerID:   providerID,
			providerType: providerType,
			bucket:       bucket,
			endpoint:     endpoint,
			region:       region,
			envPrefix:    envPrefix,
			defaultRole:  defaultRole,
		})
	}

	addProvider(
		reg.Primary(),
		reg.PrimaryID(),
		os.Getenv("STORAGE_PROVIDER_1"),
		os.Getenv("STORAGE_1_BUCKET"),
		os.Getenv("STORAGE_1_ENDPOINT"),
		os.Getenv("STORAGE_1_REGION"),
		"STORAGE_1",
		"primary",
	)
	if reg.HasSecondary() {
		addProvider(
			reg.Secondary(),
			reg.SecondaryID(),
			os.Getenv("STORAGE_PROVIDER_2"),
			os.Getenv("STORAGE_2_BUCKET"),
			os.Getenv("STORAGE_2_ENDPOINT"),
			os.Getenv("STORAGE_2_REGION"),
			"STORAGE_2",
			"secondary",
		)
	}
	if reg.HasTertiary() {
		addProvider(
			reg.Tertiary(),
			reg.TertiaryID(),
			os.Getenv("STORAGE_PROVIDER_3"),
			os.Getenv("STORAGE_3_BUCKET"),
			os.Getenv("STORAGE_3_ENDPOINT"),
			os.Getenv("STORAGE_3_REGION"),
			"STORAGE_3",
			"tertiary",
		)
	}

	return providers
}

func resolveStorageRoleAssignments(configured []configuredStorageProvider, dbRoles map[string]string) map[string]*configuredStorageProvider {
	assignments := map[string]*configuredStorageProvider{
		"primary":   nil,
		"secondary": nil,
		"tertiary":  nil,
	}
	used := map[string]bool{}

	// Pass 1: Assign explicitly mapped DB roles
	for i := range configured {
		provider := &configured[i]
		role := dbRoles[provider.providerID]
		if role != "primary" && role != "secondary" && role != "tertiary" {
			continue // No valid DB role, will fallback in pass 2
		}
		if assignments[role] != nil {
			continue // Another provider already took this DB role, fallback
		}
		assignments[role] = provider
		used[provider.providerID] = true
	}

	// Pass 2: Assign remaining configured providers to open slots based on env ordering
	for _, role := range []string{"primary", "secondary", "tertiary"} {
		if assignments[role] != nil {
			continue
		}
		for i := range configured {
			provider := &configured[i]
			if used[provider.providerID] {
				continue
			}
			assignments[role] = provider
			used[provider.providerID] = true
			break
		}
	}

	return assignments
}

// registerAndBackfillStorageProviders upserts configured storage providers into the
// database, backfills file_storage_locations for existing files, recalculates provider
// stats, and marks stale admin tasks as failed. Called once on server startup after
// storage.InitS3() and database.InitDB().
func registerAndBackfillStorageProviders() {
	reg := storage.Registry
	if reg == nil {
		log.Printf("Storage: skipping provider registration (no registry)")
		return
	}

	// Helper to upsert a provider config into the DB
	upsertProvider := func(providerID, providerType, bucket, endpoint, region, role, envPrefix string) {
		record := &models.StorageProviderRecord{
			ProviderID:   providerID,
			ProviderType: providerType,
			BucketName:   bucket,
			Endpoint:     endpoint,
			Region:       region,
			Role:         role,
			EnvVarPrefix: envPrefix,
			IsActive:     true,
		}
		if err := models.UpsertStorageProvider(database.DB, record); err != nil {
			log.Printf("Storage: failed to upsert provider %s: %v", providerID, err)
		}
	}

	// Read and upsert all configured providers using slot ordering initially
	configuredProviders := configuredStorageProvidersFromEnv(reg)
	for _, provider := range configuredProviders {
		upsertProvider(provider.providerID, provider.providerType, provider.bucket, provider.endpoint, provider.region, provider.defaultRole, provider.envPrefix)
	}

	// Retrieve authoritative DB roles to reconcile the in-memory registry
	dbRoles := make(map[string]string, len(configuredProviders))
	for _, provider := range configuredProviders {
		role, err := models.GetStorageProviderRole(database.DB, provider.providerID)
		if err == nil {
			dbRoles[provider.providerID] = role
		}
	}

	// Resolve the 3-way assignment: DB roles win, slot order is fallback
	assignments := resolveStorageRoleAssignments(configuredProviders, dbRoles)

	if primaryAssignment := assignments["primary"]; primaryAssignment != nil {
		if reg.PrimaryID() != primaryAssignment.providerID {
			log.Printf("Storage: startup reconciliation set primary to %s (from DB role)", primaryAssignment.providerID)
		}
		reg.SetPrimary(primaryAssignment.provider, primaryAssignment.providerID)
	}

	if secondaryAssignment := assignments["secondary"]; secondaryAssignment != nil {
		if reg.SecondaryID() != secondaryAssignment.providerID {
			log.Printf("Storage: startup reconciliation set secondary to %s (from DB role)", secondaryAssignment.providerID)
		}
		reg.SetSecondary(secondaryAssignment.provider, secondaryAssignment.providerID)
	} else {
		reg.SetSecondary(nil, "")
	}

	if tertiaryAssignment := assignments["tertiary"]; tertiaryAssignment != nil {
		if reg.TertiaryID() != tertiaryAssignment.providerID {
			log.Printf("Storage: startup reconciliation set tertiary to %s (from DB role)", tertiaryAssignment.providerID)
		}
		reg.SetTertiary(tertiaryAssignment.provider, tertiaryAssignment.providerID)
	} else {
		reg.SetTertiary(nil, "")
	}

	// Backfill file_storage_locations for existing files without location records
	backfilled, err := models.BackfillFileStorageLocations(database.DB, reg.PrimaryID())
	if err != nil {
		log.Printf("Storage: backfill failed: %v", err)
	} else if backfilled > 0 {
		log.Printf("Storage: backfilled %d file location records for primary provider %s", backfilled, reg.PrimaryID())
	}

	// Recalculate primary provider stats from actual data
	if err := models.RecalculateProviderStats(database.DB, reg.PrimaryID()); err != nil {
		log.Printf("Storage: failed to recalculate primary stats: %v", err)
	}

	// Mark any stale admin tasks (from previous server crashes) as failed
	staleTasks, err := models.MarkStaleTasksAsFailed(database.DB)
	if err != nil {
		log.Printf("Storage: failed to mark stale tasks: %v", err)
	} else if staleTasks > 0 {
		log.Printf("Storage: marked %d stale admin tasks as failed", staleTasks)
	}

	log.Printf("Storage: provider registration and backfill complete")
}

// initializeAdminUser creates and configures the designated admin user if needed
// CRITICAL SECURITY: This function MUST NEVER run in production environment
func initializeAdminUser() error {
	// SECURITY CHECK #1: Block in production environment
	if utils.IsProductionEnvironment() {
		// Log critical security warning and BLOCK execution
		logging.ErrorLogger.Printf("CRITICAL SECURITY: initializeAdminUser() blocked in production environment")
		return fmt.Errorf("SECURITY: Admin user initialization blocked in production environment")
	}

	// SECURITY CHECK #2: Verify we have admin usernames configured
	adminUsernames := os.Getenv("ADMIN_USERNAMES")
	if adminUsernames == "" {
		log.Printf("No ADMIN_USERNAMES configured, skipping admin user initialization")
		return nil
	}

	// Fixed dev admin credentials for testing
	const devAdminUsername = "arkfile-dev-admin"
	const devAdminPassword = "DevAdmin2025!SecureInitialPassword"
	const devAdminTOTPSecret = "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D"

	// SECURITY CHECK #3: Only auto-create if arkfile-dev-admin is in ADMIN_USERNAMES
	if !strings.Contains(adminUsernames, devAdminUsername) {
		log.Printf("Dev admin username '%s' not in ADMIN_USERNAMES, skipping auto-creation", devAdminUsername)
		return nil
	}

	log.Printf("Checking if dev admin user '%s' needs initialization...", devAdminUsername)

	// Check if admin user already exists
	existingUser, err := models.GetUserByUsername(database.DB, devAdminUsername)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check admin user existence: %w", err)
	}

	if existingUser != nil {
		log.Printf("Dev admin user '%s' already exists (ID: %d), skipping initialization", devAdminUsername, existingUser.ID)
		return nil
	}

	// Create dev admin user with OPAQUE protocol
	log.Printf("Creating dev admin user with OPAQUE registration...")
	user, err := auth.CreateDevAdminWithOPAQUE(database.DB, devAdminUsername, devAdminPassword)
	if err != nil {
		return fmt.Errorf("failed to create dev admin user: %w", err)
	}

	log.Printf("Dev admin user created successfully: %s (ID: %d)", user.Username, user.ID)

	// Setup TOTP with fixed secret
	log.Printf("Setting up TOTP for dev admin user...")
	if err := auth.SetupDevAdminTOTP(database.DB, user, devAdminTOTPSecret); err != nil {
		return fmt.Errorf("failed to setup dev admin TOTP: %w", err)
	}

	log.Printf("Dev admin TOTP setup completed successfully")

	// Validate the complete TOTP workflow
	log.Printf("Validating dev admin TOTP workflow...")
	if err := auth.ValidateDevAdminTOTPWorkflow(database.DB, user, devAdminTOTPSecret); err != nil {
		log.Printf("Warning: Dev admin TOTP workflow validation failed: %v", err)
		// Don't fail - allow server to start even if validation fails
	} else {
		log.Printf("Dev admin TOTP workflow validation passed")
	}

	// NEW: Validate complete authentication flow (OPAQUE + TOTP)
	log.Printf("Validating complete dev admin authentication flow...")
	if err := auth.ValidateDevAdminAuthentication(database.DB, devAdminUsername, devAdminPassword, devAdminTOTPSecret); err != nil {
		log.Printf("CRITICAL: Dev admin authentication validation failed: %v", err)
		// This is critical - if authentication doesn't work, the system is broken
		return fmt.Errorf("dev admin authentication validation failed: %w", err)
	}

	log.Printf("SUCCESS: Full OPAQUE Auth + TOTP validation complete for '%s' user.", devAdminUsername)

	return nil
}
