package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/billing"
	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
)

type upsertPlanRequest struct {
	PlanID            string `json:"plan_id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	PriceUSD          string `json:"price_usd"`
	PriceUSDCents     int    `json:"price_usd_cents"`
	StorageLimitBytes int64  `json:"storage_limit_bytes"`
	StorageLimit      string `json:"storage_limit"`
	SortOrder         int    `json:"sort_order"`
	IsActive          *bool  `json:"is_active"`
	IsPublic          *bool  `json:"is_public"`
}

type grantGiftRequest struct {
	PlanID string `json:"plan_id"`
	Days   int    `json:"days"`
	Note   string `json:"note"`
}

func AdminListSubscriptionPlansHandler(c echo.Context) error {
	if _, err := requireSubscriptionsAdmin(c); err != nil {
		return err
	}
	plans, err := models.ListAllSubscriptionPlans(database.DB)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to list plans")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"plans": plans},
	})
}

func AdminUpsertSubscriptionPlanHandler(c echo.Context) error {
	adminUsername, err := requireSubscriptionsAdmin(c)
	if err != nil {
		return err
	}
	var req upsertPlanRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}
	if strings.TrimSpace(req.PlanID) == "" || strings.TrimSpace(req.Name) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "plan_id and name are required")
	}
	priceCents := req.PriceUSDCents
	if priceCents == 0 && req.PriceUSD != "" {
		micro, perr := models.ParseCreditsFromUSD(req.PriceUSD)
		if perr != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid price_usd")
		}
		priceCents = int(micro / (models.MicrocentsPerUSD / 100))
	}
	storageBytes := req.StorageLimitBytes
	if storageBytes == 0 && req.StorageLimit != "" {
		parsed, perr := parseStorageLimitString(req.StorageLimit)
		if perr != nil {
			return echo.NewHTTPError(http.StatusBadRequest, perr.Error())
		}
		storageBytes = parsed
	}
	if storageBytes <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "storage_limit_bytes or storage_limit is required")
	}
	active := true
	public := true
	if req.IsActive != nil {
		active = *req.IsActive
	}
	if req.IsPublic != nil {
		public = *req.IsPublic
	}
	plan := &models.SubscriptionPlan{
		PlanID:            req.PlanID,
		Name:              req.Name,
		Description:       req.Description,
		PriceUSDCents:     priceCents,
		StorageLimitBytes: storageBytes,
		SortOrder:         req.SortOrder,
		IsActive:          active,
		IsPublic:          public,
		UpdatedBy:         adminUsername,
	}
	if err := models.UpsertSubscriptionPlan(database.DB, plan); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save plan")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"success": true, "plan": plan})
}

func AdminGetUserSubscriptionHandler(c echo.Context) error {
	if _, err := requireSubscriptionsAdmin(c); err != nil {
		return err
	}
	username := c.Param("username")
	user, err := models.GetUserByUsername(database.DB, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to load user")
	}
	sub, _ := billing.GetActiveSubscription(database.DB, username)
	effectiveLimit, _ := billing.EffectiveStorageLimit(database.DB, username)
	data := map[string]interface{}{
		"username":                      username,
		"baseline_storage_bytes":        user.StorageLimitBytes,
		"effective_storage_limit_bytes": effectiveLimit,
		"billing_mode":                  string(billing.EffectiveBillingMode(database.DB, username)),
	}
	if sub != nil {
		data["subscription"] = sub
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"success": true, "data": data})
}

func AdminGrantGiftSubscriptionHandler(c echo.Context) error {
	adminUsername, err := requireSubscriptionsAdmin(c)
	if err != nil {
		return err
	}
	username := c.Param("username")
	var req grantGiftRequest
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.PlanID) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "plan_id is required")
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Configuration error")
	}
	days := req.Days
	if days == 0 {
		days = cfg.Subscriptions.GiftDefaultDays
	}
	if days > cfg.Subscriptions.GiftMaxDays {
		return echo.NewHTTPError(http.StatusBadRequest, "days exceeds maximum allowed for gift subscriptions")
	}
	sub, err := billing.GrantGiftSubscription(database.DB, username, req.PlanID, days, req.Note, adminUsername)
	if err != nil {
		if strings.Contains(err.Error(), "already has an active") {
			return echo.NewHTTPError(http.StatusConflict, err.Error())
		}
		if err == sql.ErrNoRows || strings.Contains(err.Error(), "not found") {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		logging.ErrorLogger.Printf("Grant gift subscription: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to grant gift subscription")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"success": true, "subscription": sub})
}

func AdminCancelGiftSubscriptionHandler(c echo.Context) error {
	if _, err := requireSubscriptionsAdmin(c); err != nil {
		return err
	}
	username := c.Param("username")
	immediate := c.QueryParam("immediate") == "true" || c.QueryParam("immediate") == "1"
	if err := billing.CancelGiftSubscription(database.DB, username, immediate); err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, "No active subscription for user")
		}
		if strings.Contains(err.Error(), "paid subscriptions") {
			return echo.NewHTTPError(http.StatusConflict, err.Error())
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to cancel gift subscription")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"success": true})
}

func AdminSyncUserSubscriptionHandler(c echo.Context) error {
	if _, err := requireSubscriptionsAdmin(c); err != nil {
		return err
	}
	username := c.Param("username")
	sub, err := billing.GetActiveSubscription(database.DB, username)
	if err != nil || sub == nil {
		return echo.NewHTTPError(http.StatusNotFound, "No active subscription for user")
	}
	if sub.Source != "bridge" {
		return echo.NewHTTPError(http.StatusBadRequest, "Sync applies to bridge-backed subscriptions only")
	}
	if err := billing.ReconcileEntitlementFromBridge(database.DB, sub.EntitlementRef); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	updated, _ := billing.GetActiveSubscription(database.DB, username)
	return c.JSON(http.StatusOK, map[string]interface{}{"success": true, "subscription": updated})
}

func AdminReconcileSubscriptionsHandler(c echo.Context) error {
	if _, err := requireSubscriptionsAdmin(c); err != nil {
		return err
	}
	withinDays := 7
	if v := c.QueryParam("within_days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			withinDays = n
		}
	}
	count, err := billing.ReconcileBridgeSubscriptions(database.DB, withinDays)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Reconcile failed")
	}
	giftExpired, _ := billing.ExpireDueGiftSubscriptions(database.DB)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"bridge_reconciled": count,
			"gifts_expired":     giftExpired,
		},
	})
}

func requireSubscriptionsAdmin(c echo.Context) (string, error) {
	cfg, err := config.LoadConfig()
	if err != nil || !cfg.Subscriptions.Enabled {
		return "", subscriptionsDisabledError()
	}
	adminUsername := auth.GetUsernameFromToken(c)
	if adminUsername == "" {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}
	adminUser, err := models.GetUserByUsername(database.DB, adminUsername)
	if err != nil || !adminUser.HasAdminPrivileges() {
		return "", echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}
	return adminUsername, nil
}

func parseStorageLimitString(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, sql.ErrNoRows
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "TIB"):
		mult = 1 << 40
		s = strings.TrimSuffix(s, "TIB")
	case strings.HasSuffix(s, "TB"):
		mult = 1 << 40
		s = strings.TrimSuffix(s, "TB")
	case strings.HasSuffix(s, "GIB"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "GIB")
	case strings.HasSuffix(s, "GB"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MIB"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "MIB")
	case strings.HasSuffix(s, "MB"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "MB")
	}
	s = strings.TrimSpace(s)
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}
	return int64(n * float64(mult)), nil
}
