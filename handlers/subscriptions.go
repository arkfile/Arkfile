package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/billing"
	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	"github.com/arkfile/Arkfile/subbridge"
)

type subscriptionCheckoutRequest struct {
	PlanID string `json:"plan_id"`
}

func subscriptionsDisabledError() *echo.HTTPError {
	return echo.NewHTTPError(http.StatusForbidden, "Subscriptions are disabled on this instance")
}

func ListSubscriptionPlansHandler(c echo.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil || !cfg.Subscriptions.Enabled {
		return subscriptionsDisabledError()
	}
	plans, err := models.ListPublicSubscriptionPlans(database.DB)
	if err != nil {
		logging.ErrorLogger.Printf("List subscription plans: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to list plans")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"plans":   plans,
	})
}

func GetMySubscriptionHandler(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}
	cfg, err := config.LoadConfig()
	if err != nil || !cfg.Subscriptions.Enabled {
		return subscriptionsDisabledError()
	}

	sub, err := billing.GetActiveSubscription(database.DB, username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to load subscription")
	}
	effectiveLimit, _ := billing.EffectiveStorageLimit(database.DB, username)
	user, _ := models.GetUserByUsername(database.DB, username)
	baseline := int64(models.DefaultStorageLimit)
	if user != nil {
		baseline = user.StorageLimitBytes
	}

	data := map[string]interface{}{
		"billing_mode":                  string(billing.EffectiveBillingMode(database.DB, username)),
		"baseline_storage_bytes":        baseline,
		"effective_storage_limit_bytes": effectiveLimit,
	}
	if sub != nil {
		data["subscription"] = map[string]interface{}{
			"status":               sub.Status,
			"plan_id":              sub.PlanID,
			"plan_name":            sub.PlanName,
			"price_usd":            models.FormatPlanPriceUSD(sub.PlanPriceUSDCents),
			"plan_storage_bytes":   sub.PlanStorageBytes,
			"current_period_end":   sub.CurrentPeriodEnd.UTC().Format("2006-01-02T15:04:05Z07:00"),
			"cancel_at_period_end": sub.CancelAtPeriodEnd,
			"source":               sub.Source,
		}
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"success": true, "data": data})
}

func CreateSubscriptionCheckoutHandler(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}
	cfg, err := config.LoadConfig()
	if err != nil || !cfg.Subscriptions.Enabled {
		return subscriptionsDisabledError()
	}

	active, err := billing.GetActiveSubscription(database.DB, username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check subscription state")
	}
	if active != nil {
		return echo.NewHTTPError(http.StatusConflict,
			"You already have an active subscription. Manage your plan from billing or use `arkfile-client subscription portal`.")
	}

	var req subscriptionCheckoutRequest
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.PlanID) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "plan_id is required")
	}
	plan, err := models.GetSubscriptionPlan(database.DB, req.PlanID)
	if err != nil || !plan.IsActive || !plan.IsPublic {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid or unavailable plan")
	}

	checkoutID := "subchk_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	if err := models.CreateSubscriptionCheckout(database.DB, &models.SubscriptionCheckout{
		CheckoutID: checkoutID,
		Username:   username,
		PlanID:     plan.PlanID,
		Status:     "pending",
	}); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create checkout")
	}

	returnURL := cfg.Subscriptions.ReturnURL
	if returnURL == "" {
		returnURL = strings.TrimRight(cfg.Server.BaseURL, "/") + "/?subscription=return"
	}
	checkoutURL, err := billing.CreateCheckoutURL(cfg.Subscriptions, checkoutID, plan.PlanID, returnURL)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to sign checkout token")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"checkout_url": checkoutURL,
			"checkout_id":  checkoutID,
		},
	})
}

func CreateSubscriptionPortalHandler(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}
	cfg, err := config.LoadConfig()
	if err != nil || !cfg.Subscriptions.Enabled {
		return subscriptionsDisabledError()
	}

	sub, err := billing.GetActiveSubscription(database.DB, username)
	if err != nil || sub == nil || sub.Source != "bridge" {
		return echo.NewHTTPError(http.StatusBadRequest, "No paid subscription to manage")
	}

	returnURL := cfg.Subscriptions.ReturnURL
	if returnURL == "" {
		returnURL = strings.TrimRight(cfg.Server.BaseURL, "/") + "/"
	}
	portalURL, err := billing.CreatePortalURL(cfg.Subscriptions, sub.SubscriptionRef, returnURL)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to sign portal token")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"portal_url": portalURL,
		},
	})
}

func SubscriptionBridgeWebhookHandler(c echo.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal configuration error")
	}
	if !cfg.Subscriptions.Enabled {
		return echo.NewHTTPError(http.StatusForbidden, "Subscriptions are disabled")
	}

	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to read body")
	}
	sig := c.Request().Header.Get(subbridge.SignatureHeaderName)
	if err := subbridge.VerifyWebhookSignature(cfg.Subscriptions.WebhookSecret, body, sig); err != nil {
		logging.ErrorLogger.Printf("Subscription bridge webhook signature failed: %v", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid signature")
	}

	var payload subbridge.CallbackPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid JSON")
	}

	if err := billing.ProcessSubscriptionBridgeCallback(database.DB, &payload); err != nil {
		logging.ErrorLogger.Printf("Subscription bridge webhook processing failed: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process subscription bridge event")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"success": true})
}
