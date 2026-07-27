package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arkfile/Arkfile/config"
)

const testPayNymPaymentCode = "PM8TJYp8zHvhimVNRjUcEuULfmvmUML6YTbTSnU69MYy93AzsXELFLaVjpxc5mxDex7R8ttgtL1tGAt2TshZAoFeB5zn4c9nRo4oZpmuyuo4FTpUrd"

// 95-character stand-in Monero address for config validation length checks.
const testMoneroAddress = "4AdUndXHHZ6cfufTMvppY6JwXNouMBbJN3dZYEj3oKtMbLhQqVjX8j5kL9nP1mR2sT3uV4wX5yZ6aB7cD8eF9gH0iJ1kLmN"

func TestOobPaymentsHandler_Unconfigured(t *testing.T) {
	config.ResetConfigForTest()
	t.Setenv("ADMIN_PAYNYM", "")
	t.Setenv("ADMIN_PAYNYM_PAYMENT_CODE", "")
	t.Setenv("ADMIN_MONERO_ADDRESS", "")

	c, rec, _, _ := setupTestEnv(t, http.MethodGet, "/api/oob-payments", nil)

	err := OobPaymentsHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, false, body["configured"])
	assert.Equal(t, "", body["paynym"])
	assert.Equal(t, "", body["paynym_payment_code"])
	assert.Equal(t, "", body["monero_address"])
}

func TestOobPaymentsHandler_Configured(t *testing.T) {
	config.ResetConfigForTest()
	t.Setenv("ADMIN_PAYNYM", "+testpaynym99")
	t.Setenv("ADMIN_PAYNYM_PAYMENT_CODE", testPayNymPaymentCode)
	t.Setenv("ADMIN_MONERO_ADDRESS", testMoneroAddress)
	t.Setenv("ARKFILE_ADMIN_CONTACT", "ops@example.test")

	c, rec, _, _ := setupTestEnv(t, http.MethodGet, "/api/oob-payments", nil)

	err := OobPaymentsHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, true, body["configured"])
	assert.Equal(t, "+testpaynym99", body["paynym"])
	assert.Equal(t, testPayNymPaymentCode, body["paynym_payment_code"])
	assert.Equal(t, testMoneroAddress, body["monero_address"])
	assert.Equal(t, "ops@example.test", body["admin_contact"])
}
