package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arkfile/Arkfile/config"
)

func TestAdminContactsHandler_Configured(t *testing.T) {
	config.ResetConfigForTest()
	t.Setenv("ARKFILE_ADMIN_CONTACT", "ops@example.com")
	t.Setenv("ADMIN_USERNAMES", "alice")

	c, rec, _, _ := setupTestEnv(t, http.MethodGet, "/api/admin-contacts", nil)

	err := AdminContactsHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"configured":true`)
	assert.Contains(t, rec.Body.String(), `"admin_contact":"ops@example.com"`)
	assert.Contains(t, rec.Body.String(), `"admin_usernames":["alice"]`)
}

func TestAdminContactsHandler_Unconfigured(t *testing.T) {
	config.ResetConfigForTest()
	t.Setenv("CONFIG_FILE", "")
	t.Setenv("ARKFILE_ADMIN_CONTACT", "")
	t.Setenv("ADMIN_USERNAMES", "")
	t.Setenv("ADMIN_USERNAMES", "")

	c, rec, _, _ := setupTestEnv(t, http.MethodGet, "/api/admin-contacts", nil)

	err := AdminContactsHandler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, false, payload["configured"])
	assert.Equal(t, "", payload["admin_contact"])
	usernames, ok := payload["admin_usernames"].([]interface{})
	require.True(t, ok)
	assert.Len(t, usernames, 0)
}
