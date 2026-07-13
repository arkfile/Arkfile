package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/arkfile/Arkfile/crypto"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ticketTokenAndHash generates a random 32-byte download token and returns its
// base64 form plus the base64 SHA-256 hash the server would store, matching the
// logic in hashDownloadToken (file_shares.go).
func ticketTokenAndHash(t *testing.T) (tokenB64, hashB64 string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	tokenB64 = base64.StdEncoding.EncodeToString(raw)
	h := sha256.Sum256(raw)
	hashB64 = base64.StdEncoding.EncodeToString(h[:])
	return
}

// expectRateLimitCheck mocks the two queries getOrCreateRateLimitEntry runs
// for an entity with no prior failures, so checkRateLimit returns allowed.
func expectRateLimitCheck(mock sqlmock.Sqlmock, shareID string) {
	mock.ExpectExec(`INSERT OR IGNORE INTO share_access_attempts`).
		WithArgs(shareID, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectQuery(`SELECT share_id, entity_id, failed_count, last_failed_attempt, next_allowed_attempt`).
		WithArgs(shareID, sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{
			"share_id", "entity_id", "failed_count", "last_failed_attempt", "next_allowed_attempt",
		}).AddRow(shareID, "uninitialized", 0, nil, nil))
}

func TestIssueShareDownloadTicket_Success(t *testing.T) {
	tokenB64, hashB64 := ticketTokenAndHash(t)

	reqBody, _ := json.Marshal(map[string]string{"download_token": tokenB64})
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/public/shares/"+testShareID+"/ticket", bytes.NewReader(reqBody))
	c.SetParamNames("id")
	c.SetParamValues(testShareID)

	expectRateLimitCheck(mock, testShareID)

	shareRows := sqlmock.NewRows([]string{
		"download_token_hash", "expires_at", "revoked_at", "revoked_reason", "access_count", "max_accesses",
	}).AddRow(hashB64, nil, nil, nil, 0, nil)
	mock.ExpectQuery(`SELECT download_token_hash, expires_at, revoked_at, revoked_reason, access_count, max_accesses`).
		WithArgs(testShareID).
		WillReturnRows(shareRows)

	err := IssueShareDownloadTicket(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	ticket, _ := resp["ticket"].(string)
	require.NotEmpty(t, ticket, "response must include a ticket")

	// The issued ticket must verify under the server ticket key for the entity
	// ID the handler observed. GetOrCreateEntityID returns "uninitialized" in
	// handler tests (DefaultEntityIDService is nil), which is deterministic.
	ticketKey, err := crypto.GetShareTicketKey()
	require.NoError(t, err)
	_, err = crypto.VerifyShareTicket(ticketKey, ticket, testShareID, "uninitialized", time.Now())
	assert.NoError(t, err, "issued ticket must verify for the issuing entity")

	// A different entity ID must NOT verify (entity binding).
	_, err = crypto.VerifyShareTicket(ticketKey, ticket, testShareID, "some-other-entity-id-padding-to-64-chars-ok!!", time.Now())
	assert.Error(t, err, "issued ticket must not verify for a different entity")
}

func TestIssueShareDownloadTicket_InvalidToken(t *testing.T) {
	_, hashB64 := ticketTokenAndHash(t)

	badRaw := bytes.Repeat([]byte{0x07}, 32)
	badTokenB64 := base64.StdEncoding.EncodeToString(badRaw)
	reqBody, _ := json.Marshal(map[string]string{"download_token": badTokenB64})
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/public/shares/"+testShareID+"/ticket", bytes.NewReader(reqBody))
	c.SetParamNames("id")
	c.SetParamValues(testShareID)

	expectRateLimitCheck(mock, testShareID)

	shareRows := sqlmock.NewRows([]string{
		"download_token_hash", "expires_at", "revoked_at", "revoked_reason", "access_count", "max_accesses",
	}).AddRow(hashB64, nil, nil, nil, 0, nil)
	mock.ExpectQuery(`SELECT download_token_hash, expires_at, revoked_at, revoked_reason, access_count, max_accesses`).
		WithArgs(testShareID).
		WillReturnRows(shareRows)

	// recordFailedAttempt after the bad token: INSERT OR IGNORE + tx + SELECT + UPDATE + commit.
	mock.ExpectExec(`INSERT OR IGNORE INTO share_access_attempts`).
		WithArgs(testShareID, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 0))
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT failed_count FROM share_access_attempts`).
		WithArgs(testShareID, sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"failed_count"}).AddRow(0))
	mock.ExpectExec(`UPDATE share_access_attempts`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := IssueShareDownloadTicket(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
}

func TestIssueShareDownloadTicket_ShareNotFound(t *testing.T) {
	tokenB64, _ := ticketTokenAndHash(t)
	reqBody, _ := json.Marshal(map[string]string{"download_token": tokenB64})
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/public/shares/"+testShareID+"/ticket", bytes.NewReader(reqBody))
	c.SetParamNames("id")
	c.SetParamValues(testShareID)

	expectRateLimitCheck(mock, testShareID)

	mock.ExpectQuery(`SELECT download_token_hash, expires_at, revoked_at, revoked_reason, access_count, max_accesses`).
		WithArgs(testShareID).
		WillReturnError(sql.ErrNoRows)

	err := IssueShareDownloadTicket(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
}

func TestIssueShareDownloadTicket_MissingToken(t *testing.T) {
	reqBody, _ := json.Marshal(map[string]string{"download_token": ""})
	c, _, mock, _ := setupTestEnv(t, http.MethodPost, "/api/public/shares/"+testShareID+"/ticket", bytes.NewReader(reqBody))
	c.SetParamNames("id")
	c.SetParamValues(testShareID)

	// checkRateLimit runs before the body/token check; mock it so the handler
	// reaches the "Download token is required" 400 path.
	expectRateLimitCheck(mock, testShareID)

	err := IssueShareDownloadTicket(c)
	require.Error(t, err)
	httpErr, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
}
