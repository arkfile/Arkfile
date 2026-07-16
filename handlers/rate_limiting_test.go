package handlers

import (
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPruneShareAccessAttemptsDeletesExpiredRows(t *testing.T) {
	_, _, mock, _ := setupTestEnv(t, http.MethodGet, "/api/share/test", nil)

	cutoff := time.Now().Add(-shareAccessAttemptRetention)
	mock.ExpectExec(`DELETE FROM share_access_attempts`).
		WithArgs(cutoff).
		WillReturnResult(sqlmock.NewResult(0, 3))

	rows, err := pruneShareAccessAttempts(cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(3), rows)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMaybePruneShareAccessAttemptsIsThrottled(t *testing.T) {
	_, _, mock, _ := setupTestEnv(t, http.MethodGet, "/api/share/test", nil)

	originalLastCleanup := lastShareAccessAttemptCleanupAt
	lastShareAccessAttemptCleanupAt = time.Now()
	t.Cleanup(func() { lastShareAccessAttemptCleanupAt = originalLastCleanup })

	maybePruneShareAccessAttempts(time.Now().Add(5 * time.Minute))
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestShareRateLimit_FourthFailureAppliesThirtySecondPenalty(t *testing.T) {
	penalty := calculateSharePenalty(4)
	assert.Equal(t, 30*time.Second, penalty)
}
