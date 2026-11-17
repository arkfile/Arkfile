package jsonutil

import (
	"strings"
	"testing"
)

func TestRedactSensitiveJSON(t *testing.T) {
	body := []byte(`{"success":true,"data":{"token":"jwt-access","refresh_token":"jwt-refresh","username":"alice","mfa":{"secret":"BASE32SECRET","backup_codes":["AAAA","BBBB"]}},"items":[{"Temp_Token":"tmp"}]}`)
	got := RedactSensitiveJSON(body)

	for _, leaked := range []string{"jwt-access", "jwt-refresh", "BASE32SECRET", "AAAA", "BBBB", "tmp"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("redacted output still contains %q: %s", leaked, got)
		}
	}
	if !strings.Contains(got, `"username":"alice"`) {
		t.Fatalf("non-sensitive field was removed: %s", got)
	}
	if !strings.Contains(got, `"success":true`) {
		t.Fatalf("non-sensitive field was removed: %s", got)
	}
}

func TestRedactSensitiveJSONNonJSON(t *testing.T) {
	got := RedactSensitiveJSON([]byte("token=abc"))
	if strings.Contains(got, "abc") {
		t.Fatalf("non-JSON body was echoed: %s", got)
	}
	if got != "<9 bytes, not JSON>" {
		t.Fatalf("unexpected summary: %s", got)
	}
}
