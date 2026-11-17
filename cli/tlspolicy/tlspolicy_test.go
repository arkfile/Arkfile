package tlspolicy

import "testing"

func TestRequireLoopbackForInsecure(t *testing.T) {
	allowed := []string{
		"https://localhost:8443",
		"https://LOCALHOST",
		"https://127.0.0.1:8443",
		"https://127.10.0.5",
		"https://[::1]:8443",
	}
	for _, u := range allowed {
		if err := RequireLoopbackForInsecure(u); err != nil {
			t.Errorf("%s: unexpected error: %v", u, err)
		}
	}

	rejected := []string{
		"https://arkfile.net",
		"https://192.168.1.10:8443",
		"https://localhost.evil.example",
		"https://[2001:db8::1]",
		"",
	}
	for _, u := range rejected {
		if err := RequireLoopbackForInsecure(u); err == nil {
			t.Errorf("%s: expected rejection", u)
		}
	}
}
