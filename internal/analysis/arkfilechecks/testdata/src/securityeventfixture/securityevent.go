package securityeventfixture

import "github.com/arkfile/Arkfile/logging"

func rejected() {
	_ = logging.SecurityEvent{ // want "construct security events through approved logging helpers"
		Details: map[string]interface{}{"operation": "direct"},
	}
	query := "INSERT INTO security_events (details) VALUES (?)" // want "persist security events through approved logging helpers"
	_ = query
}

func accepted() {
	_ = logging.LogSecurityEvent("event", nil, nil, nil, map[string]interface{}{
		"operation": "approved",
	})
}
