// Package tlspolicy holds TLS rules shared by the Arkfile CLI tools.
package tlspolicy

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// RequireLoopbackForInsecure returns an error unless serverURL names a
// loopback host. Skipping certificate verification against any other host
// lets a network attacker take the session tokens and MFA codes in transit.
func RequireLoopbackForInsecure(serverURL string) error {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("--tls-insecure: invalid server URL: %w", err)
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("--tls-insecure is only allowed for localhost or loopback addresses, not %q; install the server's certificate as trusted instead", host)
}
