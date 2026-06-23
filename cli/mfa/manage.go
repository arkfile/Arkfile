package mfa

import (
	"fmt"
	"strings"
	"time"
)

// CredentialSummary is owner-visible MFA credential metadata.
type CredentialSummary struct {
	CredentialID string
	MethodType   string
	CreatedAt    time.Time
	LastUsed     *time.Time
	Label        string
}

// AdminCredentialSummary is admin-visible MFA metadata (no user labels).
type AdminCredentialSummary struct {
	CredentialID string
	MethodType   string
	CreatedAt    time.Time
}

func parseCredentialSummaries(data map[string]interface{}) []CredentialSummary {
	raw, ok := data["credentials"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]CredentialSummary, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		summary := CredentialSummary{
			CredentialID: strings.TrimSpace(fmt.Sprint(entry["credential_id"])),
			MethodType:   strings.TrimSpace(fmt.Sprint(entry["method_type"])),
		}
		if label, _ := entry["label"].(string); label != "" {
			summary.Label = label
		}
		if created, _ := entry["created_at"].(string); created != "" {
			if t, err := time.Parse(time.RFC3339, created); err == nil {
				summary.CreatedAt = t
			}
		}
		if last, _ := entry["last_used"].(string); last != "" {
			if t, err := time.Parse(time.RFC3339, last); err == nil {
				summary.LastUsed = &t
			}
		}
		out = append(out, summary)
	}
	return out
}

func parseAdminCredentialSummaries(data map[string]interface{}) []AdminCredentialSummary {
	raw, ok := data["credentials"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]AdminCredentialSummary, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		summary := AdminCredentialSummary{
			CredentialID: strings.TrimSpace(fmt.Sprint(entry["credential_id"])),
			MethodType:   strings.TrimSpace(fmt.Sprint(entry["method_type"])),
		}
		if created, _ := entry["created_at"].(string); created != "" {
			if t, err := time.Parse(time.RFC3339, created); err == nil {
				summary.CreatedAt = t
			}
		}
		out = append(out, summary)
	}
	return out
}

// ListCredentials returns the authenticated user's enrolled MFA methods.
func ListCredentials(req Requester, token string) ([]CredentialSummary, error) {
	resp, err := req("GET", "/api/mfa/credentials", nil, token)
	if err != nil {
		return nil, fmt.Errorf("failed to list MFA credentials: %w", err)
	}
	return parseCredentialSummaries(resp.Data), nil
}

// ListUserCredentialsAdmin returns MFA metadata for a user (admin API; no labels).
func ListUserCredentialsAdmin(req Requester, token, username string) ([]AdminCredentialSummary, error) {
	if strings.TrimSpace(username) == "" {
		return nil, fmt.Errorf("username is required")
	}
	path := fmt.Sprintf("/api/admin/users/%s/mfa-credentials", username)
	resp, err := req("GET", path, nil, token)
	if err != nil {
		return nil, fmt.Errorf("failed to list MFA credentials for %s: %w", username, err)
	}
	return parseAdminCredentialSummaries(resp.Data), nil
}

// RemoveCredential deletes one enrolled MFA method for the authenticated user.
func RemoveCredential(req Requester, token, credentialID string) (requiresSetup bool, forceLogout bool, err error) {
	if strings.TrimSpace(credentialID) == "" {
		return false, false, fmt.Errorf("credential id is required")
	}
	path := fmt.Sprintf("/api/mfa/credentials/%s", credentialID)
	resp, err := req("DELETE", path, nil, token)
	if err != nil {
		return false, false, fmt.Errorf("failed to remove MFA credential: %w", err)
	}
	if resp.Data != nil {
		if v, ok := resp.Data["requires_mfa_setup"].(bool); ok {
			requiresSetup = v
		}
		if v, ok := resp.Data["force_logout"].(bool); ok {
			forceLogout = v
		}
	}
	return requiresSetup, forceLogout, nil
}

// RegenerateBackupCodes replaces all backup codes for the authenticated user.
func RegenerateBackupCodes(req Requester, token string) ([]string, error) {
	resp, err := req("POST", "/api/mfa/backup-codes/regenerate", map[string]interface{}{}, token)
	if err != nil {
		return nil, fmt.Errorf("failed to regenerate backup codes: %w", err)
	}
	return stringSlice(resp.Data["backup_codes"]), nil
}

// UpdateCredentialLabel sets the user-private label on a security key credential.
func UpdateCredentialLabel(req Requester, token, credentialID, label string) error {
	if strings.TrimSpace(credentialID) == "" {
		return fmt.Errorf("credential id is required")
	}
	path := fmt.Sprintf("/api/mfa/credentials/%s/label", credentialID)
	_, err := req("PATCH", path, map[string]string{"label": label}, token)
	if err != nil {
		return fmt.Errorf("failed to update security key label: %w", err)
	}
	return nil
}

func methodTypeDisplay(methodType, label string) string {
	switch strings.TrimSpace(methodType) {
	case string(MethodTOTP):
		return "Authenticator app (TOTP)"
	case string(MethodWebAuthn):
		if label != "" {
			return "Security key: " + label
		}
		return "Security key"
	default:
		return methodType
	}
}

// PrintCredentials prints owner-visible credential rows.
func PrintCredentials(creds []CredentialSummary) {
	if len(creds) == 0 {
		fmt.Println("No enrolled second factors.")
		return
	}
	fmt.Printf("Enrolled second factors (%d):\n", len(creds))
	for i, cred := range creds {
		fmt.Printf("  [%d] %s\n", i+1, methodTypeDisplay(cred.MethodType, cred.Label))
		fmt.Printf("      credential_id: %s\n", cred.CredentialID)
		if !cred.CreatedAt.IsZero() {
			fmt.Printf("      enrolled:    %s\n", cred.CreatedAt.Format(time.RFC3339))
		}
		if cred.LastUsed != nil {
			fmt.Printf("      last used:   %s\n", cred.LastUsed.Format(time.RFC3339))
		}
	}
}

// PrintAdminCredentials prints admin-visible credential rows (no user labels).
func PrintAdminCredentials(username string, creds []AdminCredentialSummary) {
	if len(creds) == 0 {
		fmt.Printf("User %s has no completed MFA credentials.\n", username)
		return
	}
	fmt.Printf("MFA credentials for %s (%d):\n", username, len(creds))
	for i, cred := range creds {
		fmt.Printf("  [%d] %s\n", i+1, methodTypeDisplay(cred.MethodType, ""))
		fmt.Printf("      credential_id: %s\n", cred.CredentialID)
		if !cred.CreatedAt.IsZero() {
			fmt.Printf("      enrolled:    %s\n", cred.CreatedAt.Format(time.RFC3339))
		}
	}
}
