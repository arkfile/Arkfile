package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/arkfile/Arkfile/cli/mfa"
)

// HTTPClient wraps http.Client with additional functionality.
type HTTPClient struct {
	client  *http.Client
	baseURL string
	verbose bool
}

// Response represents a generic API response.
type Response struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data"`
}

func newHTTPClient(baseURL string, tlsInsecure bool, tlsMinVersion uint16, verbose bool) *HTTPClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: tlsInsecure,
			MinVersion:         tlsMinVersion,
		},
	}

	return &HTTPClient{
		client:  &http.Client{Transport: tr, Timeout: 30 * time.Second},
		baseURL: strings.TrimSuffix(baseURL, "/"),
		verbose: verbose,
	}
}

func (c *HTTPClient) makeRequest(method, endpoint string, payload interface{}, token string) (*Response, error) {
	url := c.baseURL + endpoint

	var body io.Reader
	if payload != nil {
		jsonData, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		body = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	if c.verbose {
		logVerbose("Making %s request to %s", method, url)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if c.verbose {
		logVerbose("Response status: %d", resp.StatusCode)
		logVerbose("Response body: %s", string(responseData))
	}

	var apiResp Response
	if err := json.Unmarshal(responseData, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return &apiResp, fmt.Errorf("HTTP %d: %s", resp.StatusCode, apiResp.Message)
	}

	return &apiResp, nil
}

func (c *HTTPClient) fetchOpaqueServerID() (string, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/config/opaque", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d fetching OPAQUE server identity", resp.StatusCode)
	}

	var parsed struct {
		ServerID string `json:"server_id"`
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read OPAQUE config: %w", err)
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", fmt.Errorf("failed to parse OPAQUE config: %w", err)
	}
	if parsed.ServerID == "" {
		return "", fmt.Errorf("server returned empty OPAQUE server identity")
	}
	return parsed.ServerID, nil
}

func adminMFARequester(client *HTTPClient) mfa.Requester {
	return func(method, endpoint string, payload interface{}, token string) (*mfa.APIResponse, error) {
		resp, err := client.makeRequest(method, endpoint, payload, token)
		if err != nil {
			return nil, err
		}
		out := &mfa.APIResponse{
			Success: resp.Success,
			Message: resp.Message,
			Data:    resp.Data,
		}
		if resp.Data != nil {
			if t, ok := resp.Data["token"].(string); ok {
				out.Token = t
			}
			if rt, ok := resp.Data["refresh_token"].(string); ok {
				out.RefreshToken = rt
			}
			if tt, ok := resp.Data["temp_token"].(string); ok {
				out.TempToken = tt
			}
			if exp, ok := resp.Data["expires_at"].(string); ok {
				if parsed, err := time.Parse(time.RFC3339, exp); err == nil {
					out.ExpiresAt = parsed
				}
			}
		}
		return out, nil
	}
}
