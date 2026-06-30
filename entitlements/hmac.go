package entitlements

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	TokenLifetime       = 15 * time.Minute
	SignatureMaxSkew    = 5 * time.Minute
	SignatureHeaderName = "Entitlement-Bridge-Signature"
)

type StartTokenPayload struct {
	CheckoutID string `json:"checkout_id"`
	PlanID     string `json:"plan_id"`
	ReturnURL  string `json:"return_url"`
	Exp        int64  `json:"exp"`
}

type PortalTokenPayload struct {
	EntitlementRef string `json:"entitlement_ref"`
	ReturnURL      string `json:"return_url"`
	Exp            int64  `json:"exp"`
}

type CallbackPayload struct {
	Protocol           string `json:"protocol"`
	Version            int    `json:"version"`
	EventID            string `json:"event_id"`
	EventType          string `json:"event_type"`
	CheckoutID         string `json:"checkout_id"`
	EntitlementRef     string `json:"entitlement_ref"`
	PlanID             string `json:"plan_id"`
	Status             string `json:"status"`
	CurrentPeriodStart string `json:"current_period_start"`
	CurrentPeriodEnd   string `json:"current_period_end"`
	CancelAtPeriodEnd  bool   `json:"cancel_at_period_end"`
	ProcessorFamily    string `json:"processor_family,omitempty"`
	OccurredAt         string `json:"occurred_at"`
}

func SignToken(secret string, payload interface{}) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(body) + "." + hex.EncodeToString(sig), nil
}

func VerifyToken(secret, token string, dest interface{}) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errors.New("invalid token format")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("decode token payload: %w", err)
	}
	sig, err := hex.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode token signature: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return errors.New("invalid token signature")
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("parse token payload: %w", err)
	}
	type expCarrier struct {
		Exp int64 `json:"exp"`
	}
	var carrier expCarrier
	if err := json.Unmarshal(body, &carrier); err != nil {
		return err
	}
	if carrier.Exp == 0 {
		return errors.New("token missing exp")
	}
	now := time.Now().UTC().Unix()
	if now > carrier.Exp+int64(SignatureMaxSkew.Seconds()) {
		return errors.New("token expired")
	}
	return nil
}

func SignWebhook(secret string, body []byte) string {
	ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func VerifyWebhookSignature(secret string, body []byte, header string) error {
	tsStr, sigHex, err := parseSignatureHeader(header)
	if err != nil {
		return err
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return errors.New("invalid signature timestamp")
	}
	now := time.Now().UTC().Unix()
	if ts < now-int64(SignatureMaxSkew.Seconds()) || ts > now+int64(SignatureMaxSkew.Seconds()) {
		return errors.New("signature timestamp outside replay window")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tsStr + "."))
	mac.Write(body)
	expected, err := hex.DecodeString(sigHex)
	if err != nil {
		return errors.New("invalid signature hex")
	}
	if !hmac.Equal(expected, mac.Sum(nil)) {
		return errors.New("invalid webhook signature")
	}
	return nil
}

func parseSignatureHeader(header string) (ts, sig string, err error) {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "t=") {
			ts = strings.TrimPrefix(part, "t=")
		}
		if strings.HasPrefix(part, "v1=") {
			sig = strings.TrimPrefix(part, "v1=")
		}
	}
	if ts == "" || sig == "" {
		return "", "", errors.New("missing signature components")
	}
	return ts, sig, nil
}

func SignBridgeGET(secret, method, path string) string {
	ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	base := method + "\n" + path + "\n" + ts
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(base))
	return "Bridge-HMAC t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func VerifyBridgeGET(secret, method, path, authHeader string) error {
	tsStr, sigHex, err := parseBridgeHMACHeader(authHeader)
	if err != nil {
		return err
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return errors.New("invalid auth timestamp")
	}
	now := time.Now().UTC().Unix()
	if ts < now-int64(SignatureMaxSkew.Seconds()) || ts > now+int64(SignatureMaxSkew.Seconds()) {
		return errors.New("auth timestamp outside replay window")
	}
	base := method + "\n" + path + "\n" + tsStr
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(base))
	expected, err := hex.DecodeString(sigHex)
	if err != nil {
		return errors.New("invalid auth hex")
	}
	if !hmac.Equal(expected, mac.Sum(nil)) {
		return errors.New("invalid bridge auth signature")
	}
	return nil
}

func parseBridgeHMACHeader(header string) (ts, sig string, err error) {
	header = strings.TrimPrefix(strings.TrimSpace(header), "Bridge-HMAC")
	header = strings.TrimSpace(header)
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "t=") {
			ts = strings.TrimPrefix(part, "t=")
		}
		if strings.HasPrefix(part, "v1=") {
			sig = strings.TrimPrefix(part, "v1=")
		}
	}
	if ts == "" || sig == "" {
		return "", "", errors.New("missing bridge auth components")
	}
	return ts, sig, nil
}

func FetchEntitlementSnapshot(bridgeURL, secret, entitlementRef string) (*CallbackPayload, error) {
	path := "/v1/entitlements/" + entitlementRef
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(bridgeURL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", SignBridgeGET(secret, "GET", path))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("entitlement not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bridge returned %d: %s", resp.StatusCode, string(body))
	}
	var snap CallbackPayload
	if err := json.Unmarshal(body, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}
