package subbridge

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	TokenLifetime       = 15 * time.Minute
	SignatureMaxSkew    = 5 * time.Minute
	SignatureHeaderName = "Subscription-Bridge-Signature"
	ProtocolName        = "subscription-bridge"
	ProtocolVersion     = 1
	maxResponseBody     = 1 << 20
)

var bridgeHTTPClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type DerivedKeys struct {
	Token     Key
	Callback  Key
	Reconcile Key
}

type Key [32]byte

// DeriveKeys expands one deployment pairing root into purpose-specific keys.
func DeriveKeys(pairingRoot string) (DerivedKeys, error) {
	if len(pairingRoot) != 64 || !isLowerHex(pairingRoot) {
		return DerivedKeys{}, errors.New("subscription bridge pairing root must be exactly 64 lowercase hexadecimal characters")
	}
	root, err := hex.DecodeString(pairingRoot)
	if err != nil {
		return DerivedKeys{}, errors.New("invalid subscription bridge pairing root")
	}
	derive := func(info string) (Key, error) {
		reader := hkdf.New(sha256.New, root, []byte("subscription-bridge/v1"), []byte(info))
		var key Key
		if _, err := io.ReadFull(reader, key[:]); err != nil {
			return Key{}, err
		}
		return key, nil
	}
	token, err := derive("consumer-to-bridge/token")
	if err != nil {
		return DerivedKeys{}, err
	}
	callback, err := derive("bridge-to-consumer/callback")
	if err != nil {
		return DerivedKeys{}, err
	}
	reconcile, err := derive("consumer-to-bridge/reconcile")
	if err != nil {
		return DerivedKeys{}, err
	}
	return DerivedKeys{Token: token, Callback: callback, Reconcile: reconcile}, nil
}

type StartTokenPayload struct {
	CheckoutID string `json:"checkout_id"`
	PlanID     string `json:"plan_id"`
	ReturnURL  string `json:"return_url"`
	Iat        int64  `json:"iat"`
	Exp        int64  `json:"exp"`
}

type PortalTokenPayload struct {
	SubscriptionRef string `json:"subscription_ref"`
	ReturnURL       string `json:"return_url"`
	Iat             int64  `json:"iat"`
	Exp             int64  `json:"exp"`
}

type CallbackPayload struct {
	Protocol           string `json:"protocol"`
	Version            int    `json:"version"`
	EventID            string `json:"event_id"`
	EventType          string `json:"event_type"`
	CheckoutID         string `json:"checkout_id"`
	SubscriptionRef    string `json:"subscription_ref"`
	PlanID             string `json:"plan_id"`
	StateVersion       int64  `json:"state_version"`
	Status             string `json:"status"`
	CurrentPeriodStart string `json:"current_period_start"`
	CurrentPeriodEnd   string `json:"current_period_end"`
	CancelAtPeriodEnd  bool   `json:"cancel_at_period_end"`
	StateChangedAt     string `json:"state_changed_at"`
}

type SnapshotPayload struct {
	Protocol           string `json:"protocol"`
	Version            int    `json:"version"`
	CheckoutID         string `json:"checkout_id"`
	SubscriptionRef    string `json:"subscription_ref"`
	PlanID             string `json:"plan_id"`
	StateVersion       int64  `json:"state_version"`
	Status             string `json:"status"`
	CurrentPeriodStart string `json:"current_period_start"`
	CurrentPeriodEnd   string `json:"current_period_end"`
	CancelAtPeriodEnd  bool   `json:"cancel_at_period_end"`
	StateChangedAt     string `json:"state_changed_at"`
}

type SnapshotResponse struct {
	Payload SnapshotPayload
	Body    []byte
}

func SignStartToken(key Key, payload StartTokenPayload) (string, error) {
	if payload.CheckoutID == "" || payload.PlanID == "" {
		return "", errors.New("token missing checkout fields")
	}
	if err := validateSignedReturnURL(payload.ReturnURL); err != nil {
		return "", err
	}
	if err := validateTokenLifetime(payload.Iat, payload.Exp); err != nil {
		return "", err
	}
	return signToken(key, payload)
}

func SignPortalToken(key Key, payload PortalTokenPayload) (string, error) {
	if payload.SubscriptionRef == "" {
		return "", errors.New("token missing subscription_ref")
	}
	if err := validateSignedReturnURL(payload.ReturnURL); err != nil {
		return "", err
	}
	if err := validateTokenLifetime(payload.Iat, payload.Exp); err != nil {
		return "", err
	}
	return signToken(key, payload)
}

func signToken(key Key, payload interface{}) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write(body)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(body) + "." + hex.EncodeToString(sig), nil
}

func VerifyStartToken(key Key, token string) (*StartTokenPayload, error) {
	var payload StartTokenPayload
	_, err := verifyTokenAt(key, token, &payload,
		[]string{"checkout_id", "plan_id", "return_url", "iat", "exp"}, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if payload.CheckoutID == "" || payload.PlanID == "" {
		return nil, errors.New("token missing checkout fields")
	}
	if err := validateSignedReturnURL(payload.ReturnURL); err != nil {
		return nil, err
	}
	return &payload, nil
}

func VerifyPortalToken(key Key, token string) (*PortalTokenPayload, error) {
	var payload PortalTokenPayload
	_, err := verifyTokenAt(key, token, &payload,
		[]string{"subscription_ref", "return_url", "iat", "exp"}, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if payload.SubscriptionRef == "" {
		return nil, errors.New("token missing subscription_ref")
	}
	if err := validateSignedReturnURL(payload.ReturnURL); err != nil {
		return nil, err
	}
	return &payload, nil
}

func verifyTokenAt(key Key, token string, dest interface{}, fields []string, now time.Time) ([]byte, error) {
	if len(token) == 0 || len(token) > 8192 {
		return nil, errors.New("invalid token length")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode token payload: %w", err)
	}
	if base64.RawURLEncoding.EncodeToString(body) != parts[0] {
		return nil, errors.New("non-canonical token payload encoding")
	}
	sig, err := decodeLowerHex(parts[1], sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("decode token signature: %w", err)
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write(body)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errors.New("invalid token signature")
	}
	if err := decodeExactObject(body, dest, fields); err != nil {
		return nil, fmt.Errorf("parse token payload: %w", err)
	}
	type timeCarrier struct {
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}
	var carrier timeCarrier
	if err := json.Unmarshal(body, &carrier); err != nil {
		return nil, err
	}
	if err := validateTokenLifetime(carrier.Iat, carrier.Exp); err != nil {
		return nil, err
	}
	nowUnix := now.UTC().Unix()
	if carrier.Iat > nowUnix+int64(SignatureMaxSkew.Seconds()) {
		return nil, errors.New("token issued in the future")
	}
	if nowUnix > carrier.Exp+int64(SignatureMaxSkew.Seconds()) {
		return nil, errors.New("token expired")
	}
	return body, nil
}

func validateTokenLifetime(iat, exp int64) error {
	if iat < 0 || exp < 0 || exp <= iat || exp-iat > int64(TokenLifetime.Seconds()) {
		return errors.New("invalid token lifetime")
	}
	return nil
}

func validateSignedReturnURL(returnURL string) error {
	normalized, err := NormalizeReturnURL(returnURL)
	if err != nil {
		return err
	}
	if normalized != returnURL {
		return errors.New("return_url is not normalized")
	}
	return nil
}

func SignWebhook(key Key, body []byte) string {
	return signWebhookAt(key, body, time.Now().UTC().Unix())
}

func signWebhookAt(key Key, body []byte, timestamp int64) string {
	ts := strconv.FormatInt(timestamp, 10)
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func VerifyWebhookSignature(key Key, body []byte, header string) error {
	return verifyWebhookSignatureAt(key, body, header, time.Now().UTC())
}

func verifyWebhookSignatureAt(key Key, body []byte, header string, now time.Time) error {
	tsStr, sigHex, err := parseSignatureHeader(header)
	if err != nil {
		return err
	}
	if !isCanonicalUnixTimestamp(tsStr) {
		return errors.New("invalid signature timestamp")
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return errors.New("invalid signature timestamp")
	}
	nowUnix := now.UTC().Unix()
	if ts < nowUnix-int64(SignatureMaxSkew.Seconds()) || ts > nowUnix+int64(SignatureMaxSkew.Seconds()) {
		return errors.New("signature timestamp outside replay window")
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(tsStr + "."))
	mac.Write(body)
	expected, err := decodeLowerHex(sigHex, sha256.Size)
	if err != nil {
		return errors.New("invalid signature hex")
	}
	if !hmac.Equal(expected, mac.Sum(nil)) {
		return errors.New("invalid webhook signature")
	}
	return nil
}

func parseSignatureHeader(header string) (ts, sig string, err error) {
	parts := strings.Split(header, ",")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "t=") || !strings.HasPrefix(parts[1], "v1=") {
		return "", "", errors.New("invalid signature header")
	}
	ts = strings.TrimPrefix(parts[0], "t=")
	sig = strings.TrimPrefix(parts[1], "v1=")
	if ts == "" || sig == "" || strings.TrimSpace(ts) != ts || strings.TrimSpace(sig) != sig {
		return "", "", errors.New("invalid signature components")
	}
	return ts, sig, nil
}

func SignBridgeGET(key Key, method, path string) string {
	return signBridgeGETAt(key, method, path, time.Now().UTC().Unix())
}

func signBridgeGETAt(key Key, method, path string, timestamp int64) string {
	ts := strconv.FormatInt(timestamp, 10)
	base := method + "\n" + path + "\n" + ts
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(base))
	return "Subscription-Bridge-HMAC t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func VerifyBridgeGET(key Key, method, path, authHeader string) error {
	return verifyBridgeGETAt(key, method, path, authHeader, time.Now().UTC())
}

func verifyBridgeGETAt(key Key, method, path, authHeader string, now time.Time) error {
	tsStr, sigHex, err := parseBridgeHMACHeader(authHeader)
	if err != nil {
		return err
	}
	if !isCanonicalUnixTimestamp(tsStr) {
		return errors.New("invalid bridge auth timestamp")
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return errors.New("invalid auth timestamp")
	}
	nowUnix := now.UTC().Unix()
	if ts < nowUnix-int64(SignatureMaxSkew.Seconds()) || ts > nowUnix+int64(SignatureMaxSkew.Seconds()) {
		return errors.New("auth timestamp outside replay window")
	}
	base := method + "\n" + path + "\n" + tsStr
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(base))
	expected, err := decodeLowerHex(sigHex, sha256.Size)
	if err != nil {
		return errors.New("invalid auth hex")
	}
	if !hmac.Equal(expected, mac.Sum(nil)) {
		return errors.New("invalid bridge auth signature")
	}
	return nil
}

func parseBridgeHMACHeader(header string) (ts, sig string, err error) {
	const prefix = "Subscription-Bridge-HMAC "
	if !strings.HasPrefix(header, prefix) {
		return "", "", errors.New("invalid bridge auth scheme")
	}
	header = strings.TrimPrefix(header, prefix)
	parts := strings.Split(header, ",")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "t=") || !strings.HasPrefix(parts[1], "v1=") {
		return "", "", errors.New("invalid bridge auth header")
	}
	ts = strings.TrimPrefix(parts[0], "t=")
	sig = strings.TrimPrefix(parts[1], "v1=")
	if ts == "" || sig == "" || strings.TrimSpace(ts) != ts || strings.TrimSpace(sig) != sig {
		return "", "", errors.New("invalid bridge auth components")
	}
	return ts, sig, nil
}

func FetchSubscriptionSnapshot(bridgeURL string, key Key, subscriptionRef string) (*SnapshotResponse, error) {
	path := "/v1/subscriptions/" + url.PathEscape(subscriptionRef)
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(bridgeURL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", SignBridgeGET(key, "GET", path))

	resp, err := bridgeHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBody {
		return nil, errors.New("bridge response exceeds size limit")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("subscription not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bridge returned HTTP %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("bridge returned invalid content type")
	}
	var snapshot SnapshotPayload
	if err := DecodeSnapshot(body, &snapshot); err != nil {
		return nil, err
	}
	return &SnapshotResponse{Payload: snapshot, Body: append([]byte(nil), body...)}, nil
}

func DecodeCallback(body []byte, payload *CallbackPayload) error {
	return decodeExactObject(body, payload, []string{
		"protocol", "version", "event_id", "event_type", "checkout_id",
		"subscription_ref", "plan_id", "state_version", "status",
		"current_period_start", "current_period_end", "cancel_at_period_end",
		"state_changed_at",
	})
}

func DecodeSnapshot(body []byte, payload *SnapshotPayload) error {
	return decodeExactObject(body, payload, []string{
		"protocol", "version", "checkout_id", "subscription_ref", "plan_id",
		"state_version", "status", "current_period_start", "current_period_end",
		"cancel_at_period_end", "state_changed_at",
	})
}

func ParseUTCSecond(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Nanosecond() != 0 || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, errors.New("timestamp must use second-precision UTC RFC3339 with Z")
	}
	return parsed, nil
}

func NormalizeReturnURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("invalid return_url")
	}
	scheme := strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return "", errors.New("invalid return_url host")
	}
	isLoopback := hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"
	if scheme != "https" && !(scheme == "http" && isLoopback) {
		return "", errors.New("return_url must use HTTPS except on loopback")
	}
	port := parsed.Port()
	if scheme == "https" && port == "443" {
		port = ""
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	}
	parsed.Scheme = scheme
	parsed.Host = host
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String(), nil
}

func decodeExactObject(body []byte, dest interface{}, fields []string) error {
	allowed := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		allowed[field] = struct{}{}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("protocol payload must be a JSON object")
	}
	seen := make(map[string]struct{}, len(fields))
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return errors.New("invalid protocol object key")
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("invalid protocol object key")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate protocol field %q", key)
		}
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown protocol field %q", key)
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return fmt.Errorf("invalid protocol field %q", key)
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return errors.New("invalid protocol object")
	}
	if token, err = decoder.Token(); err != io.EOF {
		return errors.New("trailing protocol JSON")
	}
	for _, field := range fields {
		if _, ok := seen[field]; !ok {
			return fmt.Errorf("missing protocol field %q", field)
		}
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return err
	}
	return nil
}

func decodeLowerHex(value string, byteLength int) ([]byte, error) {
	if len(value) != byteLength*2 || !isLowerHex(value) {
		return nil, errors.New("hex value must be lowercase and have the required length")
	}
	return hex.DecodeString(value)
}

func isLowerHex(value string) bool {
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func isCanonicalUnixTimestamp(value string) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
