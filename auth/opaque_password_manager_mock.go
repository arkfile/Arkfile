//go:build mock
// +build mock

package auth

import (
	"fmt"
	"sync"
	"time"
)

// MockOPAQUEPasswordManager implements OPAQUEPasswordManagerInterface for testing
type MockOPAQUEPasswordManager struct {
	records    map[string]*OPAQUEPasswordRecord
	nextID     int
	mutex      sync.RWMutex
	failureMap map[string]error // For testing error conditions
}

// NewMockOPAQUEPasswordManager creates a new mock password manager for testing
func NewMockOPAQUEPasswordManager() *MockOPAQUEPasswordManager {
	return &MockOPAQUEPasswordManager{
		records:    make(map[string]*OPAQUEPasswordRecord),
		nextID:     1,
		failureMap: make(map[string]error),
	}
}

// SetFailure configures the mock to fail specific operations for testing
func (mock *MockOPAQUEPasswordManager) SetFailure(operation string, err error) {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()
	mock.failureMap[operation] = err
}

// ClearFailures removes all configured failures
func (mock *MockOPAQUEPasswordManager) ClearFailures() {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()
	mock.failureMap = make(map[string]error)
}

// RegisterCustomFilePassword registers a custom password for a specific file (mock implementation)
func (mock *MockOPAQUEPasswordManager) RegisterCustomFilePassword(
	userEmail, fileID, password, keyLabel, passwordHint string) error {

	mock.mutex.Lock()
	defer mock.mutex.Unlock()

	// Check for configured failure
	if err, exists := mock.failureMap["RegisterCustomFilePassword"]; exists {
		return err
	}

	recordIdentifier := fmt.Sprintf("%s:file:%s", userEmail, fileID)

	// Use mock OPAQUE provider for registration
	provider := GetOPAQUEProvider()
	if !provider.IsAvailable() {
		return fmt.Errorf("OPAQUE provider not available")
	}

	// Get server keys from mock provider
	_, serverPrivateKey, err := provider.GetServerKeys()
	if err != nil {
		return fmt.Errorf("failed to get server keys: %w", err)
	}

	// Register with mock OPAQUE provider
	userRecord, exportKey, err := provider.RegisterUser([]byte(password), serverPrivateKey)
	if err != nil {
		return fmt.Errorf("OPAQUE registration failed: %w", err)
	}

	// Create mock encrypted hint
	var encryptedHint []byte
	if passwordHint != "" {
		// Mock encryption - just store the hint with a prefix for testing
		encryptedHint = []byte("mock-encrypted:" + passwordHint)
	}

	// Store in memory
	now := time.Now()
	record := &OPAQUEPasswordRecord{
		ID:                    mock.nextID,
		RecordType:            "file_custom",
		RecordIdentifier:      recordIdentifier,
		OPAQUEUserRecord:      userRecord,
		AssociatedFileID:      &fileID,
		AssociatedUserEmail:   &userEmail,
		KeyLabel:              &keyLabel,
		PasswordHintEncrypted: encryptedHint,
		CreatedAt:             now,
		LastUsedAt:            nil,
		IsActive:              true,
	}

	mock.records[recordIdentifier] = record
	mock.nextID++

	// Clean up export key
	for i := range exportKey {
		exportKey[i] = 0
	}

	return nil
}

// RegisterSharePassword registers a password for anonymous share access (mock implementation)
func (mock *MockOPAQUEPasswordManager) RegisterSharePassword(
	shareID, fileID, ownerEmail, password string) error {

	mock.mutex.Lock()
	defer mock.mutex.Unlock()

	// Check for configured failure
	if err, exists := mock.failureMap["RegisterSharePassword"]; exists {
		return err
	}

	recordIdentifier := fmt.Sprintf("share:%s", shareID)

	// Use mock OPAQUE provider
	provider := GetOPAQUEProvider()
	if !provider.IsAvailable() {
		return fmt.Errorf("OPAQUE provider not available")
	}

	// Get server keys from mock provider
	_, serverPrivateKey, err := provider.GetServerKeys()
	if err != nil {
		return fmt.Errorf("failed to get server keys: %w", err)
	}

	// Register with mock OPAQUE provider
	userRecord, exportKey, err := provider.RegisterUser([]byte(password), serverPrivateKey)
	if err != nil {
		return fmt.Errorf("OPAQUE registration failed: %w", err)
	}

	// Store in memory
	now := time.Now()
	record := &OPAQUEPasswordRecord{
		ID:                    mock.nextID,
		RecordType:            "share",
		RecordIdentifier:      recordIdentifier,
		OPAQUEUserRecord:      userRecord,
		AssociatedFileID:      &fileID,
		AssociatedUserEmail:   &ownerEmail,
		KeyLabel:              nil,
		PasswordHintEncrypted: nil,
		CreatedAt:             now,
		LastUsedAt:            nil,
		IsActive:              true,
	}

	mock.records[recordIdentifier] = record
	mock.nextID++

	// Clean up export key
	for i := range exportKey {
		exportKey[i] = 0
	}

	return nil
}

// AuthenticatePassword authenticates any password via OPAQUE and returns the export key (mock implementation)
func (mock *MockOPAQUEPasswordManager) AuthenticatePassword(
	recordIdentifier, password string) ([]byte, error) {

	mock.mutex.Lock()
	defer mock.mutex.Unlock()

	// Check for configured failure
	if err, exists := mock.failureMap["AuthenticatePassword"]; exists {
		return nil, err
	}

	// Find record
	record, exists := mock.records[recordIdentifier]
	if !exists || !record.IsActive {
		return nil, fmt.Errorf("password record not found")
	}

	// Use mock OPAQUE provider for authentication
	provider := GetOPAQUEProvider()
	if !provider.IsAvailable() {
		return nil, fmt.Errorf("OPAQUE provider not available")
	}

	// Authenticate with mock OPAQUE provider
	exportKey, err := provider.AuthenticateUser([]byte(password), record.OPAQUEUserRecord)
	if err != nil {
		return nil, fmt.Errorf("OPAQUE authentication failed: %w", err)
	}

	// Update last used timestamp
	now := time.Now()
	record.LastUsedAt = &now

	return exportKey, nil
}

// GetPasswordRecord retrieves a password record by identifier (mock implementation)
func (mock *MockOPAQUEPasswordManager) GetPasswordRecord(recordIdentifier string) (*OPAQUEPasswordRecord, error) {
	mock.mutex.RLock()
	defer mock.mutex.RUnlock()

	// Check for configured failure
	if err, exists := mock.failureMap["GetPasswordRecord"]; exists {
		return nil, err
	}

	record, exists := mock.records[recordIdentifier]
	if !exists || !record.IsActive {
		return nil, fmt.Errorf("record not found")
	}

	// Return a copy to prevent external modification
	recordCopy := *record
	return &recordCopy, nil
}

// GetFilePasswordRecords gets all password records for a specific file (mock implementation)
func (mock *MockOPAQUEPasswordManager) GetFilePasswordRecords(fileID string) ([]*OPAQUEPasswordRecord, error) {
	mock.mutex.RLock()
	defer mock.mutex.RUnlock()

	// Check for configured failure
	if err, exists := mock.failureMap["GetFilePasswordRecords"]; exists {
		return nil, err
	}

	var records []*OPAQUEPasswordRecord
	for _, record := range mock.records {
		if record.IsActive && record.AssociatedFileID != nil && *record.AssociatedFileID == fileID {
			// Return a copy to prevent external modification
			recordCopy := *record
			records = append(records, &recordCopy)
		}
	}

	return records, nil
}

// DeletePasswordRecord deactivates a password record (mock implementation)
func (mock *MockOPAQUEPasswordManager) DeletePasswordRecord(recordIdentifier string) error {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()

	// Check for configured failure
	if err, exists := mock.failureMap["DeletePasswordRecord"]; exists {
		return err
	}

	record, exists := mock.records[recordIdentifier]
	if !exists {
		return fmt.Errorf("record not found")
	}

	// Deactivate the record
	record.IsActive = false
	return nil
}

// GetPasswordHint decrypts and returns the password hint for a record (mock implementation)
func (mock *MockOPAQUEPasswordManager) GetPasswordHint(recordIdentifier string, exportKey []byte) (string, error) {
	mock.mutex.RLock()
	defer mock.mutex.RUnlock()

	// Check for configured failure
	if err, exists := mock.failureMap["GetPasswordHint"]; exists {
		return "", err
	}

	record, exists := mock.records[recordIdentifier]
	if !exists || !record.IsActive {
		return "", fmt.Errorf("record not found")
	}

	if len(record.PasswordHintEncrypted) == 0 {
		return "", nil // No hint available
	}

	// Mock decryption - just remove the mock prefix
	encryptedHint := string(record.PasswordHintEncrypted)
	if len(encryptedHint) > 15 && encryptedHint[:15] == "mock-encrypted:" {
		return encryptedHint[15:], nil
	}

	return "", fmt.Errorf("invalid encrypted hint format")
}

// GetRecordCount returns the number of records (for testing)
func (mock *MockOPAQUEPasswordManager) GetRecordCount() int {
	mock.mutex.RLock()
	defer mock.mutex.RUnlock()
	return len(mock.records)
}

// GetActiveRecordCount returns the number of active records (for testing)
func (mock *MockOPAQUEPasswordManager) GetActiveRecordCount() int {
	mock.mutex.RLock()
	defer mock.mutex.RUnlock()

	count := 0
	for _, record := range mock.records {
		if record.IsActive {
			count++
		}
	}
	return count
}

// Reset clears all records (for testing)
func (mock *MockOPAQUEPasswordManager) Reset() {
	mock.mutex.Lock()
	defer mock.mutex.Unlock()

	mock.records = make(map[string]*OPAQUEPasswordRecord)
	mock.nextID = 1
	mock.failureMap = make(map[string]error)
}
