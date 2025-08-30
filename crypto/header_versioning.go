// Protocol Header Versioning and Negotiation System for Arkfile
// This module handles version negotiation for future cryptographic transitions

package crypto

import (
	"fmt"
)

// Protocol version constants
const (
	AuthProtoVersionOPAQUE   = 0x01 // Current OPAQUE protocol
	AuthProtoVersionOPAQUEPQ = 0x02 // Future post-quantum OPAQUE protocol
	VersionReserved          = 0xFF // Reserved for future use
)

// Protocol version names for human-readable output
var VersionNames = map[byte]string{
	AuthProtoVersionOPAQUE:   "OPAQUE-v1",
	AuthProtoVersionOPAQUEPQ: "OPAQUE-PQ-v1",
	VersionReserved:          "Reserved",
}

// File encryption header versions (separate from authentication protocol)
const (
	FileEncryptionV4 = 0x04 // Current multi-key encryption format
	FileEncryptionV5 = 0x05 // Enhanced multi-key encryption format
)

// ProtocolNegotiator handles version negotiation between client and server
type ProtocolNegotiator struct {
	SupportedVersions []byte
	PreferredVersion  byte
	CurrentVersion    byte
}

// CapabilityFlags represent client/server capabilities
type CapabilityFlags struct {
	SupportsOPAQUE      bool
	SupportsOPAQUEPQ    bool
	SupportsFileV4      bool
	SupportsFileV5      bool
	RequiresPostQuantum bool
}

// NewProtocolNegotiator creates a new protocol negotiator
func NewProtocolNegotiator() *ProtocolNegotiator {
	return &ProtocolNegotiator{
		SupportedVersions: []byte{AuthProtoVersionOPAQUE}, // Currently only OPAQUE-v1
		PreferredVersion:  AuthProtoVersionOPAQUE,
		CurrentVersion:    AuthProtoVersionOPAQUE,
	}
}

// NegotiateVersion selects the best mutually supported version
func (pn *ProtocolNegotiator) NegotiateVersion(clientVersions []byte) (byte, error) {
	if len(clientVersions) == 0 {
		return 0, fmt.Errorf("client provided no supported versions")
	}

	// Find the highest mutually supported version
	for _, serverVersion := range pn.SupportedVersions {
		for _, clientVersion := range clientVersions {
			if serverVersion == clientVersion {
				// Prefer post-quantum if both support it
				if serverVersion == AuthProtoVersionOPAQUEPQ {
					return AuthProtoVersionOPAQUEPQ, nil
				}
				// Fall back to current stable version
				if serverVersion == AuthProtoVersionOPAQUE {
					return AuthProtoVersionOPAQUE, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("no mutually supported protocol versions")
}

// AddPostQuantumSupport enables post-quantum protocol support
func (pn *ProtocolNegotiator) AddPostQuantumSupport() {
	// Check if already supported
	for _, version := range pn.SupportedVersions {
		if version == AuthProtoVersionOPAQUEPQ {
			return // Already supported
		}
	}

	// Add post-quantum support while maintaining backward compatibility
	pn.SupportedVersions = append(pn.SupportedVersions, AuthProtoVersionOPAQUEPQ)
	pn.PreferredVersion = AuthProtoVersionOPAQUEPQ
}

// RemovePostQuantumSupport disables post-quantum protocol support
func (pn *ProtocolNegotiator) RemovePostQuantumSupport() {
	newVersions := make([]byte, 0, len(pn.SupportedVersions))
	for _, version := range pn.SupportedVersions {
		if version != AuthProtoVersionOPAQUEPQ {
			newVersions = append(newVersions, version)
		}
	}
	pn.SupportedVersions = newVersions
	pn.PreferredVersion = AuthProtoVersionOPAQUE
}

// GetCapabilities returns current protocol capabilities
func (pn *ProtocolNegotiator) GetCapabilities() CapabilityFlags {
	caps := CapabilityFlags{
		SupportsFileV4: true, // Always support current file encryption
		SupportsFileV5: true, // Always support enhanced file encryption
	}

	for _, version := range pn.SupportedVersions {
		switch version {
		case AuthProtoVersionOPAQUE:
			caps.SupportsOPAQUE = true
		case AuthProtoVersionOPAQUEPQ:
			caps.SupportsOPAQUEPQ = true
		}
	}

	return caps
}

// IsVersionSupported checks if a specific version is supported
func (pn *ProtocolNegotiator) IsVersionSupported(version byte) bool {
	for _, supportedVersion := range pn.SupportedVersions {
		if supportedVersion == version {
			return true
		}
	}
	return false
}

// GetVersionName returns human-readable name for version
func GetVersionName(version byte) string {
	if name, exists := VersionNames[version]; exists {
		return name
	}
	return fmt.Sprintf("Unknown-0x%02x", version)
}

// ValidationResult represents protocol validation outcome
type ValidationResult struct {
	Valid        bool
	Version      byte
	ErrorMessage string
}

// ValidateProtocolHeader validates incoming protocol headers
func (pn *ProtocolNegotiator) ValidateProtocolHeader(header []byte) ValidationResult {
	if len(header) < 1 {
		return ValidationResult{
			Valid:        false,
			ErrorMessage: "protocol header too short",
		}
	}

	version := header[0]

	if !pn.IsVersionSupported(version) {
		return ValidationResult{
			Valid:        false,
			Version:      version,
			ErrorMessage: fmt.Sprintf("unsupported protocol version: %s", GetVersionName(version)),
		}
	}

	return ValidationResult{
		Valid:   true,
		Version: version,
	}
}

// CreateProtocolHeader creates protocol header for outgoing messages
func (pn *ProtocolNegotiator) CreateProtocolHeader(version byte) ([]byte, error) {
	if !pn.IsVersionSupported(version) {
		return nil, fmt.Errorf("cannot create header for unsupported version: %s", GetVersionName(version))
	}

	// Simple header with version byte
	// Future versions may include additional capability flags
	header := []byte{version}

	return header, nil
}

// MigrationHelper assists with protocol version migrations
type MigrationHelper struct {
	negotiator *ProtocolNegotiator
}

// NewMigrationHelper creates a new migration helper
func NewMigrationHelper(negotiator *ProtocolNegotiator) *MigrationHelper {
	return &MigrationHelper{
		negotiator: negotiator,
	}
}

// PrepareForPostQuantumMigration configures system for PQ transition
func (mh *MigrationHelper) PrepareForPostQuantumMigration() error {
	// Validate current setup supports migration
	caps := mh.negotiator.GetCapabilities()
	if !caps.SupportsOPAQUE {
		return fmt.Errorf("current OPAQUE support required for migration")
	}

	// Enable dual protocol support
	mh.negotiator.AddPostQuantumSupport()

	return nil
}

// CompletePostQuantumMigration finalizes PQ transition
func (mh *MigrationHelper) CompletePostQuantumMigration() error {
	// Validate post-quantum support is active
	if !mh.negotiator.IsVersionSupported(AuthProtoVersionOPAQUEPQ) {
		return fmt.Errorf("post-quantum support not enabled")
	}

	// Optionally remove legacy OPAQUE support (not recommended initially)
	// This would be done only after all clients have migrated

	return nil
}

// RollbackPostQuantumMigration reverses PQ migration
func (mh *MigrationHelper) RollbackPostQuantumMigration() error {
	// Remove post-quantum support
	mh.negotiator.RemovePostQuantumSupport()

	// Ensure OPAQUE-v1 support is maintained
	if !mh.negotiator.IsVersionSupported(AuthProtoVersionOPAQUE) {
		return fmt.Errorf("cannot rollback - OPAQUE-v1 support missing")
	}

	return nil
}

// GetMigrationStatus returns current migration status
func (mh *MigrationHelper) GetMigrationStatus() map[string]interface{} {
	caps := mh.negotiator.GetCapabilities()

	status := map[string]interface{}{
		"supported_versions": mh.negotiator.SupportedVersions,
		"preferred_version":  GetVersionName(mh.negotiator.PreferredVersion),
		"current_version":    GetVersionName(mh.negotiator.CurrentVersion),
		"capabilities": map[string]bool{
			"opaque":             caps.SupportsOPAQUE,
			"opaque_pq":          caps.SupportsOPAQUEPQ,
			"file_encryption_v4": caps.SupportsFileV4,
			"file_encryption_v5": caps.SupportsFileV5,
		},
		"migration_ready": caps.SupportsOPAQUE && caps.SupportsOPAQUEPQ,
	}

	return status
}

// ClientCompatibilityChecker helps determine client compatibility
type ClientCompatibilityChecker struct {
	serverNegotiator *ProtocolNegotiator
}

// NewClientCompatibilityChecker creates a new compatibility checker
func NewClientCompatibilityChecker(negotiator *ProtocolNegotiator) *ClientCompatibilityChecker {
	return &ClientCompatibilityChecker{
		serverNegotiator: negotiator,
	}
}

// CheckCompatibility verifies if client can connect
func (ccc *ClientCompatibilityChecker) CheckCompatibility(clientVersions []byte, clientCaps CapabilityFlags) (bool, string) {
	// Check version compatibility
	negotiatedVersion, err := ccc.serverNegotiator.NegotiateVersion(clientVersions)
	if err != nil {
		return false, fmt.Sprintf("version negotiation failed: %v", err)
	}

	// Check specific capability requirements
	serverCaps := ccc.serverNegotiator.GetCapabilities()

	// If client requires post-quantum but server doesn't support it
	if clientCaps.RequiresPostQuantum && !serverCaps.SupportsOPAQUEPQ {
		return false, "client requires post-quantum security but server doesn't support it"
	}

	// If negotiated version is post-quantum but client doesn't support it
	if negotiatedVersion == AuthProtoVersionOPAQUEPQ && !clientCaps.SupportsOPAQUEPQ {
		return false, "server prefers post-quantum but client doesn't support it"
	}

	return true, fmt.Sprintf("compatible using %s", GetVersionName(negotiatedVersion))
}

// FormatVersionList returns formatted string of supported versions
func FormatVersionList(versions []byte) string {
	if len(versions) == 0 {
		return "none"
	}

	versionNames := make([]string, len(versions))
	for i, version := range versions {
		versionNames[i] = GetVersionName(version)
	}

	result := versionNames[0]
	for i := 1; i < len(versionNames); i++ {
		if i == len(versionNames)-1 {
			result += " and " + versionNames[i]
		} else {
			result += ", " + versionNames[i]
		}
	}

	return result
}
