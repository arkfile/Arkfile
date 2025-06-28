// Device Capability Negotiation Framework for Arkfile
// This module handles privacy-first device capability detection and parameter negotiation

package crypto

import (
	"fmt"
	"runtime"
	"time"
)

// DeviceProfile represents detected device capabilities
type DeviceProfile struct {
	DeviceClass    DeviceClass
	MemoryProfile  MemoryProfile
	ComputeProfile ComputeProfile
	BatteryProfile BatteryProfile
	NetworkProfile NetworkProfile
	Detected       time.Time
	UserConsent    bool
}

// DeviceClass represents broad device categories
type DeviceClass int

const (
	DeviceUnknown DeviceClass = iota
	DeviceMobile
	DeviceTablet
	DeviceDesktop
	DeviceServer
	DeviceEmbedded
)

// String returns string representation of device class
func (dc DeviceClass) String() string {
	switch dc {
	case DeviceMobile:
		return "mobile"
	case DeviceTablet:
		return "tablet"
	case DeviceDesktop:
		return "desktop"
	case DeviceServer:
		return "server"
	case DeviceEmbedded:
		return "embedded"
	default:
		return "unknown"
	}
}

// MemoryProfile represents available memory characteristics
type MemoryProfile struct {
	AvailableGB   float64
	RecommendedMB int
	MaxSafeMB     int
	ProfileName   string
	SupportsSwap  bool
}

// ComputeProfile represents processing capabilities
type ComputeProfile struct {
	LogicalCores       int
	RecommendedThreads int
	MaxThreads         int
	ProfileName        string
	HasHardwareAES     bool
}

// BatteryProfile represents power constraints
type BatteryProfile struct {
	HasBattery     bool
	EstimatedLevel float64 // 0.0 to 1.0, -1 if unknown
	PowerMode      PowerMode
	ProfileName    string
}

// PowerMode represents current power management mode
type PowerMode int

const (
	PowerModeUnknown PowerMode = iota
	PowerModeMaxPerformance
	PowerModeBalanced
	PowerModePowerSaver
	PowerModePluggedIn
)

// String returns string representation of power mode
func (pm PowerMode) String() string {
	switch pm {
	case PowerModeMaxPerformance:
		return "max_performance"
	case PowerModeBalanced:
		return "balanced"
	case PowerModePowerSaver:
		return "power_saver"
	case PowerModePluggedIn:
		return "plugged_in"
	default:
		return "unknown"
	}
}

// NetworkProfile represents network characteristics
type NetworkProfile struct {
	ConnectionType     string
	EstimatedBandwidth int // Mbps, -1 if unknown
	Latency            int // ms, -1 if unknown
	IsMetered          bool
	ProfileName        string
}

// CapabilityNegotiator handles device capability detection and parameter selection
type CapabilityNegotiator struct {
	privacyFirst   bool
	userConsent    bool
	staticFallback DeviceProfile
}

// NewCapabilityNegotiator creates a new capability negotiator
func NewCapabilityNegotiator(privacyFirst bool) *CapabilityNegotiator {
	return &CapabilityNegotiator{
		privacyFirst: privacyFirst,
		userConsent:  false,
		staticFallback: DeviceProfile{
			DeviceClass: DeviceDesktop, // Conservative default
			MemoryProfile: MemoryProfile{
				AvailableGB:   4.0,
				RecommendedMB: 64,
				MaxSafeMB:     128,
				ProfileName:   "conservative_default",
				SupportsSwap:  true,
			},
			ComputeProfile: ComputeProfile{
				LogicalCores:       4,
				RecommendedThreads: 2,
				MaxThreads:         4,
				ProfileName:        "conservative_default",
				HasHardwareAES:     true, // Assume modern hardware
			},
			BatteryProfile: BatteryProfile{
				HasBattery:     false,
				EstimatedLevel: -1,
				PowerMode:      PowerModeBalanced,
				ProfileName:    "conservative_default",
			},
			NetworkProfile: NetworkProfile{
				ConnectionType:     "unknown",
				EstimatedBandwidth: -1,
				Latency:            -1,
				IsMetered:          false,
				ProfileName:        "conservative_default",
			},
			Detected:    time.Now(),
			UserConsent: false,
		},
	}
}

// RequestUserConsent asks user permission for capability detection
func (cn *CapabilityNegotiator) RequestUserConsent() error {
	// In a real implementation, this would present UI to user
	// For now, we implement privacy-first approach

	if cn.privacyFirst {
		// Privacy-first mode: use conservative defaults unless user explicitly opts in
		cn.userConsent = false
		return nil
	}

	// Standard mode: assume consent for basic capability detection
	cn.userConsent = true
	return nil
}

// DetectCapabilities performs device capability detection
func (cn *CapabilityNegotiator) DetectCapabilities() (DeviceProfile, error) {
	if cn.privacyFirst && !cn.userConsent {
		// Return conservative defaults without any detection
		return cn.staticFallback, nil
	}

	capability := DeviceProfile{
		Detected:    time.Now(),
		UserConsent: cn.userConsent,
	}

	// Basic capability detection using only standard Go runtime info
	// This avoids invasive system probing while still providing useful optimization

	// Detect compute profile from runtime
	capability.ComputeProfile = cn.detectComputeProfile()

	// Detect memory profile (conservative approach)
	capability.MemoryProfile = cn.detectMemoryProfile()

	// Detect device class from available information
	capability.DeviceClass = cn.detectDeviceClass()

	// Conservative battery and network profiles
	capability.BatteryProfile = cn.detectBatteryProfile()
	capability.NetworkProfile = cn.detectNetworkProfile()

	return capability, nil
}

// detectComputeProfile detects processing capabilities
func (cn *CapabilityNegotiator) detectComputeProfile() ComputeProfile {
	cores := runtime.NumCPU()

	// Conservative thread allocation
	recommendedThreads := 2
	maxThreads := cores

	if cores >= 8 {
		recommendedThreads = 4
		maxThreads = cores / 2 // Leave headroom for other processes
	} else if cores >= 4 {
		recommendedThreads = 2
		maxThreads = cores - 1
	} else {
		recommendedThreads = 1
		maxThreads = cores
	}

	profileName := "conservative"
	if cores >= 16 {
		profileName = "high_performance"
	} else if cores >= 8 {
		profileName = "performance"
	} else if cores >= 4 {
		profileName = "balanced"
	} else {
		profileName = "limited"
	}

	return ComputeProfile{
		LogicalCores:       cores,
		RecommendedThreads: recommendedThreads,
		MaxThreads:         maxThreads,
		ProfileName:        profileName,
		HasHardwareAES:     true, // Assume modern hardware
	}
}

// detectMemoryProfile detects memory characteristics
func (cn *CapabilityNegotiator) detectMemoryProfile() MemoryProfile {
	// Conservative memory detection - avoid system-specific probing
	// Use heuristics based on compute profile

	cores := runtime.NumCPU()

	// Estimate available memory based on CPU count (very conservative)
	var availableGB float64
	var recommendedMB, maxSafeMB int
	var profileName string

	if cores >= 16 {
		// High-end system
		availableGB = 16.0
		recommendedMB = 128
		maxSafeMB = 256
		profileName = "high_memory"
	} else if cores >= 8 {
		// Performance system
		availableGB = 8.0
		recommendedMB = 64
		maxSafeMB = 128
		profileName = "performance_memory"
	} else if cores >= 4 {
		// Balanced system
		availableGB = 4.0
		recommendedMB = 64
		maxSafeMB = 96
		profileName = "balanced_memory"
	} else {
		// Limited system
		availableGB = 2.0
		recommendedMB = 32
		maxSafeMB = 64
		profileName = "limited_memory"
	}

	return MemoryProfile{
		AvailableGB:   availableGB,
		RecommendedMB: recommendedMB,
		MaxSafeMB:     maxSafeMB,
		ProfileName:   profileName,
		SupportsSwap:  true, // Conservative assumption
	}
}

// detectDeviceClass attempts to classify device type
func (cn *CapabilityNegotiator) detectDeviceClass() DeviceClass {
	// Conservative device classification based on minimal information
	cores := runtime.NumCPU()

	if cores >= 16 {
		return DeviceServer
	} else if cores >= 8 {
		return DeviceDesktop
	} else if cores >= 4 {
		return DeviceDesktop // Could be high-end mobile, but conservative
	} else {
		return DeviceMobile // Likely mobile or embedded
	}
}

// detectBatteryProfile detects power characteristics
func (cn *CapabilityNegotiator) detectBatteryProfile() BatteryProfile {
	// Conservative battery profile - assume battery unless clearly desktop/server
	deviceClass := cn.detectDeviceClass()

	hasBattery := true
	powerMode := PowerModeBalanced

	if deviceClass == DeviceServer || deviceClass == DeviceDesktop {
		hasBattery = false
		powerMode = PowerModePluggedIn
	}

	return BatteryProfile{
		HasBattery:     hasBattery,
		EstimatedLevel: -1, // Unknown
		PowerMode:      powerMode,
		ProfileName:    "conservative_power",
	}
}

// detectNetworkProfile detects network characteristics
func (cn *CapabilityNegotiator) detectNetworkProfile() NetworkProfile {
	// Conservative network profile - no invasive detection
	return NetworkProfile{
		ConnectionType:     "unknown",
		EstimatedBandwidth: -1,
		Latency:            -1,
		IsMetered:          false, // Conservative assumption
		ProfileName:        "conservative_network",
	}
}

// SelectCryptoParameters chooses optimal cryptographic parameters
func (cn *CapabilityNegotiator) SelectCryptoParameters(capability DeviceProfile) CryptoParameters {
	// Select Argon2ID parameters based on device capability

	var params CryptoParameters

	// Base parameters on memory and compute profiles
	memProfile := capability.MemoryProfile
	computeProfile := capability.ComputeProfile
	batteryProfile := capability.BatteryProfile

	// Conservative parameter selection with security floors
	if memProfile.RecommendedMB >= 128 && computeProfile.RecommendedThreads >= 4 && !batteryProfile.HasBattery {
		// High-end system - use maximum security
		params = CryptoParameters{
			Profile:      "maximum",
			MemoryKB:     128 * 1024, // 128MB
			Iterations:   4,
			Parallelism:  4,
			KeyLength:    32,
			SaltLength:   16,
			OptimizedFor: "security",
		}
	} else if memProfile.RecommendedMB >= 64 && computeProfile.RecommendedThreads >= 2 {
		// Balanced system - use balanced security
		params = CryptoParameters{
			Profile:      "balanced",
			MemoryKB:     64 * 1024, // 64MB
			Iterations:   2,
			Parallelism:  2,
			KeyLength:    32,
			SaltLength:   16,
			OptimizedFor: "balance",
		}
	} else {
		// Limited system - use interactive security (still secure)
		params = CryptoParameters{
			Profile:      "interactive",
			MemoryKB:     32 * 1024, // 32MB
			Iterations:   1,
			Parallelism:  2,
			KeyLength:    32,
			SaltLength:   16,
			OptimizedFor: "responsiveness",
		}
	}

	// Apply battery-aware adjustments
	if batteryProfile.HasBattery && batteryProfile.PowerMode == PowerModePowerSaver {
		// Reduce computational intensity for battery savings
		if params.Iterations > 1 {
			params.Iterations--
		}
		if params.Parallelism > 1 {
			params.Parallelism--
		}
		params.OptimizedFor = "battery_life"
	}

	// Always maintain security minimums
	if params.MemoryKB < 32*1024 {
		params.MemoryKB = 32 * 1024 // Minimum 32MB
	}
	if params.Iterations < 1 {
		params.Iterations = 1 // Minimum 1 iteration
	}
	if params.Parallelism < 1 {
		params.Parallelism = 1 // Minimum 1 thread
	}

	return params
}

// CryptoParameters represents selected cryptographic parameters
type CryptoParameters struct {
	Profile      string
	MemoryKB     int
	Iterations   int
	Parallelism  int
	KeyLength    int
	SaltLength   int
	OptimizedFor string
}

// GetParameterExplanation returns human-readable explanation of parameter selection
func (cp CryptoParameters) GetParameterExplanation() string {
	return fmt.Sprintf(
		"Using %s profile: %dMB memory, %d iterations, %d threads - optimized for %s",
		cp.Profile,
		cp.MemoryKB/1024,
		cp.Iterations,
		cp.Parallelism,
		cp.OptimizedFor,
	)
}

// ValidateParameters ensures parameters meet security requirements
func (cp CryptoParameters) ValidateParameters() error {
	if cp.MemoryKB < 32*1024 {
		return fmt.Errorf("memory parameter too low: %dKB (minimum 32MB)", cp.MemoryKB)
	}
	if cp.Iterations < 1 {
		return fmt.Errorf("iterations too low: %d (minimum 1)", cp.Iterations)
	}
	if cp.Parallelism < 1 {
		return fmt.Errorf("parallelism too low: %d (minimum 1)", cp.Parallelism)
	}
	if cp.KeyLength < 32 {
		return fmt.Errorf("key length too short: %d (minimum 32)", cp.KeyLength)
	}
	if cp.SaltLength < 16 {
		return fmt.Errorf("salt length too short: %d (minimum 16)", cp.SaltLength)
	}

	return nil
}

// GetCapabilitySummary returns human-readable capability summary
func (dc DeviceProfile) GetCapabilitySummary() string {
	return fmt.Sprintf(
		"Device: %s, Memory: %s, Compute: %s, Power: %s (detected: %s, consent: %t)",
		dc.DeviceClass.String(),
		dc.MemoryProfile.ProfileName,
		dc.ComputeProfile.ProfileName,
		dc.BatteryProfile.ProfileName,
		dc.Detected.Format("2006-01-02 15:04:05"),
		dc.UserConsent,
	)
}
