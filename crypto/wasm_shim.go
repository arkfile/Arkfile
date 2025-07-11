//go:build js && wasm
// +build js,wasm

package crypto

import (
	"syscall/js"
	"time"
)

// DetectDeviceCapabilityWASM detects device performance by benchmarking Argon2ID
// This function is only available in WASM builds
func DetectDeviceCapabilityWASM() DeviceCapability {
	// Test password and salt for benchmarking
	testPassword := []byte("benchmark_password_for_capability_detection")
	testSalt := make([]byte, 32)
	copy(testSalt, []byte("benchmark_salt_for_performance_test_"))

	// Benchmark ArgonInteractive profile
	start := time.Now()
	DeriveKeyArgon2ID(testPassword, testSalt, ArgonInteractive)
	interactiveTime := time.Since(start)

	// Determine capability based on performance
	// These thresholds are tuned for browser environments
	if interactiveTime > 2000*time.Millisecond {
		return DeviceMinimal // Very slow device (old mobile)
	} else if interactiveTime > 800*time.Millisecond {
		return DeviceInteractive // Normal mobile device
	} else if interactiveTime > 300*time.Millisecond {
		return DeviceBalanced // Good mobile or low-end desktop
	} else {
		return DeviceMaximum // High-end desktop
	}
}

// GetOptimalProfileForBrowser returns the best Argon2ID profile for the current browser environment
func GetOptimalProfileForBrowser() ArgonProfile {
	capability := DetectDeviceCapabilityWASM()
	return capability.GetProfile()
}

// BenchmarkArgonProfileWASM benchmarks a specific Argon2ID profile and returns duration in milliseconds
func BenchmarkArgonProfileWASM(profile ArgonProfile) int64 {
	testPassword := []byte("benchmark_test")
	testSalt := make([]byte, 32)
	copy(testSalt, []byte("benchmark_salt_for_profile_test_"))

	start := time.Now()
	DeriveKeyArgon2ID(testPassword, testSalt, profile)
	duration := time.Since(start)

	return duration.Milliseconds()
}

// AdaptiveArgon2IDWASM applies Argon2ID with browser-appropriate parameters
// This is the main function exposed to JavaScript for client-side hardening
func AdaptiveArgon2IDWASM(password, salt []byte) []byte {
	profile := GetOptimalProfileForBrowser()
	return DeriveKeyArgon2ID(password, salt, profile)
}

// JavaScript-callable functions for WASM

// detectDeviceCapabilityJS is exported to JavaScript
func detectDeviceCapabilityJS(this js.Value, args []js.Value) interface{} {
	capability := DetectDeviceCapabilityWASM()
	return capability.String()
}

// benchmarkArgonProfileJS is exported to JavaScript for manual profiling
func benchmarkArgonProfileJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return map[string]interface{}{
			"error": "requires 3 arguments: time, memory, threads",
		}
	}

	// Parse arguments
	timeVal := uint32(args[0].Int())
	memory := uint32(args[1].Int())
	threads := uint8(args[2].Int())

	profile := ArgonProfile{
		Time:    timeVal,
		Memory:  memory,
		Threads: threads,
		KeyLen:  32,
	}

	// Validate profile
	if err := ValidateProfile(profile); err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	duration := BenchmarkArgonProfileWASM(profile)

	return map[string]interface{}{
		"duration_ms": duration,
		"profile": map[string]interface{}{
			"time":    profile.Time,
			"memory":  profile.Memory,
			"threads": profile.Threads,
		},
	}
}

// adaptiveArgon2IDJS is exported to JavaScript for client-side hardening
func adaptiveArgon2IDJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return "Invalid number of arguments: expected 2 (password, salt)"
	}

	// Convert JavaScript arguments to Go types
	passwordArray := args[0]
	saltArray := args[1]

	// Convert Uint8Array to []byte
	password := make([]byte, passwordArray.Length())
	js.CopyBytesToGo(password, passwordArray)

	salt := make([]byte, saltArray.Length())
	js.CopyBytesToGo(salt, saltArray)

	// Apply adaptive Argon2ID
	result := AdaptiveArgon2IDWASM(password, salt)

	// Convert result back to JavaScript Uint8Array
	resultArray := js.Global().Get("Uint8Array").New(len(result))
	js.CopyBytesToJS(resultArray, result)

	return resultArray
}

// getRecommendedProfileJS returns the recommended profile for the current device
func getRecommendedProfileJS(this js.Value, args []js.Value) interface{} {
	profile := GetOptimalProfileForBrowser()

	return map[string]interface{}{
		"time":    profile.Time,
		"memory":  profile.Memory,
		"threads": profile.Threads,
		"keyLen":  profile.KeyLen,
	}
}

// RegisterWASMFunctions registers all crypto functions with the JavaScript global scope
// This should be called from the main WASM module
func RegisterWASMFunctions() {
	js.Global().Set("detectDeviceCapability", js.FuncOf(detectDeviceCapabilityJS))
	js.Global().Set("benchmarkArgonProfile", js.FuncOf(benchmarkArgonProfileJS))
	js.Global().Set("adaptiveArgon2ID", js.FuncOf(adaptiveArgon2IDJS))
	js.Global().Set("getRecommendedProfile", js.FuncOf(getRecommendedProfileJS))
}

// Performance monitoring utilities

// WASMPerformanceInfo contains performance metrics for the current browser
type WASMPerformanceInfo struct {
	DeviceCapability     string
	RecommendedProfile   ArgonProfile
	InteractiveBenchmark int64 // milliseconds
	BalancedBenchmark    int64 // milliseconds
	MaximumBenchmark     int64 // milliseconds
}

// GetWASMPerformanceInfo runs comprehensive performance tests and returns detailed info
func GetWASMPerformanceInfo() WASMPerformanceInfo {
	capability := DetectDeviceCapabilityWASM()

	info := WASMPerformanceInfo{
		DeviceCapability:   capability.String(),
		RecommendedProfile: capability.GetProfile(),
	}

	// Benchmark all profiles for comparison
	info.InteractiveBenchmark = BenchmarkArgonProfileWASM(ArgonInteractive)
	info.BalancedBenchmark = BenchmarkArgonProfileWASM(ArgonBalanced)
	info.MaximumBenchmark = BenchmarkArgonProfileWASM(ArgonMaximum)

	return info
}

// getPerformanceInfoJS exports performance info to JavaScript
func getPerformanceInfoJS(this js.Value, args []js.Value) interface{} {
	info := GetWASMPerformanceInfo()

	return map[string]interface{}{
		"deviceCapability": info.DeviceCapability,
		"recommendedProfile": map[string]interface{}{
			"time":    info.RecommendedProfile.Time,
			"memory":  info.RecommendedProfile.Memory,
			"threads": info.RecommendedProfile.Threads,
			"keyLen":  info.RecommendedProfile.KeyLen,
		},
		"benchmarks": map[string]interface{}{
			"interactive": info.InteractiveBenchmark,
			"balanced":    info.BalancedBenchmark,
			"maximum":     info.MaximumBenchmark,
		},
	}
}

// RegisterExtendedWASMFunctions registers additional performance and diagnostic functions
func RegisterExtendedWASMFunctions() {
	RegisterWASMFunctions() // Register basic functions first
	js.Global().Set("getPerformanceInfo", js.FuncOf(getPerformanceInfoJS))
}

// opaqueHealthCheckJS provides a simple health check for OPAQUE readiness
func opaqueHealthCheckJS(this js.Value, args []js.Value) interface{} {
	return map[string]interface{}{
		"wasmReady":   true,
		"timestamp":   time.Now().Unix(),
		"opaqueReady": true, // WASM is ready means OPAQUE can work
	}
}

// deviceCapabilityAutoDetectJS provides simple device capability for registration
func deviceCapabilityAutoDetectJS(this js.Value, args []js.Value) interface{} {
	capability := DetectDeviceCapabilityWASM()
	profile := capability.GetProfile()

	return map[string]interface{}{
		"capability":  capability.String(),
		"memory":      profile.Memory,
		"description": getCapabilityDescription(capability),
	}
}

// getCapabilityDescription returns user-friendly description of device capability
func getCapabilityDescription(capability DeviceCapability) string {
	switch capability {
	case DeviceMinimal:
		return "Basic device - optimized for battery life and older hardware"
	case DeviceInteractive:
		return "Standard device - balanced security and performance"
	case DeviceBalanced:
		return "Good device - enhanced security with good performance"
	case DeviceMaximum:
		return "High-end device - maximum security with fast processing"
	default:
		return "Standard device - balanced security and performance"
	}
}

// RegisterAllWASMFunctions registers all WASM functions
func RegisterAllWASMFunctions() {
	RegisterExtendedWASMFunctions()

	// Add OPAQUE-compatible functions
	js.Global().Set("opaqueHealthCheck", js.FuncOf(opaqueHealthCheckJS))
	js.Global().Set("deviceCapabilityAutoDetect", js.FuncOf(deviceCapabilityAutoDetectJS))
}
