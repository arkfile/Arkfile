package main

import (
	"encoding/base32"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <secret> [unix_timestamp]\n", os.Args[0])
		fmt.Println("  secret: Base32-encoded TOTP secret")
		fmt.Println("  unix_timestamp: Optional Unix timestamp (defaults to current time)")
		fmt.Println("\nFor testing, use a fixed secret like: JBSWY3DPEHPK3PXP")
		fmt.Println("This generates deterministic codes for automated testing.")
		os.Exit(1)
	}

	secret := os.Args[1]

	// Add padding if needed for base32 decoding
	secretPadded := secret
	if len(secret)%8 != 0 {
		padding := 8 - (len(secret) % 8)
		for i := 0; i < padding; i++ {
			secretPadded += "="
		}
	}

	// Validate secret format
	if _, err := base32.StdEncoding.DecodeString(secretPadded); err != nil {
		fmt.Printf("Error: Invalid base32 secret: %v\n", err)
		os.Exit(1)
	}

	// Use the padded secret for TOTP generation
	secret = secretPadded

	// Use provided timestamp or current time
	var testTime time.Time
	if len(os.Args) >= 3 {
		timestamp, err := strconv.ParseInt(os.Args[2], 10, 64)
		if err != nil {
			fmt.Printf("Error: Invalid timestamp: %v\n", err)
			os.Exit(1)
		}
		testTime = time.Unix(timestamp, 0)
	} else {
		testTime = time.Now()
	}

	// Generate TOTP code using the same parameters as production
	code, err := totp.GenerateCodeCustom(secret, testTime, totp.ValidateOpts{
		Period:    30, // Same as TOTPPeriod in production
		Skew:      0,  // No skew for deterministic generation
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil {
		fmt.Printf("Error generating TOTP code: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", code)
}
