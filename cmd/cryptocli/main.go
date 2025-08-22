// cryptocli - Offline cryptographic operations for arkfile
// This tool works completely offline using existing arkfile crypto infrastructure

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/84adam/Arkfile/crypto"
)

const (
	Version = "1.0.0-static"
	Usage   = `cryptocli - Offline cryptographic operations for arkfile

USAGE:
    cryptocli [global options] command [command options] [arguments...]

COMMANDS:
    encrypt           Encrypt files using OPAQUE export keys
    decrypt           Decrypt files using OPAQUE export keys
    derive-key        Derive encryption keys from OPAQUE export keys
    hash              Calculate SHA-256 hash of files
    generate-key      Generate random AES keys
    version           Show version information

GLOBAL OPTIONS:
    --verbose, -v     Verbose output
    --help, -h        Show help

ENCRYPTION COMMANDS:
    encrypt --file FILE --export-key KEY --username USER --file-id ID [--key-type TYPE]
    decrypt --file FILE --export-key KEY --username USER --file-id ID [--key-type TYPE]

KEY DERIVATION:
    derive-key --export-key KEY --username USER --file-id ID [--key-type TYPE]

UTILITY COMMANDS:
    hash --file FILE
    generate-key [--size SIZE]

KEY TYPES:
    account           Account password-derived encryption (default)
    custom            Custom password-derived encryption

EXAMPLES:
    # Encrypt with account key
    cryptocli encrypt --file document.pdf --export-key <base64> --username alice --file-id doc123

    # Decrypt with custom key
    cryptocli decrypt --file encrypted.bin --export-key <base64> --username alice --file-id doc123 --key-type custom

    # Derive key for inspection
    cryptocli derive-key --export-key <base64> --username alice --file-id doc123

    # Calculate file hash
    cryptocli hash --file document.pdf

    # Generate random key
    cryptocli generate-key --size 32
`
)

var verbose bool

// EncryptedFileHeader represents the structure of encrypted file headers
type EncryptedFileHeader struct {
	Version byte
	KeyType byte
}

func main() {
	// Global flags
	var (
		verboseFlag = flag.Bool("verbose", false, "Verbose output")
		vFlag       = flag.Bool("v", false, "Verbose output (short)")
		helpFlag    = flag.Bool("help", false, "Show help information")
		hFlag       = flag.Bool("h", false, "Show help information (short)")
		versionFlag = flag.Bool("version", false, "Show version information")
	)

	flag.Parse()

	verbose = *verboseFlag || *vFlag

	if *versionFlag {
		printVersion()
		return
	}

	if *helpFlag || *hFlag || flag.NArg() == 0 {
		printUsage()
		return
	}

	// Parse command
	command := flag.Arg(0)
	args := flag.Args()[1:]

	// Execute command
	switch command {
	case "encrypt":
		if err := handleEncryptCommand(args); err != nil {
			logError("Encryption failed: %v", err)
			os.Exit(1)
		}
	case "decrypt":
		if err := handleDecryptCommand(args); err != nil {
			logError("Decryption failed: %v", err)
			os.Exit(1)
		}
	case "derive-key":
		if err := handleDeriveKeyCommand(args); err != nil {
			logError("Key derivation failed: %v", err)
			os.Exit(1)
		}
	case "hash":
		if err := handleHashCommand(args); err != nil {
			logError("Hash calculation failed: %v", err)
			os.Exit(1)
		}
	case "generate-key":
		if err := handleGenerateKeyCommand(args); err != nil {
			logError("Key generation failed: %v", err)
			os.Exit(1)
		}
	case "version":
		printVersion()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

// handleEncryptCommand processes encrypt command
func handleEncryptCommand(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	var (
		filePath    = fs.String("file", "", "File to encrypt (required)")
		exportKey   = fs.String("export-key", "", "OPAQUE export key (base64) (required)")
		username    = fs.String("username", "", "Username for key derivation (required)")
		fileID      = fs.String("file-id", "", "File ID for key derivation (required)")
		keyType     = fs.String("key-type", "account", "Key type: account or custom")
		outputPath  = fs.String("output", "", "Output file path (optional)")
		chunkFormat = fs.Bool("chunked", false, "Use chunked encryption format")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli encrypt [FLAGS]

Encrypt files using OPAQUE export keys (completely offline).

FLAGS:
    --file FILE         File to encrypt (required)
    --export-key KEY    OPAQUE export key (base64 encoded) (required)
    --username USER     Username for key derivation (required)
    --file-id ID        File ID for key derivation (required)
    --key-type TYPE     Key type: account or custom (default: account)
    --output FILE       Output file path (optional, defaults to input.enc)
    --chunked           Use chunked encryption format
    --help             Show this help message

EXAMPLES:
    cryptocli encrypt --file document.pdf --export-key dGVzdGtleQ== --username alice --file-id doc123
    cryptocli encrypt --file data.bin --export-key dGVzdGtleQ== --username bob --file-id data456 --key-type custom
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		return fmt.Errorf("file path is required")
	}
	if *exportKey == "" {
		return fmt.Errorf("export key is required")
	}
	if *username == "" {
		return fmt.Errorf("username is required")
	}
	if *fileID == "" {
		return fmt.Errorf("file ID is required")
	}

	if *keyType != "account" && *keyType != "custom" {
		return fmt.Errorf("key type must be 'account' or 'custom'")
	}

	// Decode export key
	exportKeyBytes, err := base64.StdEncoding.DecodeString(*exportKey)
	if err != nil {
		return fmt.Errorf("invalid export key format: %w", err)
	}

	logVerbose("Export key length: %d bytes", len(exportKeyBytes))

	// Read input file
	fileData, err := os.ReadFile(*filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	logVerbose("File size: %d bytes", len(fileData))

	// Derive file encryption key
	var fileKey []byte
	var version, keyTypeByte byte

	if *keyType == "account" {
		version = 0x01
		keyTypeByte = 0x01
		fileKey, err = crypto.DeriveAccountFileKey(exportKeyBytes, *username, *fileID)
	} else {
		version = 0x02
		keyTypeByte = 0x02
		fileKey, err = crypto.DeriveOPAQUEFileKey(exportKeyBytes, *fileID, *username)
	}

	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	logVerbose("Derived key: %x", fileKey[:8]) // Show first 8 bytes for debugging

	// Encrypt file
	var encryptedData []byte

	if *chunkFormat {
		// Use chunked format with envelope
		envelope := []byte{version, keyTypeByte}

		// For simplicity, encrypt as a single chunk
		ciphertext, err := crypto.EncryptGCM(fileData, fileKey)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}

		// Combine envelope + encrypted data
		encryptedData = make([]byte, len(envelope)+len(ciphertext))
		copy(encryptedData, envelope)
		copy(encryptedData[len(envelope):], ciphertext)
	} else {
		// Use simple format with version header
		ciphertext, err := crypto.EncryptGCM(fileData, fileKey)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}

		// Add version header: [version][keyType] + ciphertext
		encryptedData = make([]byte, 2+len(ciphertext))
		encryptedData[0] = version
		encryptedData[1] = keyTypeByte
		copy(encryptedData[2:], ciphertext)
	}

	// Determine output path
	outputFilePath := *outputPath
	if outputFilePath == "" {
		outputFilePath = *filePath + ".enc"
	}

	// Write encrypted file
	if err := os.WriteFile(outputFilePath, encryptedData, 0644); err != nil {
		return fmt.Errorf("failed to write encrypted file: %w", err)
	}

	fmt.Printf("✅ Encryption completed successfully\n")
	fmt.Printf("Input file: %s (%d bytes)\n", *filePath, len(fileData))
	fmt.Printf("Output file: %s (%d bytes)\n", outputFilePath, len(encryptedData))
	fmt.Printf("Key type: %s (version: 0x%02x)\n", *keyType, version)
	if *chunkFormat {
		fmt.Printf("Format: chunked with envelope\n")
	} else {
		fmt.Printf("Format: simple with header\n")
	}

	return nil
}

// handleDecryptCommand processes decrypt command
func handleDecryptCommand(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	var (
		filePath   = fs.String("file", "", "File to decrypt (required)")
		exportKey  = fs.String("export-key", "", "OPAQUE export key (base64) (required)")
		username   = fs.String("username", "", "Username for key derivation (required)")
		fileID     = fs.String("file-id", "", "File ID for key derivation (required)")
		keyType    = fs.String("key-type", "", "Key type: account or custom (auto-detect if not specified)")
		outputPath = fs.String("output", "", "Output file path (optional)")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli decrypt [FLAGS]

Decrypt files using OPAQUE export keys (completely offline).

FLAGS:
    --file FILE         File to decrypt (required)
    --export-key KEY    OPAQUE export key (base64 encoded) (required)
    --username USER     Username for key derivation (required)
    --file-id ID        File ID for key derivation (required)
    --key-type TYPE     Key type: account or custom (auto-detect if not specified)
    --output FILE       Output file path (optional, defaults to input.dec)
    --help             Show this help message

EXAMPLES:
    cryptocli decrypt --file document.pdf.enc --export-key dGVzdGtleQ== --username alice --file-id doc123
    cryptocli decrypt --file data.bin.enc --export-key dGVzdGtleQ== --username bob --file-id data456 --key-type custom
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		return fmt.Errorf("file path is required")
	}
	if *exportKey == "" {
		return fmt.Errorf("export key is required")
	}
	if *username == "" {
		return fmt.Errorf("username is required")
	}
	if *fileID == "" {
		return fmt.Errorf("file ID is required")
	}

	// Decode export key
	exportKeyBytes, err := base64.StdEncoding.DecodeString(*exportKey)
	if err != nil {
		return fmt.Errorf("invalid export key format: %w", err)
	}

	// Read encrypted file
	encryptedData, err := os.ReadFile(*filePath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}

	logVerbose("Encrypted file size: %d bytes", len(encryptedData))

	// Check minimum length
	if len(encryptedData) < 2 {
		return fmt.Errorf("encrypted file too short")
	}

	// Read version and key type from header
	version := encryptedData[0]
	keyTypeByte := encryptedData[1]

	logVerbose("File version: 0x%02x, key type: 0x%02x", version, keyTypeByte)

	// Determine key type from header if not specified
	detectedKeyType := ""
	switch version {
	case 0x01:
		if keyTypeByte == 0x01 {
			detectedKeyType = "account"
		}
	case 0x02:
		if keyTypeByte == 0x02 {
			detectedKeyType = "custom"
		}
	}

	if detectedKeyType == "" {
		return fmt.Errorf("unsupported file format (version: 0x%02x, key type: 0x%02x)", version, keyTypeByte)
	}

	// Use specified key type or detected key type
	finalKeyType := *keyType
	if finalKeyType == "" {
		finalKeyType = detectedKeyType
	} else if finalKeyType != detectedKeyType {
		return fmt.Errorf("key type mismatch: specified %s but file contains %s", finalKeyType, detectedKeyType)
	}

	// Derive file encryption key
	var fileKey []byte

	if finalKeyType == "account" {
		fileKey, err = crypto.DeriveAccountFileKey(exportKeyBytes, *username, *fileID)
	} else {
		fileKey, err = crypto.DeriveOPAQUEFileKey(exportKeyBytes, *fileID, *username)
	}

	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	logVerbose("Derived key: %x", fileKey[:8]) // Show first 8 bytes for debugging

	// Extract ciphertext (skip 2-byte header)
	ciphertext := encryptedData[2:]

	// Decrypt file
	plaintext, err := crypto.DecryptGCM(ciphertext, fileKey)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Determine output path
	outputFilePath := *outputPath
	if outputFilePath == "" {
		// Remove .enc extension if present
		if strings.HasSuffix(*filePath, ".enc") {
			outputFilePath = strings.TrimSuffix(*filePath, ".enc")
		} else {
			outputFilePath = *filePath + ".dec"
		}
	}

	// Write decrypted file
	if err := os.WriteFile(outputFilePath, plaintext, 0644); err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	fmt.Printf("✅ Decryption completed successfully\n")
	fmt.Printf("Input file: %s (%d bytes)\n", *filePath, len(encryptedData))
	fmt.Printf("Output file: %s (%d bytes)\n", outputFilePath, len(plaintext))
	fmt.Printf("Key type: %s (version: 0x%02x)\n", finalKeyType, version)

	return nil
}

// handleDeriveKeyCommand processes derive-key command
func handleDeriveKeyCommand(args []string) error {
	fs := flag.NewFlagSet("derive-key", flag.ExitOnError)
	var (
		exportKey = fs.String("export-key", "", "OPAQUE export key (base64) (required)")
		username  = fs.String("username", "", "Username for key derivation (required)")
		fileID    = fs.String("file-id", "", "File ID for key derivation (required)")
		keyType   = fs.String("key-type", "account", "Key type: account or custom")
		format    = fs.String("format", "hex", "Output format: hex or base64")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli derive-key [FLAGS]

Derive encryption keys from OPAQUE export keys for inspection.

FLAGS:
    --export-key KEY    OPAQUE export key (base64 encoded) (required)
    --username USER     Username for key derivation (required)
    --file-id ID        File ID for key derivation (required)
    --key-type TYPE     Key type: account or custom (default: account)
    --format FORMAT     Output format: hex or base64 (default: hex)
    --help             Show this help message

EXAMPLES:
    cryptocli derive-key --export-key dGVzdGtleQ== --username alice --file-id doc123
    cryptocli derive-key --export-key dGVzdGtleQ== --username bob --file-id data456 --key-type custom --format base64
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *exportKey == "" {
		return fmt.Errorf("export key is required")
	}
	if *username == "" {
		return fmt.Errorf("username is required")
	}
	if *fileID == "" {
		return fmt.Errorf("file ID is required")
	}

	if *keyType != "account" && *keyType != "custom" {
		return fmt.Errorf("key type must be 'account' or 'custom'")
	}

	if *format != "hex" && *format != "base64" {
		return fmt.Errorf("format must be 'hex' or 'base64'")
	}

	// Decode export key
	exportKeyBytes, err := base64.StdEncoding.DecodeString(*exportKey)
	if err != nil {
		return fmt.Errorf("invalid export key format: %w", err)
	}

	// Derive file encryption key
	var fileKey []byte

	if *keyType == "account" {
		fileKey, err = crypto.DeriveAccountFileKey(exportKeyBytes, *username, *fileID)
	} else {
		fileKey, err = crypto.DeriveOPAQUEFileKey(exportKeyBytes, *fileID, *username)
	}

	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	// Output derived key
	fmt.Printf("Key derivation successful\n")
	fmt.Printf("Username: %s\n", *username)
	fmt.Printf("File ID: %s\n", *fileID)
	fmt.Printf("Key type: %s\n", *keyType)
	fmt.Printf("Export key length: %d bytes\n", len(exportKeyBytes))
	fmt.Printf("Derived key length: %d bytes\n", len(fileKey))

	if *format == "hex" {
		fmt.Printf("Derived key (hex): %x\n", fileKey)
	} else {
		fmt.Printf("Derived key (base64): %s\n", base64.StdEncoding.EncodeToString(fileKey))
	}

	return nil
}

// handleHashCommand processes hash command
func handleHashCommand(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	var (
		filePath = fs.String("file", "", "File to hash (required)")
		format   = fs.String("format", "hex", "Output format: hex or base64")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli hash [FLAGS]

Calculate SHA-256 hash of files.

FLAGS:
    --file FILE         File to hash (required)
    --format FORMAT     Output format: hex or base64 (default: hex)
    --help             Show this help message

EXAMPLES:
    cryptocli hash --file document.pdf
    cryptocli hash --file data.bin --format base64
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		return fmt.Errorf("file path is required")
	}

	if *format != "hex" && *format != "base64" {
		return fmt.Errorf("format must be 'hex' or 'base64'")
	}

	// Read file
	fileData, err := os.ReadFile(*filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Calculate SHA-256 hash directly
	hasher := sha256.New()
	hasher.Write(fileData)
	hash := hasher.Sum(nil)

	// Output hash
	fmt.Printf("File: %s\n", *filePath)
	fmt.Printf("Size: %d bytes\n", len(fileData))

	if *format == "hex" {
		fmt.Printf("SHA-256 (hex): %s\n", hex.EncodeToString(hash))
	} else {
		fmt.Printf("SHA-256 (base64): %s\n", base64.StdEncoding.EncodeToString(hash))
	}

	return nil
}

// handleGenerateKeyCommand processes generate-key command
func handleGenerateKeyCommand(args []string) error {
	fs := flag.NewFlagSet("generate-key", flag.ExitOnError)
	var (
		size   = fs.Int("size", 32, "Key size in bytes (default: 32 for AES-256)")
		format = fs.String("format", "hex", "Output format: hex or base64")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli generate-key [FLAGS]

Generate cryptographically secure random keys.

FLAGS:
    --size SIZE         Key size in bytes (default: 32 for AES-256)
    --format FORMAT     Output format: hex or base64 (default: hex)
    --help             Show this help message

EXAMPLES:
    cryptocli generate-key
    cryptocli generate-key --size 16 --format base64
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *size < 1 || *size > 1024 {
		return fmt.Errorf("key size must be between 1 and 1024 bytes")
	}

	if *format != "hex" && *format != "base64" {
		return fmt.Errorf("format must be 'hex' or 'base64'")
	}

	// Generate key
	key := crypto.GenerateRandomBytes(*size)

	// Output key
	fmt.Printf("Generated %d-byte key:\n", *size)

	if *format == "hex" {
		fmt.Printf("Key (hex): %x\n", key)
	} else {
		fmt.Printf("Key (base64): %s\n", base64.StdEncoding.EncodeToString(key))
	}

	return nil
}

// Helper functions

func printVersion() {
	fmt.Printf("cryptocli version %s\n", Version)
	fmt.Printf("Offline cryptographic operations for arkfile\n")
}

func printUsage() {
	fmt.Print(Usage)
}

func logVerbose(format string, args ...interface{}) {
	if verbose {
		fmt.Printf("[VERBOSE] "+format+"\n", args...)
	}
}

func logError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}

// readPassword reads a password from stdin without echoing
func readPassword() (string, error) {
	fmt.Print("Password: ")
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(password), nil
}
