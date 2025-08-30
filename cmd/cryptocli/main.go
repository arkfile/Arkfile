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
	"golang.org/x/term"
)

const (
	Version = "1.0.0-static"
	Usage   = `cryptocli - Offline cryptographic operations for arkfile

USAGE:
    cryptocli [global options] command [command options] [arguments...]

COMMANDS:
    encrypt-password  Encrypt files using password-based key derivation
    decrypt-password  Decrypt files using password-based key derivation
    hash              Calculate SHA-256 hash of files
    generate-key      Generate random AES keys
    generate-test-file Generate test files with deterministic patterns
    version           Show version information

GLOBAL OPTIONS:
    --verbose, -v     Verbose output
    --help, -h        Show help

UTILITY COMMANDS:
    hash --file FILE
    generate-key [--size SIZE]
    generate-test-file --filename FILE --size SIZE

KEY TYPES:
    account           Account password-derived encryption (default)
    custom            Custom password-derived encryption

EXAMPLES:
    # Calculate file hash
    cryptocli hash --file document.pdf

    # Generate random key
    cryptocli generate-key --size 32

    # Generate test file
    cryptocli generate-test-file --filename test.bin --size 104857600
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
	case "encrypt-password":
		if err := handleEncryptPasswordCommand(args); err != nil {
			logError("Password-based encryption failed: %v", err)
			os.Exit(1)
		}
	case "decrypt-password":
		if err := handleDecryptPasswordCommand(args); err != nil {
			logError("Password-based decryption failed: %v", err)
			os.Exit(1)
		}
	case "derive-export-key":
		logError("derive-export-key command is not available in offline mode")
		logError("OPAQUE export key derivation requires server keys and user records")
		os.Exit(1)
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
	case "generate-test-file":
		if err := handleGenerateTestFileCommand(args); err != nil {
			logError("Test file generation failed: %v", err)
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

// handleGenerateTestFileCommand processes generate-test-file command
func handleGenerateTestFileCommand(args []string) error {
	fs := flag.NewFlagSet("generate-test-file", flag.ExitOnError)
	var (
		filename = fs.String("filename", "", "Output filename (required)")
		size     = fs.Int64("size", 0, "File size in bytes (required)")
		pattern  = fs.String("pattern", "deterministic", "Pattern type: deterministic, random, or zeros")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli generate-test-file [FLAGS]

Generate test files with specified size and pattern for testing purposes.

FLAGS:
    --filename FILE     Output filename (required)
    --size SIZE         File size in bytes (required)
    --pattern TYPE      Pattern type: deterministic, random, or zeros (default: deterministic)
    --help             Show this help message

EXAMPLES:
    cryptocli generate-test-file --filename test.bin --size 104857600
    cryptocli generate-test-file --filename random.bin --size 1048576 --pattern random
    cryptocli generate-test-file --filename zeros.bin --size 2048 --pattern zeros
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filename == "" {
		return fmt.Errorf("filename is required")
	}
	if *size <= 0 {
		return fmt.Errorf("size must be greater than 0")
	}
	if *size > 1024*1024*1024 { // 1GB limit
		return fmt.Errorf("size must not exceed 1GB (1073741824 bytes)")
	}

	var filePattern crypto.FilePattern
	switch *pattern {
	case "deterministic":
		filePattern = crypto.PatternSequential
	case "random":
		filePattern = crypto.PatternRandom
	case "zeros":
		filePattern = crypto.PatternZeros
	default:
		return fmt.Errorf("pattern must be 'deterministic', 'random', or 'zeros'")
	}

	logVerbose("Generating test file: %s (%d bytes, pattern: %s)", *filename, *size, filePattern)

	hashHex, err := crypto.GenerateTestFileToPath(*filename, *size, filePattern)
	if err != nil {
		return fmt.Errorf("failed to generate test file: %w", err)
	}

	// Output results
	fmt.Printf("Test file generated successfully\n")
	fmt.Printf("Filename: %s\n", *filename)
	fmt.Printf("Size: %d bytes\n", *size)
	fmt.Printf("Pattern: %s\n", *pattern)
	fmt.Printf("SHA-256: %s\n", hashHex)

	return nil
}

// handleEncryptPasswordCommand processes encrypt-password command
func handleEncryptPasswordCommand(args []string) error {
	fs := flag.NewFlagSet("encrypt-password", flag.ExitOnError)
	var (
		filePath   = fs.String("file", "", "File to encrypt (required)")
		username   = fs.String("username", "", "Username for salt generation (required)")
		keyType    = fs.String("key-type", "account", "Key type: account, custom, or share")
		outputPath = fs.String("output", "", "Output file path (optional)")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli encrypt-password [FLAGS]

Encrypt files using password-based key derivation with unified Argon2ID parameters.
Passwords are always prompted securely (hidden from view) for security.

FLAGS:
    --file FILE         File to encrypt (required)
    --username USER     Username for salt generation (required)
    --key-type TYPE     Key type: account, custom, or share (default: account)
    --output FILE       Output file path (optional, defaults to input.enc)
    --help             Show this help message

KEY TYPES:
    account             Account password encryption (uses username + "account" salt)
    custom              Custom password encryption (uses username + "custom" salt)
    share               Share password encryption (uses username + "share" salt)

EXAMPLES:
    cryptocli encrypt-password --file document.pdf --username alice --key-type account
    cryptocli encrypt-password --file data.bin --username bob --key-type custom
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		return fmt.Errorf("file path is required")
	}
	if *username == "" {
		return fmt.Errorf("username is required")
	}

	if *keyType != "account" && *keyType != "custom" && *keyType != "share" {
		return fmt.Errorf("key type must be 'account', 'custom', or 'share'")
	}

	// Always prompt for password securely
	fmt.Printf("Enter %s password for user '%s': ", *keyType, *username)
	passwordStr, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if passwordStr == "" {
		return fmt.Errorf("password cannot be empty")
	}

	// Validate password complexity based on key type
	var validation *crypto.PasswordValidationResult
	switch *keyType {
	case "account":
		validation = crypto.ValidateAccountPassword(passwordStr)
	case "custom":
		validation = crypto.ValidateCustomPassword(passwordStr)
	case "share":
		validation = crypto.ValidateSharePassword(passwordStr)
	}

	if !validation.MeetsRequirement {
		fmt.Printf("\nPassword validation failed:\n")
		fmt.Printf("  Entropy: %.2f bits (minimum: 60.0 bits required)\n", validation.Entropy)
		fmt.Printf("  Strength score: %d/4\n", validation.StrengthScore)
		if len(validation.Feedback) > 0 {
			fmt.Printf("  Feedback:\n")
			for _, feedback := range validation.Feedback {
				fmt.Printf("    - %s\n", feedback)
			}
		}
		if len(validation.PatternPenalties) > 0 {
			fmt.Printf("  Security concerns:\n")
			for _, penalty := range validation.PatternPenalties {
				fmt.Printf("    - %s\n", penalty)
			}
		}
		return fmt.Errorf("password does not meet security requirements")
	}

	logVerbose("Password validation passed: %.2f bits entropy (score: %d/4)", validation.Entropy, validation.StrengthScore)
	logVerbose("Using unified Argon2ID parameters: 8 iterations, 256MB memory, 4 threads")

	// Use core crypto function for encryption
	if err := crypto.EncryptFileToPath(*filePath, getOutputPath(*filePath, *outputPath), []byte(passwordStr), *username, *keyType); err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Clear password from memory
	passwordStr = ""

	// Get file sizes for reporting
	inputInfo, err := os.Stat(*filePath)
	if err != nil {
		return fmt.Errorf("failed to get input file info: %w", err)
	}

	outputFilePath := getOutputPath(*filePath, *outputPath)
	outputInfo, err := os.Stat(outputFilePath)
	if err != nil {
		return fmt.Errorf("failed to get output file info: %w", err)
	}

	fmt.Printf("Password-based encryption completed successfully\n")
	fmt.Printf("Input file: %s (%d bytes)\n", *filePath, inputInfo.Size())
	fmt.Printf("Output file: %s (%d bytes)\n", outputFilePath, outputInfo.Size())
	// Note: The file's actual envelope version is 0x01 and key type is 0x01, 0x02, or 0x03 as handled by crypto.CreatePasswordEnvelope.
	fmt.Printf("Key type: %s (version: 0x01)\n", *keyType)
	fmt.Printf("Argon2ID parameters: 8 iterations, 256MB memory, 4 threads\n")

	return nil
}

// handleDecryptPasswordCommand processes decrypt-password command
func handleDecryptPasswordCommand(args []string) error {
	fs := flag.NewFlagSet("decrypt-password", flag.ExitOnError)
	var (
		filePath   = fs.String("file", "", "File to decrypt (required)")
		username   = fs.String("username", "", "Username for salt generation (required)")
		keyType    = fs.String("key-type", "", "Key type: account, custom, or share (auto-detect if not specified)")
		outputPath = fs.String("output", "", "Output file path (optional)")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli decrypt-password [FLAGS]

Decrypt files using password-based key derivation with unified Argon2ID parameters.
Passwords are always prompted securely (hidden from view) for security.

FLAGS:
    --file FILE         File to decrypt (required)
    --username USER     Username for salt generation (required)
    --key-type TYPE     Key type: account, custom, or share (auto-detect if not specified)
    --output FILE       Output file path (optional, defaults to input.dec)
    --help             Show this help message

KEY TYPES:
    account             Account password encryption (uses username + "account" salt)
    custom              Custom password encryption (uses username + "custom" salt)
    share               Share password encryption (uses username + "share" salt)

EXAMPLES:
    cryptocli decrypt-password --file document.pdf.enc --username alice --key-type account
    cryptocli decrypt-password --file data.bin.enc --username bob --key-type custom
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		return fmt.Errorf("file path is required")
	}
	if *username == "" {
		return fmt.Errorf("username is required")
	}

	// Always prompt for password securely
	fmt.Printf("Enter password for user '%s': ", *username)
	passwordStr, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if passwordStr == "" {
		return fmt.Errorf("password cannot be empty")
	}

	logVerbose("Using unified Argon2ID parameters: 8 iterations, 256MB memory, 4 threads")

	// Use core crypto function for decryption
	outputFilePath := getOutputPath(*filePath, *outputPath)
	detectedKeyType, err := crypto.DecryptFileFromPath(*filePath, outputFilePath, []byte(passwordStr), *username)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Clear password from memory
	passwordStr = ""

	// Validate key type if specified
	if *keyType != "" && *keyType != detectedKeyType {
		return fmt.Errorf("key type mismatch: specified %s but file contains %s", *keyType, detectedKeyType)
	}

	// Get file sizes for reporting
	inputInfo, err := os.Stat(*filePath)
	if err != nil {
		return fmt.Errorf("failed to get input file info: %w", err)
	}

	outputInfo, err := os.Stat(outputFilePath)
	if err != nil {
		return fmt.Errorf("failed to get output file info: %w", err)
	}

	fmt.Printf("Password-based decryption completed successfully\n")
	fmt.Printf("Input file: %s (%d bytes)\n", *filePath, inputInfo.Size())
	fmt.Printf("Output file: %s (%d bytes)\n", outputFilePath, outputInfo.Size())
	fmt.Printf("Key type: %s (version: 0x01)\n", detectedKeyType)
	fmt.Printf("Argon2ID parameters: 8 iterations, 256MB memory, 4 threads\n")

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

func readPassword() (string, error) {
	fmt.Print("Password: ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		fmt.Println() // Print newline after password input
		return string(password), nil
	} else {
		// Fallback for non-terminal input
		reader := bufio.NewReader(os.Stdin)
		password, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(password), nil
	}
}

// getOutputPath determines the output file path
func getOutputPath(inputPath, outputPath string) string {
	if outputPath != "" {
		return outputPath
	}

	// Default output path
	if strings.HasSuffix(inputPath, ".enc") {
		// For decryption, remove .enc extension
		return strings.TrimSuffix(inputPath, ".enc")
	} else {
		// For encryption, add .enc extension
		return inputPath + ".enc"
	}
}
