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
    encrypt-metadata  Encrypt file metadata (filename, hash) using password-derived key
    decrypt-metadata  Decrypt file metadata (filename, hash) using password-derived key
    encrypt-fek       Encrypt a File Encryption Key (FEK) using password-derived key
    decrypt-fek       Decrypt a File Encryption Key (FEK) using password-derived key
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
	case "encrypt-metadata":
		if err := handleEncryptMetadataCommand(args); err != nil {
			logError("Metadata encryption failed: %v", err)
			os.Exit(1)
		}
	case "decrypt-metadata":
		if err := handleDecryptMetadataCommand(args); err != nil {
			logError("Metadata decryption failed: %v", err)
			os.Exit(1)
		}
	case "encrypt-fek":
		if err := handleEncryptFEKCommand(args); err != nil {
			logError("FEK encryption failed: %v", err)
			os.Exit(1)
		}
	case "decrypt-fek":
		if err := handleDecryptFEKCommand(args); err != nil {
			logError("FEK decryption failed: %v", err)
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
	password, err := readPassword(fmt.Sprintf("Enter %s password for user '%s': ", *keyType, *username))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	// Validate password complexity based on key type
	var validation *crypto.PasswordValidationResult
	switch *keyType {
	case "account":
		validation = crypto.ValidateAccountPassword(string(password))
	case "custom":
		validation = crypto.ValidateCustomPassword(string(password))
	case "share":
		validation = crypto.ValidateSharePassword(string(password))
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
	if err := crypto.EncryptFileToPath(*filePath, getOutputPath(*filePath, *outputPath), password, *username, *keyType); err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

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
	prompt := fmt.Sprintf("Enter password for user '%s'", *username)
	if *keyType != "" {
		prompt = fmt.Sprintf("Enter %s password for user '%s'", *keyType, *username)
	}
	password, err := readPassword(prompt + ": ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	logVerbose("Using unified Argon2ID parameters: 8 iterations, 256MB memory, 4 threads")

	// Use core crypto function for decryption
	outputFilePath := getOutputPath(*filePath, *outputPath)
	detectedKeyType, err := crypto.DecryptFileFromPath(*filePath, outputFilePath, password, *username)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Validate key type if specified, otherwise update it
	if *keyType == "" {
		*keyType = detectedKeyType
		logVerbose("Auto-detected key type: %s", detectedKeyType)
	} else if *keyType != detectedKeyType {
		// Only fail if the user explicitly specified the wrong key type
		return fmt.Errorf("key type mismatch: specified '%s' but file contains '%s'", *keyType, detectedKeyType)
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

// handleEncryptMetadataCommand processes the encrypt-metadata command
func handleEncryptMetadataCommand(args []string) error {
	fs := flag.NewFlagSet("encrypt-metadata", flag.ExitOnError)
	var (
		filename       = fs.String("filename", "", "Filename to encrypt (required)")
		sha256sum      = fs.String("sha256sum", "", "SHA256 hash to encrypt (required)")
		username       = fs.String("username", "", "Username for salt generation (required)")
		passwordSource = fs.String("password-source", "prompt", "Password source: prompt or stdin")
		outputFormat   = fs.String("output-format", "separated", "Output format: separated or combined (default: separated)")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli encrypt-metadata [FLAGS]

Encrypts file metadata (filename, SHA256 hash) using a password-derived key.
Metadata is encrypted separately from file content and uses a key derived directly from the password.
Outputs separate nonce and encrypted data fields for compatibility with the server API.

FLAGS:
    --filename FILE         Filename to encrypt (required)
    --sha256sum HASH        SHA256 hash to encrypt (required)
    --username USER         Username for salt generation (required)
    --password-source SRC   Password source: prompt or stdin (default: prompt)
    --output-format FMT     Output format: separated or combined (default: separated)
    --help                  Show this help message

OUTPUT FORMAT:
    separated: Outputs nonce and encrypted data separately (default, for server/client compatibility)
    combined: Outputs combined nonce+data+tag format (legacy format)

EXAMPLE:
    cryptocli encrypt-metadata --filename "document.pdf" --sha256sum "abc123..." --username "alice"
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filename == "" || *sha256sum == "" || *username == "" {
		fs.Usage()
		return fmt.Errorf("filename, sha256sum, and username are required")
	}

	// Read password
	var password []byte
	var err error
	if *passwordSource == "stdin" {
		reader := bufio.NewReader(os.Stdin)
		passwordStr, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read password from stdin: %w", err)
		}
		password = []byte(strings.TrimSpace(passwordStr))
	} else {
		password, err = readPassword(fmt.Sprintf("Enter password for user '%s' to encrypt metadata: ", *username))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	// Derive metadata key directly from password (account key type)
	// Metadata always uses the account password key derivation
	metadataKey := crypto.DeriveAccountPasswordKey(password, *username)
	logVerbose("Derived metadata key using account password derivation for user: %s", *username)

	// Encrypt filename
	encryptedFilename, err := crypto.EncryptGCM([]byte(*filename), metadataKey)
	if err != nil {
		return fmt.Errorf("filename encryption failed: %w", err)
	}

	// Encrypt SHA256
	encryptedSha256, err := crypto.EncryptGCM([]byte(*sha256sum), metadataKey)
	if err != nil {
		return fmt.Errorf("SHA256 encryption failed: %w", err)
	}

	// Print results based on output format
	fmt.Printf("Metadata encrypted successfully\n")

	if *outputFormat == "combined" {
		// Legacy format: output combined nonce+data+tag
		fmt.Printf("Encrypted Filename: %s\n", base64.StdEncoding.EncodeToString(encryptedFilename))
		fmt.Printf("Encrypted SHA256: %s\n", base64.StdEncoding.EncodeToString(encryptedSha256))
	} else {
		// Default separated format: extract nonce and data separately
		// GCM format is: [12-byte nonce][encrypted data + 16-byte tag]

		// For filename
		if len(encryptedFilename) < 12 {
			return fmt.Errorf("encrypted filename too short to contain nonce")
		}
		filenameNonce := encryptedFilename[:12]
		filenameData := encryptedFilename[12:]

		// For SHA256
		if len(encryptedSha256) < 12 {
			return fmt.Errorf("encrypted SHA256 too short to contain nonce")
		}
		sha256Nonce := encryptedSha256[:12]
		sha256Data := encryptedSha256[12:]

		// Output in the format expected by arkfile-client and server
		fmt.Printf("Filename Nonce: %s\n", base64.StdEncoding.EncodeToString(filenameNonce))
		fmt.Printf("Encrypted Filename: %s\n", base64.StdEncoding.EncodeToString(filenameData))
		fmt.Printf("SHA256 Nonce: %s\n", base64.StdEncoding.EncodeToString(sha256Nonce))
		fmt.Printf("Encrypted SHA256: %s\n", base64.StdEncoding.EncodeToString(sha256Data))

		logVerbose("Output format: separated (nonce: 12 bytes, data+tag: %d bytes for filename, %d bytes for SHA256)",
			len(filenameData), len(sha256Data))
	}

	return nil
}

// handleDecryptMetadataCommand processes the decrypt-metadata command
func handleDecryptMetadataCommand(args []string) error {
	fs := flag.NewFlagSet("decrypt-metadata", flag.ExitOnError)
	var (
		filenameNonce          = fs.String("filename-nonce", "", "Base64 encoded filename nonce (required)")
		encryptedFilenameData  = fs.String("encrypted-filename-data", "", "Base64 encoded encrypted filename data (required)")
		sha256sumNonce         = fs.String("sha256sum-nonce", "", "Base64 encoded SHA256 nonce (required)")
		encryptedSha256sumData = fs.String("encrypted-sha256sum-data", "", "Base64 encoded encrypted SHA256 data (required)")
		username               = fs.String("username", "", "Username for salt generation (required)")
		passwordSource         = fs.String("password-source", "prompt", "Password source: prompt or stdin")
		debugMode              = fs.Bool("debug", false, "Enable debug logging for troubleshooting")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli decrypt-metadata [FLAGS]

Decrypts file metadata (filename, SHA256 hash) using a password-derived key.
Metadata is encrypted separately from file content and uses a key derived directly from the password.
This version accepts separate nonce and encrypted data parameters matching server JSON format.

FLAGS:
    --filename-nonce DATA           Base64 encoded filename nonce (required)
    --encrypted-filename-data DATA  Base64 encoded encrypted filename data (required)
    --sha256sum-nonce DATA          Base64 encoded SHA256 nonce (required)  
    --encrypted-sha256sum-data DATA Base64 encoded encrypted SHA256 data (required)
    --username USER                 Username for salt generation (required)
    --password-source SRC           Password source: prompt or stdin (default: prompt)
    --debug                        Enable debug logging for troubleshooting
    --help                         Show this help message

EXAMPLE:
    cryptocli decrypt-metadata \
        --filename-nonce "base64nonce..." \
        --encrypted-filename-data "base64data..." \
        --sha256sum-nonce "base64nonce..." \
        --encrypted-sha256sum-data "base64data..." \
        --username "alice"
`)
	}

	if err := fs.Parse(args); err != nil {
		logError("Failed to parse command line arguments: %v", err)
		return err
	}

	// Enable debug logging if requested or if verbose is enabled
	debugLogging := *debugMode || verbose

	if debugLogging {
		logVerbose("=== CRYPTOCLI DECRYPT-METADATA DEBUG SESSION ===")
		logVerbose("Command: decrypt-metadata")
		logVerbose("Arguments received: %d args", len(args))
		logVerbose("Username: '%s'", *username)
		logVerbose("Password source: %s", *passwordSource)
		logVerbose("Debug mode: %t", *debugMode)
	}

	if *filenameNonce == "" || *encryptedFilenameData == "" || *sha256sumNonce == "" || *encryptedSha256sumData == "" || *username == "" {
		if debugLogging {
			logVerbose("Parameter validation failed:")
			logVerbose("  filename-nonce empty: %t", *filenameNonce == "")
			logVerbose("  encrypted-filename-data empty: %t", *encryptedFilenameData == "")
			logVerbose("  sha256sum-nonce empty: %t", *sha256sumNonce == "")
			logVerbose("  encrypted-sha256sum-data empty: %t", *encryptedSha256sumData == "")
			logVerbose("  username empty: %t", *username == "")
		}
		fs.Usage()
		return fmt.Errorf("filename-nonce, encrypted-filename-data, sha256sum-nonce, encrypted-sha256sum-data, and username are required")
	}

	if debugLogging {
		logVerbose("=== INPUT PARAMETERS VALIDATION PASSED ===")
		logVerbose("filename-nonce length: %d characters", len(*filenameNonce))
		logVerbose("encrypted-filename-data length: %d characters", len(*encryptedFilenameData))
		logVerbose("sha256sum-nonce length: %d characters", len(*sha256sumNonce))
		logVerbose("encrypted-sha256sum-data length: %d characters", len(*encryptedSha256sumData))
		logVerbose("username: '%s'", *username)
	}

	// Read password
	var password []byte
	var err error
	if *passwordSource == "stdin" {
		if debugLogging {
			logVerbose("Reading password from stdin...")
		}
		reader := bufio.NewReader(os.Stdin)
		passwordStr, err := reader.ReadString('\n')
		if err != nil {
			if debugLogging {
				logVerbose("Failed to read password from stdin: %v", err)
			}
			return fmt.Errorf("failed to read password from stdin: %w", err)
		}
		password = []byte(strings.TrimSpace(passwordStr))
	} else {
		if debugLogging {
			logVerbose("Reading password from secure prompt...")
		}
		password, err = readPassword(fmt.Sprintf("Enter password for user '%s' to decrypt metadata: ", *username))
		if err != nil {
			if debugLogging {
				logVerbose("Failed to read password from prompt: %v", err)
			}
			return fmt.Errorf("failed to read password: %w", err)
		}
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	if len(password) == 0 {
		if debugLogging {
			logVerbose("Password validation failed: empty password")
		}
		return fmt.Errorf("password cannot be empty")
	}

	if debugLogging {
		logVerbose("Password successfully read (length: %d characters)", len(password))
		logVerbose("=== STARTING BASE64 DECODING ===")
	}

	// Decode separate nonce and encrypted data components
	filenameNonceBytes, err := base64.StdEncoding.DecodeString(*filenameNonce)
	if err != nil {
		if debugLogging {
			logVerbose("Base64 decode failed for filename-nonce: %v", err)
			logVerbose("Raw filename-nonce input: '%s' (length: %d)", *filenameNonce, len(*filenameNonce))
		}
		return fmt.Errorf("failed to decode filename-nonce: %w", err)
	}

	encryptedFilenameBytes, err := base64.StdEncoding.DecodeString(*encryptedFilenameData)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted-filename-data: %w", err)
	}
	// BROKEN: encryptedFilenameBytes, err := base64.StdEncoding.DecodeString(*encryptedFilenameData)
	// encryptedFilenameBytes := []byte(*encryptedFilenameData)

	sha256sumNonceBytes, err := base64.StdEncoding.DecodeString(*sha256sumNonce)
	if err != nil {
		if debugLogging {
			logVerbose("Base64 decode failed for sha256sum-nonce: %v", err)
			logVerbose("Raw sha256sum-nonce input: '%s' (length: %d)", *sha256sumNonce, len(*sha256sumNonce))
		}
		return fmt.Errorf("failed to decode sha256sum-nonce: %w", err)
	}

	encryptedSha256sumBytes, err := base64.StdEncoding.DecodeString(*encryptedSha256sumData)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted-sha256sum-data: %w", err)
	}
	// BROKEN: encryptedSha256sumBytes, err := base64.StdEncoding.DecodeString(*encryptedSha256sumData)
	// encryptedSha256sumBytes := []byte(*encryptedSha256sumData)

	if debugLogging {
		logVerbose("filenameNonceBytes length: %d bytes", len(filenameNonceBytes))
		logVerbose("encryptedFilenameBytes length: %d bytes", len(encryptedFilenameBytes))
		logVerbose("sha256sumNonceBytes length: %d bytes", len(sha256sumNonceBytes))
		logVerbose("encryptedSha256sumBytes length: %d bytes", len(encryptedSha256sumBytes))
		logVerbose("=== CALLING CRYPTO.DECRYPTFILEMETADATA ===")
		logVerbose("Function parameters:")
		logVerbose("  filenameNonce: %d bytes", len(filenameNonceBytes))
		logVerbose("  encryptedFilename: %d bytes", len(encryptedFilenameBytes))
		logVerbose("  sha256sumNonce: %d bytes", len(sha256sumNonceBytes))
		logVerbose("  encryptedSha256sum: %d bytes", len(encryptedSha256sumBytes))
		logVerbose("  password: %d chars (redacted)", len(password))
		logVerbose("  username: '%s'", *username)
	}

	// Derive metadata key directly from password (account key type)
	// Metadata always uses the account password key derivation
	metadataKey := crypto.DeriveAccountPasswordKey(password, *username)

	// Decrypt filename using the fixed function
	decryptedFilenameBytes, err := crypto.DecryptMetadataWithDerivedKey(metadataKey, filenameNonceBytes, encryptedFilenameBytes)
	if err != nil {
		if debugLogging {
			logVerbose("crypto.DecryptMetadataWithDerivedKey failed for filename: %v", err)
		}
		return fmt.Errorf("filename decryption failed: %w", err)
	}

	// Decrypt SHA256 using the fixed function
	decryptedSha256Bytes, err := crypto.DecryptMetadataWithDerivedKey(metadataKey, sha256sumNonceBytes, encryptedSha256sumBytes)
	if err != nil {
		if debugLogging {
			logVerbose("crypto.DecryptMetadataWithDerivedKey failed for SHA256: %v", err)
		}
		return fmt.Errorf("SHA256 decryption failed: %w", err)
	}

	// Convert to strings
	decryptedFilename := string(decryptedFilenameBytes)
	decryptedSha256sum := string(decryptedSha256Bytes)
	if err != nil {
		if debugLogging {
			logVerbose("crypto.DecryptFileMetadata failed: %v", err)
			logVerbose("This indicates either:")
			logVerbose("  1. Wrong password for key derivation")
			logVerbose("  2. Corrupted/invalid encrypted data")
			logVerbose("  3. Username mismatch in salt generation")
			logVerbose("  4. Data format incompatibility")
		}
		return fmt.Errorf("metadata decryption failed: %w", err)
	}

	if debugLogging {
		logVerbose("=== DECRYPTION SUCCESSFUL ===")
		logVerbose("Decrypted filename: '%s' (length: %d)", decryptedFilename, len(decryptedFilename))
		logVerbose("Decrypted SHA256: '%s' (length: %d)", decryptedSha256sum, len(decryptedSha256sum))
		logVerbose("=== CRYPTOCLI DECRYPT-METADATA COMPLETED SUCCESSFULLY ===")
	}

	// Print results
	fmt.Printf("Decrypted Filename: %s\n", decryptedFilename)
	fmt.Printf("Decrypted SHA256: %s\n", decryptedSha256sum)

	return nil
}

// handleEncryptFEKCommand processes the encrypt-fek command
func handleEncryptFEKCommand(args []string) error {
	fs := flag.NewFlagSet("encrypt-fek", flag.ExitOnError)
	var (
		fekHex         = fs.String("fek", "", "File Encryption Key in hex format (required)")
		username       = fs.String("username", "", "Username for salt generation (required)")
		passwordSource = fs.String("password-source", "prompt", "Password source: prompt or stdin")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli encrypt-fek [FLAGS]

Encrypts a File Encryption Key (FEK) using a password-derived key.
The FEK is encrypted with the account password key derivation.

FLAGS:
    --fek HEX              File Encryption Key in hex format (required)
    --username USER        Username for salt generation (required)
    --password-source SRC  Password source: prompt or stdin (default: prompt)
    --help                 Show this help message

EXAMPLE:
    cryptocli encrypt-fek --fek "abc123..." --username "alice"
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *fekHex == "" || *username == "" {
		fs.Usage()
		return fmt.Errorf("fek and username are required")
	}

	// Decode FEK from hex
	fek, err := hex.DecodeString(*fekHex)
	if err != nil {
		return fmt.Errorf("failed to decode FEK from hex: %w", err)
	}

	// Validate FEK length (should be 32 bytes for AES-256)
	if len(fek) != 32 {
		return fmt.Errorf("FEK must be 32 bytes (256 bits) for AES-256, got %d bytes", len(fek))
	}

	// Read password
	var password []byte
	if *passwordSource == "stdin" {
		reader := bufio.NewReader(os.Stdin)
		passwordStr, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read password from stdin: %w", err)
		}
		password = []byte(strings.TrimSpace(passwordStr))
	} else {
		password, err = readPassword(fmt.Sprintf("Enter password for user '%s' to encrypt FEK: ", *username))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	// Derive key for FEK encryption using account password derivation
	encryptionKey := crypto.DeriveAccountPasswordKey(password, *username)
	logVerbose("Derived FEK encryption key using account password derivation for user: %s", *username)

	// Encrypt FEK
	encryptedFEK, err := crypto.EncryptGCM(fek, encryptionKey)
	if err != nil {
		return fmt.Errorf("FEK encryption failed: %w", err)
	}

	// Print result
	fmt.Printf("FEK encrypted successfully\n")
	fmt.Printf("Encrypted FEK (base64): %s\n", base64.StdEncoding.EncodeToString(encryptedFEK))

	return nil
}

// handleDecryptFEKCommand processes the decrypt-fek command
func handleDecryptFEKCommand(args []string) error {
	fs := flag.NewFlagSet("decrypt-fek", flag.ExitOnError)
	var (
		encryptedFEK   = fs.String("encrypted-fek", "", "Base64 encoded encrypted FEK (required)")
		username       = fs.String("username", "", "Username for salt generation (required)")
		passwordSource = fs.String("password-source", "prompt", "Password source: prompt or stdin")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli decrypt-fek [FLAGS]

Decrypts a File Encryption Key (FEK) using a password-derived key.
The FEK is decrypted with the account password key derivation.

FLAGS:
    --encrypted-fek B64    Base64 encoded encrypted FEK (required)
    --username USER        Username for salt generation (required)
    --password-source SRC  Password source: prompt or stdin (default: prompt)
    --help                 Show this help message

EXAMPLE:
    cryptocli decrypt-fek --encrypted-fek "..." --username "alice"
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *encryptedFEK == "" || *username == "" {
		fs.Usage()
		return fmt.Errorf("encrypted-fek and username are required")
	}

	// Decode encrypted FEK from base64
	fekEnc, err := base64.StdEncoding.DecodeString(*encryptedFEK)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted FEK: %w", err)
	}

	// Read password
	var password []byte
	if *passwordSource == "stdin" {
		reader := bufio.NewReader(os.Stdin)
		passwordStr, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read password from stdin: %w", err)
		}
		password = []byte(strings.TrimSpace(passwordStr))
	} else {
		password, err = readPassword(fmt.Sprintf("Enter password for user '%s' to decrypt FEK: ", *username))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	// Derive key for FEK decryption using account password derivation
	decryptionKey := crypto.DeriveAccountPasswordKey(password, *username)
	logVerbose("Derived FEK decryption key using account password derivation for user: %s", *username)

	// Decrypt FEK
	fekBytes, err := crypto.DecryptGCM(fekEnc, decryptionKey)
	if err != nil {
		return fmt.Errorf("FEK decryption failed: %w", err)
	}

	// Validate FEK length
	if len(fekBytes) != 32 {
		return fmt.Errorf("decrypted FEK must be 32 bytes (256 bits) for AES-256, got %d bytes", len(fekBytes))
	}

	// Print result
	fmt.Printf("FEK decrypted successfully\n")
	fmt.Printf("Decrypted FEK (hex): %s\n", hex.EncodeToString(fekBytes))

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

func readPassword(prompt string) ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print(prompt)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Println() // Print newline after password input
		return password, nil
	} else {
		// Fallback for non-terminal input
		reader := bufio.NewReader(os.Stdin)
		passwordStr, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		return []byte(strings.TrimSpace(passwordStr)), nil
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
