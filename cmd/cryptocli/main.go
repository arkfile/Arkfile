// cryptocli - Offline cryptographic operations for arkfile
// This tool works completely offline using existing arkfile crypto infrastructure
// SECURITY: FEK (File Encryption Key) is NEVER exposed as raw hex in any command

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/84adam/Arkfile/crypto"
	"golang.org/x/term"
)

const (
	Version = "3.0.0-secure"
	Usage   = `cryptocli - Offline cryptographic operations for arkfile

USAGE:
    cryptocli [global options] command [command options] [arguments...]

FILE ENCRYPTION COMMANDS:
    encrypt-file          Encrypt a file (generates FEK internally, never exposed)
    decrypt-file          Decrypt a file using encrypted FEK from metadata

METADATA COMMANDS:
    encrypt-metadata      Encrypt file metadata (filename, hash)
    decrypt-metadata      Decrypt file metadata (filename, hash)

SHARE COMMANDS:
    create-share          Create a share envelope from owner's encrypted FEK
    decrypt-share         Decrypt a shared file using share envelope
    generate-share-id     Generate a cryptographically secure share ID

UTILITY COMMANDS:
    hash                  Calculate SHA-256 hash of files
    generate-key          Generate random AES keys
    generate-test-file    Generate test files with deterministic patterns
    version               Show version information

GLOBAL OPTIONS:
    --verbose, -v         Verbose output
    --help, -h            Show help

KEY TYPES:
    account               Account password-derived encryption (default)
    custom                Custom password-derived encryption

SECURITY:
    The FEK (File Encryption Key) is NEVER exposed as raw hex.
    All FEK operations happen internally within cryptocli.

EXAMPLES:
    # Encrypt file for upload (FEK generated internally)
    cryptocli encrypt-file --file document.pdf --username alice

    # Decrypt file after download
    cryptocli decrypt-file --file document.pdf.enc --encrypted-fek "..." --username alice

    # Create share (FEK decrypted and re-encrypted internally)
    cryptocli create-share --encrypted-fek "..." --username alice --file-id "..."

    # Decrypt shared file
    cryptocli decrypt-share --file shared.enc --encrypted-envelope "..." --salt "..." \
        --share-id "..." --file-id "..."
`
)

var verbose bool

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
	// File encryption commands (FEK never exposed)
	case "encrypt-file":
		if err := handleEncryptFileCommand(args); err != nil {
			logError("File encryption failed: %v", err)
			os.Exit(1)
		}
	case "decrypt-file":
		if err := handleDecryptFileCommand(args); err != nil {
			logError("File decryption failed: %v", err)
			os.Exit(1)
		}

	// Metadata commands
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

	// Share commands (FEK never exposed)
	case "create-share":
		if err := handleCreateShareCommand(args); err != nil {
			logError("Share creation failed: %v", err)
			os.Exit(1)
		}
	case "decrypt-share":
		if err := handleDecryptShareCommand(args); err != nil {
			logError("Share decryption failed: %v", err)
			os.Exit(1)
		}
	case "generate-share-id":
		if err := handleGenerateShareIDCommand(args); err != nil {
			logError("Share ID generation failed: %v", err)
			os.Exit(1)
		}

	// Utility commands
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

// =============================================================================
// FILE ENCRYPTION COMMANDS (FEK NEVER EXPOSED)
// =============================================================================

// EncryptFileResult is the JSON output from encrypt-file command
type EncryptFileResult struct {
	EncryptedFile string `json:"encrypted_file"`
	OriginalSize  int64  `json:"original_size"`
	EncryptedSize int64  `json:"encrypted_size"`
	EncryptedFEK  string `json:"encrypted_fek"`
	FileSHA256    string `json:"file_sha256"`
	KeyType       string `json:"key_type"`
}

// handleEncryptFileCommand encrypts a file with internally generated FEK
func handleEncryptFileCommand(args []string) error {
	fs := flag.NewFlagSet("encrypt-file", flag.ExitOnError)
	var (
		filePath       = fs.String("file", "", "File to encrypt (required)")
		username       = fs.String("username", "", "Username for FEK encryption (required)")
		keyType        = fs.String("key-type", "account", "Key type: account or custom")
		outputPath     = fs.String("output", "", "Output file path (optional, defaults to input.enc)")
		passwordSource = fs.String("password-source", "prompt", "Password source: prompt or stdin")
		jsonOutput     = fs.Bool("json", true, "Output result as JSON (default: true)")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli encrypt-file [FLAGS]

Encrypt a file for upload. This command:
1. Generates a random 32-byte FEK internally (never exposed)
2. Encrypts the file with the FEK using AES-256-GCM
3. Encrypts the FEK with your password (Owner Envelope)
4. Calculates the original file's SHA-256 hash

FLAGS:
    --file FILE            File to encrypt (required)
    --username USER        Username for FEK encryption (required)
    --key-type TYPE        Key type: account or custom (default: account)
    --output FILE          Output file path (optional, defaults to input.enc)
    --password-source SRC  Password source: prompt or stdin (default: prompt)
    --json                 Output result as JSON (default: true)
    --help                 Show this help message

OUTPUT (JSON):
    encrypted_file   - Path to encrypted file
    original_size    - Original file size in bytes
    encrypted_size   - Encrypted file size in bytes
    encrypted_fek    - Base64 encoded encrypted FEK (Owner Envelope)
    file_sha256      - SHA-256 hash of original file
    key_type         - Key type used (account or custom)

EXAMPLES:
    cryptocli encrypt-file --file document.pdf --username alice
    cryptocli encrypt-file --file data.bin --username bob --key-type custom
    echo "mypassword" | cryptocli encrypt-file --file doc.pdf --username alice --password-source stdin
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		return fmt.Errorf("file path is required (use --file)")
	}
	if *username == "" {
		return fmt.Errorf("username is required (use --username)")
	}

	if *keyType != "account" && *keyType != "custom" {
		return fmt.Errorf("key type must be 'account' or 'custom'")
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
		password, err = readPassword(fmt.Sprintf("Enter %s password for user '%s': ", *keyType, *username))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}
	defer clearBytes(password)

	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	// Calculate original file hash before encryption
	originalHash, err := crypto.CalculateFileHashFromPath(*filePath)
	if err != nil {
		return fmt.Errorf("failed to calculate file hash: %w", err)
	}

	// Determine output path
	outputFilePath := getOutputPath(*filePath, *outputPath)

	// Perform complete workflow (FEK generated and encrypted internally)
	encryptedFEK, _, err := crypto.EncryptFileWorkflow(*filePath, outputFilePath, password, *username, *keyType)
	if err != nil {
		return fmt.Errorf("encryption workflow failed: %w", err)
	}

	// Get file info
	inputInfo, err := os.Stat(*filePath)
	if err != nil {
		return fmt.Errorf("failed to get input file info: %w", err)
	}

	outputInfo, err := os.Stat(outputFilePath)
	if err != nil {
		return fmt.Errorf("failed to get output file info: %w", err)
	}

	// Output result
	result := EncryptFileResult{
		EncryptedFile: outputFilePath,
		OriginalSize:  inputInfo.Size(),
		EncryptedSize: outputInfo.Size(),
		EncryptedFEK:  base64.StdEncoding.EncodeToString(encryptedFEK),
		FileSHA256:    originalHash,
		KeyType:       *keyType,
	}

	if *jsonOutput {
		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonBytes))
	} else {
		fmt.Printf("File encryption completed successfully\n")
		fmt.Printf("Encrypted file: %s\n", result.EncryptedFile)
		fmt.Printf("Original size: %d bytes\n", result.OriginalSize)
		fmt.Printf("Encrypted size: %d bytes\n", result.EncryptedSize)
		fmt.Printf("Encrypted FEK: %s\n", result.EncryptedFEK)
		fmt.Printf("File SHA-256: %s\n", result.FileSHA256)
		fmt.Printf("Key type: %s\n", result.KeyType)
	}

	logVerbose("FEK-based encryption completed (FEK never exposed)")

	return nil
}

// handleDecryptFileCommand decrypts a file using encrypted FEK from metadata
func handleDecryptFileCommand(args []string) error {
	fs := flag.NewFlagSet("decrypt-file", flag.ExitOnError)
	var (
		filePath       = fs.String("file", "", "File to decrypt (required)")
		encryptedFEK   = fs.String("encrypted-fek", "", "Base64 encoded encrypted FEK from metadata (required)")
		username       = fs.String("username", "", "Username for FEK decryption (required)")
		outputPath     = fs.String("output", "", "Output file path (optional)")
		passwordSource = fs.String("password-source", "prompt", "Password source: prompt or stdin")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli decrypt-file [FLAGS]

Decrypt a file using the encrypted FEK from metadata. This command:
1. Decrypts the FEK from the Owner Envelope using your password
2. Decrypts the file using the FEK
3. The FEK is never exposed - it stays in memory only

FLAGS:
    --file FILE            File to decrypt (required)
    --encrypted-fek B64    Base64 encoded encrypted FEK from metadata (required)
    --username USER        Username for FEK decryption (required)
    --output FILE          Output file path (optional, defaults to input without .enc)
    --password-source SRC  Password source: prompt or stdin (default: prompt)
    --help                 Show this help message

EXAMPLES:
    cryptocli decrypt-file --file document.pdf.enc --encrypted-fek "..." --username alice
    cryptocli decrypt-file --file data.enc --encrypted-fek "..." --username bob --output data.bin
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		return fmt.Errorf("file path is required (use --file)")
	}
	if *encryptedFEK == "" {
		return fmt.Errorf("encrypted FEK is required (use --encrypted-fek)")
	}
	if *username == "" {
		return fmt.Errorf("username is required (use --username)")
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
		password, err = readPassword(fmt.Sprintf("Enter password for user '%s': ", *username))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}
	defer clearBytes(password)

	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	// Decrypt FEK from Owner Envelope (FEK stays in memory only)
	fek, keyType, err := crypto.DecryptFEK(fekEnc, password, *username)
	if err != nil {
		return fmt.Errorf("FEK decryption failed (wrong password?): %w", err)
	}
	defer clearBytes(fek)

	logVerbose("FEK decrypted successfully (key type: %s)", keyType)

	// Determine output path
	outputFilePath := *outputPath
	if outputFilePath == "" {
		if strings.HasSuffix(*filePath, ".enc") {
			outputFilePath = strings.TrimSuffix(*filePath, ".enc")
		} else {
			outputFilePath = *filePath + ".dec"
		}
	}

	// Decrypt file using FEK (FEK never leaves this process)
	if err := crypto.DecryptFileFromPath(*filePath, outputFilePath, fek); err != nil {
		return fmt.Errorf("file decryption failed: %w", err)
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

	fmt.Printf("File decryption completed successfully\n")
	fmt.Printf("Input file: %s (%d bytes)\n", *filePath, inputInfo.Size())
	fmt.Printf("Output file: %s (%d bytes)\n", outputFilePath, outputInfo.Size())

	return nil
}

// =============================================================================
// METADATA COMMANDS
// =============================================================================

// handleEncryptMetadataCommand encrypts file metadata
func handleEncryptMetadataCommand(args []string) error {
	fs := flag.NewFlagSet("encrypt-metadata", flag.ExitOnError)
	var (
		filename       = fs.String("filename", "", "Filename to encrypt (required)")
		sha256sum      = fs.String("sha256sum", "", "SHA256 hash to encrypt (required)")
		username       = fs.String("username", "", "Username for salt generation (required)")
		passwordSource = fs.String("password-source", "prompt", "Password source: prompt or stdin")
		jsonOutput     = fs.Bool("json", false, "Output as JSON")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli encrypt-metadata [FLAGS]

Encrypt file metadata (filename, SHA256 hash) using a password-derived key.
Outputs separate nonce and encrypted data fields for server API compatibility.

FLAGS:
    --filename FILE         Filename to encrypt (required)
    --sha256sum HASH        SHA256 hash to encrypt (required)
    --username USER         Username for salt generation (required)
    --password-source SRC   Password source: prompt or stdin (default: prompt)
    --json                  Output as JSON
    --help                  Show this help message

EXAMPLES:
    cryptocli encrypt-metadata --filename "document.pdf" --sha256sum "abc123..." --username alice
    cryptocli encrypt-metadata --filename "doc.pdf" --sha256sum "..." --username alice --json
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
		password, err = readPassword(fmt.Sprintf("Enter password for user '%s': ", *username))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}
	defer clearBytes(password)

	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	// Derive metadata key (always uses account password derivation)
	metadataKey := crypto.DeriveAccountPasswordKey(password, *username)

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

	// Extract nonce and data separately (GCM format: [12-byte nonce][encrypted data + 16-byte tag])
	if len(encryptedFilename) < 12 || len(encryptedSha256) < 12 {
		return fmt.Errorf("encrypted data too short")
	}

	filenameNonce := encryptedFilename[:12]
	filenameData := encryptedFilename[12:]
	sha256Nonce := encryptedSha256[:12]
	sha256Data := encryptedSha256[12:]

	if *jsonOutput {
		result := map[string]string{
			"filename_nonce":      base64.StdEncoding.EncodeToString(filenameNonce),
			"encrypted_filename":  base64.StdEncoding.EncodeToString(filenameData),
			"sha256sum_nonce":     base64.StdEncoding.EncodeToString(sha256Nonce),
			"encrypted_sha256sum": base64.StdEncoding.EncodeToString(sha256Data),
		}
		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonBytes))
	} else {
		fmt.Printf("Metadata encrypted successfully\n")
		fmt.Printf("Filename Nonce: %s\n", base64.StdEncoding.EncodeToString(filenameNonce))
		fmt.Printf("Encrypted Filename: %s\n", base64.StdEncoding.EncodeToString(filenameData))
		fmt.Printf("SHA256 Nonce: %s\n", base64.StdEncoding.EncodeToString(sha256Nonce))
		fmt.Printf("Encrypted SHA256: %s\n", base64.StdEncoding.EncodeToString(sha256Data))
	}

	return nil
}

// handleDecryptMetadataCommand decrypts file metadata
func handleDecryptMetadataCommand(args []string) error {
	fs := flag.NewFlagSet("decrypt-metadata", flag.ExitOnError)
	var (
		filenameNonce          = fs.String("filename-nonce", "", "Base64 encoded filename nonce (required)")
		encryptedFilenameData  = fs.String("encrypted-filename", "", "Base64 encoded encrypted filename (required)")
		sha256sumNonce         = fs.String("sha256sum-nonce", "", "Base64 encoded SHA256 nonce (required)")
		encryptedSha256sumData = fs.String("encrypted-sha256sum", "", "Base64 encoded encrypted SHA256 (required)")
		username               = fs.String("username", "", "Username for salt generation (required)")
		passwordSource         = fs.String("password-source", "prompt", "Password source: prompt or stdin")
		jsonOutput             = fs.Bool("json", false, "Output as JSON")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli decrypt-metadata [FLAGS]

Decrypt file metadata (filename, SHA256 hash) using a password-derived key.

FLAGS:
    --filename-nonce DATA       Base64 encoded filename nonce (required)
    --encrypted-filename DATA   Base64 encoded encrypted filename (required)
    --sha256sum-nonce DATA      Base64 encoded SHA256 nonce (required)
    --encrypted-sha256sum DATA  Base64 encoded encrypted SHA256 (required)
    --username USER             Username for salt generation (required)
    --password-source SRC       Password source: prompt or stdin (default: prompt)
    --json                      Output as JSON
    --help                      Show this help message

EXAMPLES:
    cryptocli decrypt-metadata \
        --filename-nonce "..." --encrypted-filename "..." \
        --sha256sum-nonce "..." --encrypted-sha256sum "..." \
        --username alice
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filenameNonce == "" || *encryptedFilenameData == "" ||
		*sha256sumNonce == "" || *encryptedSha256sumData == "" || *username == "" {
		fs.Usage()
		return fmt.Errorf("all parameters are required")
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
		password, err = readPassword(fmt.Sprintf("Enter password for user '%s': ", *username))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}
	defer clearBytes(password)

	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	// Decode base64 inputs
	filenameNonceBytes, err := base64.StdEncoding.DecodeString(*filenameNonce)
	if err != nil {
		return fmt.Errorf("failed to decode filename-nonce: %w", err)
	}

	encryptedFilenameBytes, err := base64.StdEncoding.DecodeString(*encryptedFilenameData)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted-filename: %w", err)
	}

	sha256sumNonceBytes, err := base64.StdEncoding.DecodeString(*sha256sumNonce)
	if err != nil {
		return fmt.Errorf("failed to decode sha256sum-nonce: %w", err)
	}

	encryptedSha256sumBytes, err := base64.StdEncoding.DecodeString(*encryptedSha256sumData)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted-sha256sum: %w", err)
	}

	// Derive metadata key
	metadataKey := crypto.DeriveAccountPasswordKey(password, *username)

	// Decrypt filename
	decryptedFilename, err := crypto.DecryptMetadataWithDerivedKey(metadataKey, filenameNonceBytes, encryptedFilenameBytes)
	if err != nil {
		return fmt.Errorf("filename decryption failed: %w", err)
	}

	// Decrypt SHA256
	decryptedSha256, err := crypto.DecryptMetadataWithDerivedKey(metadataKey, sha256sumNonceBytes, encryptedSha256sumBytes)
	if err != nil {
		return fmt.Errorf("SHA256 decryption failed: %w", err)
	}

	if *jsonOutput {
		result := map[string]string{
			"filename": string(decryptedFilename),
			"sha256":   string(decryptedSha256),
		}
		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonBytes))
	} else {
		fmt.Printf("Decrypted Filename: %s\n", string(decryptedFilename))
		fmt.Printf("Decrypted SHA256: %s\n", string(decryptedSha256))
	}

	return nil
}

// =============================================================================
// SHARE COMMANDS (FEK NEVER EXPOSED)
// =============================================================================

// CreateShareResult is the JSON output from create-share command
type CreateShareResult struct {
	ShareID           string `json:"share_id"`
	EncryptedEnvelope string `json:"encrypted_envelope"`
	Salt              string `json:"salt"`
	DownloadToken     string `json:"download_token"`
	DownloadTokenHash string `json:"download_token_hash"`
}

// handleCreateShareCommand creates a share envelope from owner's encrypted FEK
func handleCreateShareCommand(args []string) error {
	fs := flag.NewFlagSet("create-share", flag.ExitOnError)
	var (
		encryptedFEK   = fs.String("encrypted-fek", "", "Base64 encoded encrypted FEK from metadata (required)")
		username       = fs.String("username", "", "Username for FEK decryption (required)")
		fileID         = fs.String("file-id", "", "File ID for AAD binding (required)")
		passwordSource = fs.String("password-source", "prompt", "Password source: prompt or stdin")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli create-share [FLAGS]

Create a share envelope from the owner's encrypted FEK. This command:
1. Decrypts the FEK from the Owner Envelope using your password
2. Generates a new share ID
3. Prompts for a share password
4. Re-encrypts the FEK with the share password and AAD binding
5. Generates a download token

The FEK is NEVER exposed - it stays in memory only.

FLAGS:
    --encrypted-fek B64    Base64 encoded encrypted FEK from metadata (required)
    --username USER        Username for FEK decryption (required)
    --file-id ID           File ID for AAD binding (required)
    --password-source SRC  Password source: prompt or stdin (default: prompt)
                           When stdin, provide: owner_password\nshare_password\n
    --help                 Show this help message

OUTPUT (JSON):
    share_id            - Generated share ID (43 chars, base64url)
    encrypted_envelope  - Base64 encoded encrypted FEK for share
    salt                - Base64 encoded salt for share key derivation
    download_token      - Base64 encoded download token for recipient
    download_token_hash - Base64 encoded hash of download token (for server)

EXAMPLES:
    cryptocli create-share --encrypted-fek "..." --username alice --file-id "abc123"
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *encryptedFEK == "" {
		return fmt.Errorf("encrypted FEK is required (use --encrypted-fek)")
	}
	if *username == "" {
		return fmt.Errorf("username is required (use --username)")
	}
	if *fileID == "" {
		return fmt.Errorf("file ID is required (use --file-id)")
	}

	// Decode encrypted FEK from base64
	fekEnc, err := base64.StdEncoding.DecodeString(*encryptedFEK)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted FEK: %w", err)
	}

	var ownerPassword, sharePassword []byte

	if *passwordSource == "stdin" {
		reader := bufio.NewReader(os.Stdin)

		// Read owner password (first line)
		ownerPasswordStr, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read owner password from stdin: %w", err)
		}
		ownerPassword = []byte(strings.TrimSpace(ownerPasswordStr))

		// Read share password (second line)
		sharePasswordStr, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read share password from stdin: %w", err)
		}
		sharePassword = []byte(strings.TrimSpace(sharePasswordStr))
	} else {
		// Prompt for owner password
		ownerPassword, err = readPassword(fmt.Sprintf("Enter password for user '%s' (to decrypt FEK): ", *username))
		if err != nil {
			return fmt.Errorf("failed to read owner password: %w", err)
		}

		// Prompt for share password
		sharePassword, err = readPassword("Enter share password (for recipient): ")
		if err != nil {
			clearBytes(ownerPassword)
			return fmt.Errorf("failed to read share password: %w", err)
		}

		// Confirm share password
		sharePasswordConfirm, err := readPassword("Confirm share password: ")
		if err != nil {
			clearBytes(ownerPassword)
			clearBytes(sharePassword)
			return fmt.Errorf("failed to read share password confirmation: %w", err)
		}

		if string(sharePassword) != string(sharePasswordConfirm) {
			clearBytes(ownerPassword)
			clearBytes(sharePassword)
			clearBytes(sharePasswordConfirm)
			return fmt.Errorf("share passwords do not match")
		}
		clearBytes(sharePasswordConfirm)
	}

	defer clearBytes(ownerPassword)
	defer clearBytes(sharePassword)

	if len(ownerPassword) == 0 {
		return fmt.Errorf("owner password cannot be empty")
	}
	if len(sharePassword) == 0 {
		return fmt.Errorf("share password cannot be empty")
	}

	// Step 1: Decrypt FEK from Owner Envelope (FEK stays in memory only)
	fek, _, err := crypto.DecryptFEK(fekEnc, ownerPassword, *username)
	if err != nil {
		return fmt.Errorf("FEK decryption failed (wrong password?): %w", err)
	}
	defer clearBytes(fek)

	logVerbose("FEK decrypted from Owner Envelope")

	// Step 2: Generate share ID (32 bytes, base64url encoded = 43 chars)
	shareIDBytes := crypto.GenerateRandomBytes(32)
	shareID := base64.RawURLEncoding.EncodeToString(shareIDBytes)

	logVerbose("Generated share ID: %s", shareID)

	// Step 3: Generate random salt (32 bytes)
	salt := crypto.GenerateRandomBytes(32)

	// Step 4: Derive share key using share password and salt
	shareKey, err := crypto.DeriveArgon2IDKey(
		sharePassword,
		salt,
		crypto.UnifiedArgonSecure.KeyLen,
		crypto.UnifiedArgonSecure.Memory,
		crypto.UnifiedArgonSecure.Time,
		crypto.UnifiedArgonSecure.Threads,
	)
	if err != nil {
		return fmt.Errorf("failed to derive share key: %w", err)
	}

	// Step 5: Create AAD: share_id || file_id
	aad := []byte(shareID + *fileID)

	// Step 6: Encrypt FEK with AAD binding
	encryptedEnvelope, err := crypto.EncryptGCMWithAAD(fek, shareKey, aad)
	if err != nil {
		return fmt.Errorf("FEK encryption with AAD failed: %w", err)
	}

	// Step 7: Generate download token
	downloadToken := crypto.GenerateRandomBytes(32)

	// Hash the download token
	hasher := sha256.New()
	hasher.Write(downloadToken)
	tokenHash := hasher.Sum(nil)

	// Output JSON result
	result := CreateShareResult{
		ShareID:           shareID,
		EncryptedEnvelope: base64.StdEncoding.EncodeToString(encryptedEnvelope),
		Salt:              base64.StdEncoding.EncodeToString(salt),
		DownloadToken:     base64.StdEncoding.EncodeToString(downloadToken),
		DownloadTokenHash: base64.StdEncoding.EncodeToString(tokenHash),
	}

	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonBytes))

	logVerbose("Share envelope created (FEK never exposed)")

	return nil
}

// handleDecryptShareCommand decrypts a shared file using share envelope
func handleDecryptShareCommand(args []string) error {
	fs := flag.NewFlagSet("decrypt-share", flag.ExitOnError)
	var (
		filePath          = fs.String("file", "", "Encrypted file to decrypt (required)")
		encryptedEnvelope = fs.String("encrypted-envelope", "", "Base64 encoded encrypted envelope (required)")
		salt              = fs.String("salt", "", "Base64 encoded salt (required)")
		shareID           = fs.String("share-id", "", "Share ID (43-char base64url, required)")
		fileID            = fs.String("file-id", "", "File ID for AAD verification (required)")
		outputPath        = fs.String("output", "", "Output file path (optional)")
		passwordSource    = fs.String("password-source", "prompt", "Password source: prompt or stdin")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli decrypt-share [FLAGS]

Decrypt a shared file using the share envelope. This command:
1. Derives the share key from the share password and salt
2. Decrypts the FEK from the share envelope with AAD verification
3. Decrypts the file using the FEK
4. The FEK is NEVER exposed - it stays in memory only

FLAGS:
    --file FILE               Encrypted file to decrypt (required)
    --encrypted-envelope B64  Base64 encoded encrypted envelope (required)
    --salt B64                Base64 encoded salt (required)
    --share-id ID             Share ID (43-char base64url, required)
    --file-id ID              File ID for AAD verification (required)
    --output FILE             Output file path (optional)
    --password-source SRC     Password source: prompt or stdin (default: prompt)
    --help                    Show this help message

EXAMPLES:
    cryptocli decrypt-share --file shared.enc \
        --encrypted-envelope "..." --salt "..." \
        --share-id "xyz..." --file-id "abc123"
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		return fmt.Errorf("file path is required (use --file)")
	}
	if *encryptedEnvelope == "" {
		return fmt.Errorf("encrypted envelope is required (use --encrypted-envelope)")
	}
	if *salt == "" {
		return fmt.Errorf("salt is required (use --salt)")
	}
	if *shareID == "" {
		return fmt.Errorf("share ID is required (use --share-id)")
	}
	if *fileID == "" {
		return fmt.Errorf("file ID is required (use --file-id)")
	}

	// Validate share ID format
	if len(*shareID) != 43 {
		return fmt.Errorf("share ID must be 43 characters (32 bytes base64url encoded), got %d", len(*shareID))
	}

	// Decode encrypted envelope
	envelopeEnc, err := base64.StdEncoding.DecodeString(*encryptedEnvelope)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted envelope: %w", err)
	}

	// Decode salt
	saltBytes, err := base64.StdEncoding.DecodeString(*salt)
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}

	// Read share password
	var password []byte
	if *passwordSource == "stdin" {
		reader := bufio.NewReader(os.Stdin)
		passwordStr, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read password from stdin: %w", err)
		}
		password = []byte(strings.TrimSpace(passwordStr))
	} else {
		password, err = readPassword("Enter share password: ")
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}
	defer clearBytes(password)

	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	// Step 1: Derive share key using share password and salt
	shareKey, err := crypto.DeriveArgon2IDKey(
		password,
		saltBytes,
		crypto.UnifiedArgonSecure.KeyLen,
		crypto.UnifiedArgonSecure.Memory,
		crypto.UnifiedArgonSecure.Time,
		crypto.UnifiedArgonSecure.Threads,
	)
	if err != nil {
		return fmt.Errorf("failed to derive share key: %w", err)
	}

	// Step 2: Create AAD: share_id || file_id
	aad := []byte(*shareID + *fileID)

	// Step 3: Decrypt FEK with AAD verification (FEK stays in memory only)
	fek, err := crypto.DecryptGCMWithAAD(envelopeEnc, shareKey, aad)
	if err != nil {
		return fmt.Errorf("share envelope decryption failed (wrong password or tampered data): %w", err)
	}
	defer clearBytes(fek)

	// Validate FEK length
	if len(fek) != 32 {
		return fmt.Errorf("decrypted FEK must be 32 bytes, got %d bytes", len(fek))
	}

	logVerbose("FEK decrypted from share envelope (AAD verified)")

	// Step 4: Determine output path
	outputFilePath := *outputPath
	if outputFilePath == "" {
		if strings.HasSuffix(*filePath, ".enc") {
			outputFilePath = strings.TrimSuffix(*filePath, ".enc")
		} else {
			outputFilePath = *filePath + ".dec"
		}
	}

	// Step 5: Decrypt file using FEK (FEK never leaves this process)
	if err := crypto.DecryptFileFromPath(*filePath, outputFilePath, fek); err != nil {
		return fmt.Errorf("file decryption failed: %w", err)
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

	fmt.Printf("Shared file decryption completed successfully\n")
	fmt.Printf("Input file: %s (%d bytes)\n", *filePath, inputInfo.Size())
	fmt.Printf("Output file: %s (%d bytes)\n", outputFilePath, outputInfo.Size())

	return nil
}

// handleGenerateShareIDCommand generates a cryptographically secure share ID
func handleGenerateShareIDCommand(args []string) error {
	fs := flag.NewFlagSet("generate-share-id", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli generate-share-id

Generate a cryptographically secure share ID (32 bytes, base64url encoded = 43 chars).
This ID is used to uniquely identify a share and is part of the AAD binding.

EXAMPLES:
    cryptocli generate-share-id
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Generate 32-byte random share ID
	shareIDBytes := crypto.GenerateRandomBytes(32)

	// Base64url encode (no padding)
	shareID := base64.RawURLEncoding.EncodeToString(shareIDBytes)

	fmt.Printf("%s\n", shareID)

	return nil
}

// =============================================================================
// UTILITY COMMANDS
// =============================================================================

// handleHashCommand calculates SHA-256 hash of a file
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
    --help              Show this help message

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

	// Calculate hash
	hashHex, err := crypto.CalculateFileHashFromPath(*filePath)
	if err != nil {
		return fmt.Errorf("failed to calculate hash: %w", err)
	}

	// Get file info
	fileInfo, err := os.Stat(*filePath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	// Output hash
	fmt.Printf("File: %s\n", *filePath)
	fmt.Printf("Size: %d bytes\n", fileInfo.Size())

	if *format == "hex" {
		fmt.Printf("SHA-256 (hex): %s\n", hashHex)
	} else {
		hashBytes, _ := hex.DecodeString(hashHex)
		fmt.Printf("SHA-256 (base64): %s\n", base64.StdEncoding.EncodeToString(hashBytes))
	}

	return nil
}

// handleGenerateKeyCommand generates a random key
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
    --help              Show this help message

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

// handleGenerateTestFileCommand generates a test file
func handleGenerateTestFileCommand(args []string) error {
	fs := flag.NewFlagSet("generate-test-file", flag.ExitOnError)
	var (
		filename = fs.String("filename", "", "Output filename (required)")
		size     = fs.Int64("size", 0, "File size in bytes (required)")
		pattern  = fs.String("pattern", "deterministic", "Pattern: deterministic, random, or zeros")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: cryptocli generate-test-file [FLAGS]

Generate test files with specified size and pattern.

FLAGS:
    --filename FILE     Output filename (required)
    --size SIZE         File size in bytes (required)
    --pattern TYPE      Pattern: deterministic, random, or zeros (default: deterministic)
    --help              Show this help message

EXAMPLES:
    cryptocli generate-test-file --filename test.bin --size 104857600
    cryptocli generate-test-file --filename random.bin --size 1048576 --pattern random
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
		return fmt.Errorf("size must not exceed 1GB")
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

	hashHex, err := crypto.GenerateTestFileToPath(*filename, *size, filePattern)
	if err != nil {
		return fmt.Errorf("failed to generate test file: %w", err)
	}

	fmt.Printf("Test file generated successfully\n")
	fmt.Printf("Filename: %s\n", *filename)
	fmt.Printf("Size: %d bytes\n", *size)
	fmt.Printf("Pattern: %s\n", *pattern)
	fmt.Printf("SHA-256: %s\n", hashHex)

	return nil
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func printVersion() {
	fmt.Printf("cryptocli version %s\n", Version)
	fmt.Printf("Secure cryptographic operations for arkfile (FEK never exposed)\n")
}

func printUsage() {
	fmt.Print(Usage)
}

func logVerbose(format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
	}
}

func logError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}

func readPassword(prompt string) ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Fprintln(os.Stderr)
		return password, nil
	} else {
		reader := bufio.NewReader(os.Stdin)
		passwordStr, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		return []byte(strings.TrimSpace(passwordStr)), nil
	}
}

func getOutputPath(inputPath, outputPath string) string {
	if outputPath != "" {
		return outputPath
	}

	if strings.HasSuffix(inputPath, ".enc") {
		return strings.TrimSuffix(inputPath, ".enc")
	}
	return inputPath + ".enc"
}

// clearBytes securely clears a byte slice
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
