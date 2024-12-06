package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "syscall/js"

    "golang.org/x/crypto/pbkdf2"
    "golang.org/x/crypto/sha3"
)

var (
    // Number of PBKDF2 iterations
    iterations = 500000
    /* Expected time to compute:
     * - 1250ms for an Intel Core i3-5005U 5th Gen 2-Core 2.0 GHz CPU
     * - 500ms for an Intel Core i5-8600T 8th Gen 6-core 3.70 GHz CPU
    */ 
    // Key length in bytes
    keyLength = 32
)

func main() {
    c := make(chan struct{})
    
    // Register JavaScript functions
    js.Global().Set("encryptFile", js.FuncOf(encryptFile))
    js.Global().Set("decryptFile", js.FuncOf(decryptFile))
    js.Global().Set("generateSalt", js.FuncOf(generateSalt))
    
    // Keep the Go program running
    <-c
}

func encryptFile(this js.Value, args []js.Value) interface{} {
    if len(args) != 2 {
        return "Invalid number of arguments"
    }

    data := make([]byte, args[0].Length())
    js.CopyBytesToGo(data, args[0])
    password := args[1].String()

    // Generate salt
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return "Failed to generate salt"
    }

    // Derive key from password
    key := pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha3.New256)

    // Create cipher block
    block, err := aes.NewCipher(key)
    if err != nil {
        return "Failed to create cipher block"
    }

    // Create GCM mode
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "Failed to create GCM"
    }

    // Generate nonce
    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return "Failed to generate nonce"
    }

    // Encrypt data
    ciphertext := gcm.Seal(nonce, nonce, data, nil)

    // Combine salt and ciphertext
    result := append(salt, ciphertext...)

    // Return base64 encoded result
    return base64.StdEncoding.EncodeToString(result)
}

func decryptFile(this js.Value, args []js.Value) interface{} {
    if len(args) != 2 {
        return "Invalid number of arguments"
    }

    encodedData := args[0].String()
    password := args[1].String()

    // Decode base64
    data, err := base64.StdEncoding.DecodeString(encodedData)
    if err != nil {
        return "Failed to decode data"
    }

    // Extract salt (first 16 bytes)
    salt := data[:16]
    data = data[16:]

    // Derive key from password
    key := pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha3.New256)

    // Create cipher block
    block, err := aes.NewCipher(key)
    if err != nil {
        return "Failed to create cipher block"
    }

    // Create GCM mode
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "Failed to create GCM"
    }

    // Extract nonce and ciphertext
    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return "Data too short"
    }

    nonce := data[:nonceSize]
    ciphertext := data[nonceSize:]

    // Decrypt data
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "Failed to decrypt data"
    }

    // Return base64 encoded plaintext
    return base64.StdEncoding.EncodeToString(plaintext)
}

func generateSalt(this js.Value, args []js.Value) interface{} {
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return "Failed to generate salt"
    }
    return base64.StdEncoding.EncodeToString(salt)
}
