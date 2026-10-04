// password_hint.go - Owner custom-password hint decryption and display.
// Hints are Account Key ciphertext in owner metadata and owner bundles only;
// they are display-only, never logged, and never part of an error string.

package main

import (
	"fmt"

	"github.com/arkfile/Arkfile/crypto"
)

type hintState int

const (
	hintAbsent hintState = iota
	hintPresent
	hintUndecryptable
)

// decryptPasswordHint returns the plaintext hint and whether it was absent,
// decrypted, or present but undecryptable. An empty decrypted hint counts as
// absent.
func decryptPasswordHint(ciphertext, nonce string, accountKey []byte, fileID, owner string) (string, hintState) {
	if ciphertext == "" || nonce == "" {
		return "", hintAbsent
	}
	hint, err := decryptMetadataField(ciphertext, nonce, accountKey, fileID, crypto.AADFieldPasswordHint, owner)
	if err != nil {
		return "", hintUndecryptable
	}
	if hint == "" {
		return "", hintAbsent
	}
	return hint, hintPresent
}

// formatPromptHint renders the hint for inclusion in a custom-password prompt.
func formatPromptHint(hint string, state hintState) string {
	switch state {
	case hintPresent:
		return fmt.Sprintf(" [hint: %s]", sanitizeDisplayText(hint))
	case hintUndecryptable:
		return " [hint could not be decrypted]"
	default:
		return ""
	}
}

// hintDisplayLine is the line decrypt-blob prints for a custom-password bundle
// before asking for its password.
func hintDisplayLine(hint string, state hintState) string {
	switch state {
	case hintPresent:
		return "Password hint: " + sanitizeDisplayText(hint)
	case hintUndecryptable:
		return "[!] WARNING: Password hint could not be decrypted"
	default:
		return "Password hint: (none saved)"
	}
}
