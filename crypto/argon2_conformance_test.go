package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type ConformanceVector struct {
	Password    string `json:"password"`
	SaltHex     string `json:"salt_hex"`
	MemoryKiB   uint32 `json:"m_kib"`
	Time        uint32 `json:"t"`
	Parallel    uint8  `json:"p"`
	KeyLen      uint32 `json:"dk"`
	ExpectedHex string `json:"expected_hex"`
}

func TestArgon2ConformanceFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/argon2-conformance-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector ConformanceVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	salt, err := hex.DecodeString(vector.SaltHex)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := DeriveArgon2IDKey(
		[]byte(vector.Password),
		salt,
		vector.KeyLen,
		vector.MemoryKiB,
		vector.Time,
		vector.Parallel,
	)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(derived) != vector.ExpectedHex {
		t.Fatal("Argon2id result does not match pinned fixture")
	}
}
