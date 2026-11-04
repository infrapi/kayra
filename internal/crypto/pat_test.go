package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
)

func TestPatEnvelopeRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	record := PatRecord{
		UserID: "jdoe", Authorization: "idm", Provider: "okta", CreatedAt: 1234,
		SnapshotGroups:     []string{"sandbox-core-sysadmin"},
		SnapshotAttributes: map[string]string{"email": "jdoe@example.com"},
	}

	data, err := EncryptRecord(&priv.PublicKey, record)
	if err != nil {
		t.Fatalf("EncryptRecord: %v", err)
	}

	got, err := DecryptRecord(priv, data)
	if err != nil {
		t.Fatalf("DecryptRecord: %v", err)
	}
	if !reflect.DeepEqual(got, record) {
		t.Fatalf("DecryptRecord = %+v, want %+v", got, record)
	}
}

func TestPatEnvelopeTamperDetection(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	data, err := EncryptRecord(&priv.PublicKey, PatRecord{UserID: "jdoe"})
	if err != nil {
		t.Fatalf("EncryptRecord: %v", err)
	}

	tampered := append([]byte{}, data...)
	// flip a byte well inside the JSON ciphertext field.
	idx := len(tampered) / 2
	tampered[idx] ^= 0xFF

	if _, err := DecryptRecord(priv, tampered); err == nil {
		t.Fatalf("DecryptRecord: want error on tampered envelope")
	}
}

func TestGenerateTokenAndHash(t *testing.T) {
	tok, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if !IsToken(tok) {
		t.Fatalf("IsToken(%q) = false, want true", tok)
	}
	if IsToken("eyJhbGciOiJSUzI1NiJ9.notapat") {
		t.Fatalf("IsToken: a JWT-shaped string should not look like a PAT")
	}

	h1 := HashToken(tok)
	h2 := HashToken(tok)
	if h1 != h2 {
		t.Fatalf("HashToken not deterministic: %q vs %q", h1, h2)
	}

	tok2, _ := GenerateToken()
	if HashToken(tok2) == h1 {
		t.Fatalf("HashToken collided across two distinct tokens")
	}
}
