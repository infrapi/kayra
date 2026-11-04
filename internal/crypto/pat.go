package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// TokenPrefix marks an opaque personal access token, distinguishing it at a
// glance from a JWT (which always starts with an unprefixed base64url
// header). Kayra's bearer-auth middleware checks this prefix before
// trying to parse the credential as either kind.
const TokenPrefix = "pat_"

const tokenRandomBytes = 32

// PatRecord is what gets hybrid-encrypted and stored in etcd at
// Keys.PatToken(hash). It carries who the token belongs to and under
// which authorization backend: for an ldap/local backend, roles are
// always resolved live from the holder's current group membership,
// never snapshotted here. SnapshotGroups/SnapshotAttributes are the one
// exception, populated only when Authorization names a claims-backed
// backend (see config.ClaimsAuthzConfig): that backend has no directory
// to re-query later by bare user id — there is no live session left by
// the time this PAT gets used — so middleware.resolvePAT falls back to
// whatever tokenapi captured here at creation time instead. A token
// minted under any other backend leaves both nil; its roles stay live.
type PatRecord struct {
	UserID             string            `json:"user_id"`
	Authorization      string            `json:"authorization"`
	Provider           string            `json:"provider"`
	CreatedAt          int64             `json:"created_at"`
	SnapshotGroups     []string          `json:"snapshot_groups,omitempty"`
	SnapshotAttributes map[string]string `json:"snapshot_attributes,omitempty"`
}

// patEnvelope is the on-disk hybrid-encryption format: the AES-256 key is
// wrapped with RSA-OAEP, the record itself is sealed with AES-GCM under
// that key. Nobody holding only the etcd data (not the RSA private key) can
// recover the record.
type patEnvelope struct {
	EncryptedKey string `json:"encrypted_key"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

// GenerateToken returns a new opaque personal access token: TokenPrefix
// followed by 32 random bytes, base64url-encoded.
func GenerateToken() (string, error) {
	buf := make([]byte, tokenRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("pat: generate random bytes: %w", err)
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// IsToken reports whether s looks like an opaque personal access token
// rather than a JWT.
func IsToken(s string) bool {
	return len(s) > len(TokenPrefix) && s[:len(TokenPrefix)] == TokenPrefix
}

// HashToken returns the lookup key for token: its etcd record is addressed
// by this hash, never by the token value itself.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// EncryptRecord seals record for storage under pub.
func EncryptRecord(pub *rsa.PublicKey, record PatRecord) ([]byte, error) {
	plaintext, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("pat: marshal record: %w", err)
	}

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("pat: generate aes key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("pat: new aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("pat: new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("pat: generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("pat: wrap aes key: %w", err)
	}

	envelope := patEnvelope{
		EncryptedKey: base64.StdEncoding.EncodeToString(encryptedKey),
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("pat: marshal envelope: %w", err)
	}
	return data, nil
}

// DecryptRecord reverses EncryptRecord using priv.
func DecryptRecord(priv *rsa.PrivateKey, data []byte) (PatRecord, error) {
	var envelope patEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return PatRecord{}, fmt.Errorf("pat: unmarshal envelope: %w", err)
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(envelope.EncryptedKey)
	if err != nil {
		return PatRecord{}, fmt.Errorf("pat: decode encrypted key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return PatRecord{}, fmt.Errorf("pat: decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return PatRecord{}, fmt.Errorf("pat: decode ciphertext: %w", err)
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey, nil)
	if err != nil {
		return PatRecord{}, fmt.Errorf("pat: unwrap aes key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return PatRecord{}, fmt.Errorf("pat: new aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return PatRecord{}, fmt.Errorf("pat: new gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return PatRecord{}, fmt.Errorf("pat: decrypt: %w", err)
	}

	var record PatRecord
	if err := json.Unmarshal(plaintext, &record); err != nil {
		return PatRecord{}, fmt.Errorf("pat: unmarshal record: %w", err)
	}
	return record, nil
}
