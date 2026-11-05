// Package crypto holds the two cryptographic concerns Kayra owns itself:
// the RSA keypair that encrypts personal access token records at rest, and
// loading the RSA signing keys the "self" authentication provider trusts.
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/store"
)

const patKeyBits = 2048

// LoadOrCreatePatKeypair resolves the RSA keypair used to encrypt PAT
// records. When cfg names files on disk, those are read; otherwise a
// keypair is generated once and persisted under s at the default location,
// so later starts reuse it instead of orphaning existing PAT records.
func LoadOrCreatePatKeypair(s store.Store, keys store.Keys, cfg config.PatConfig) (*rsa.PrivateKey, error) {
	if cfg.PrivateKeyPath != "" {
		return loadPrivateKeyFile(cfg.PrivateKeyPath)
	}

	key := keys.PatKeypair()

	data, err := s.Get(key)
	if err == nil {
		return decodePrivateKeyPEM(data)
	}
	if err != store.ErrNotFound {
		return nil, fmt.Errorf("pat keypair: read from store: %w", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, patKeyBits)
	if err != nil {
		return nil, fmt.Errorf("pat keypair: generate: %w", err)
	}

	pemBytes := encodePrivateKeyPEM(priv)
	if err := s.Put(key, pemBytes); err != nil {
		return nil, fmt.Errorf("pat keypair: persist: %w", err)
	}

	return priv, nil
}

func encodePrivateKeyPEM(priv *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
}

func decodePrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pat keypair: no PEM block found")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pat keypair: parse PKCS1 key: %w", err)
	}
	return priv, nil
}

func loadPrivateKeyFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- path is the operator's own config.PatConfig.PrivateKeyPath, never attacker input
	if err != nil {
		return nil, fmt.Errorf("pat keypair: read %s: %w", path, err)
	}
	return decodePrivateKeyPEM(data)
}
