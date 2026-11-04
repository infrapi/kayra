package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/infrapi/kayra/internal/config"
)

// SigningKey is one decoded RSA key a "local:" authentication provider
// (e.g. "self") trusts, keyed by kid.
type SigningKey struct {
	Kid       string
	Algorithm string
	Issuer    bool
	Expiry    int
	Audiences []string
	Private   *rsa.PrivateKey // non-nil only when the PEM held a private key
	Public    *rsa.PublicKey
}

// LoadSigningKeys decodes every entry of a provider's local: list. Secret
// may be a PEM RSA private key (signing + verification) or a PEM RSA public
// key (verification only, for a key this instance trusts but never issues
// with).
func LoadSigningKeys(entries []config.LocalSigningKey) ([]SigningKey, error) {
	keys := make([]SigningKey, 0, len(entries))
	for _, entry := range entries {
		if !entry.Enabled {
			continue
		}

		key := SigningKey{
			Kid:       entry.Kid,
			Algorithm: entry.Algorithm,
			Issuer:    entry.Issuer,
			Expiry:    entry.Expiry,
			Audiences: entry.Audiences,
		}

		block, _ := pem.Decode([]byte(entry.Secret))
		if block == nil {
			return nil, fmt.Errorf("signing key %s: secret is not a PEM block", entry.Kid)
		}

		switch block.Type {
		case "RSA PRIVATE KEY":
			priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("signing key %s: parse private key: %w", entry.Kid, err)
			}
			key.Private = priv
			key.Public = &priv.PublicKey
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("signing key %s: parse pkcs8 private key: %w", entry.Kid, err)
			}
			priv, ok := parsed.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("signing key %s: pkcs8 key is not RSA", entry.Kid)
			}
			key.Private = priv
			key.Public = &priv.PublicKey
		case "PUBLIC KEY":
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("signing key %s: parse public key: %w", entry.Kid, err)
			}
			pub, ok := parsed.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("signing key %s: public key is not RSA", entry.Kid)
			}
			key.Public = pub
		default:
			return nil, fmt.Errorf("signing key %s: unsupported PEM block type %q", entry.Kid, block.Type)
		}

		keys = append(keys, key)
	}
	return keys, nil
}
