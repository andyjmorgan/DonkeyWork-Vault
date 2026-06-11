package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// LocalKekProvider is the default KEK provider for dev and small self-host deployments. It reads KEK
// material from configuration and AES-256-GCM-wraps DEKs. A wrapped DEK is laid out as
// nonce(12) || tag(16) || ciphertext(dek length) — identical to the C# LocalKekProvider.
type LocalKekProvider struct {
	keks      map[string][]byte
	activeKek string
}

// NewLocalKekProvider validates the configured KEKs and returns a provider. activeKekID must be
// present in keks, and every key must be 32 raw bytes (base64-decoded).
func NewLocalKekProvider(activeKekID string, keksBase64 map[string]string) (*LocalKekProvider, error) {
	if activeKekID == "" {
		return nil, errors.New("Vault:Crypto:ActiveKekId is not configured")
	}
	if len(keksBase64) == 0 {
		return nil, errors.New("Vault:Crypto:Keks is empty; at least one KEK is required")
	}

	keks := make(map[string][]byte, len(keksBase64))
	for id, b64 := range keksBase64 {
		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("KEK %q is not valid base64: %w", id, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("KEK %q must be 32 bytes (256-bit); got %d", id, len(key))
		}
		keks[id] = key
	}
	if _, ok := keks[activeKekID]; !ok {
		return nil, fmt.Errorf("ActiveKekId %q is not present in Vault:Crypto:Keks", activeKekID)
	}
	return &LocalKekProvider{keks: keks, activeKek: activeKekID}, nil
}

// ActiveKekID returns the id of the KEK used to wrap new DEKs.
func (p *LocalKekProvider) ActiveKekID() string { return p.activeKek }

// Wrap seals a DEK with the active KEK.
func (p *LocalKekProvider) Wrap(dek []byte) ([]byte, error) {
	gcm, err := newGCM(p.keks[p.activeKek])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, dek, nil) // ciphertext || tag
	ct := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	wrapped := make([]byte, 0, nonceSize+tagSize+len(ct))
	wrapped = append(wrapped, nonce...)
	wrapped = append(wrapped, tag...)
	wrapped = append(wrapped, ct...)
	return wrapped, nil
}

// Unwrap opens a previously wrapped DEK using the named KEK.
func (p *LocalKekProvider) Unwrap(kekID string, wrappedDek []byte) ([]byte, error) {
	key, ok := p.keks[kekID]
	if !ok {
		return nil, fmt.Errorf("unknown kekId %q; no matching key in configuration", kekID)
	}
	if len(wrappedDek) < nonceSize+tagSize {
		return nil, errors.New("wrapped DEK is too short")
	}
	nonce := wrappedDek[:nonceSize]
	tag := wrappedDek[nonceSize : nonceSize+tagSize]
	ct := wrappedDek[nonceSize+tagSize:]

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(ct)+len(tag))
	sealed = append(sealed, ct...)
	sealed = append(sealed, tag...)
	return gcm.Open(nil, nonce, sealed, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
