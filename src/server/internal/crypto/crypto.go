// Package crypto implements the vault's envelope encryption for secret-at-rest columns.
//
// The blob format is stable so that existing stored ciphertext decrypts unchanged. The on-disk blob
// layout (a single bytea column) is:
//
//	magic "DWV1" (4) | version (1) | kekIdLen (1) | kekId (utf8) |
//	wrappedDekLen (2, big-endian) | wrappedDek | nonce (12) | tag (16) | ciphertext
//
// A wrapped DEK is itself laid out as: nonce(12) || tag(16) || ciphertext(dek length). AAD is not
// used; integrity is provided by the GCM tag. The kekId travels in the header so decryption routes
// to the correct (possibly historical) KEK without any schema change.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	magic     = "DWV1"
	version   = 1
	nonceSize = 12
	tagSize   = 16 // AES-GCM standard tag size; Go appends the tag to the ciphertext.
	dekSize   = 32 // 256-bit data encryption key.
)

// Cipher is the envelope encryption surface used by the domain services.
type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(blob []byte) ([]byte, error)
	EncryptString(plaintext string) ([]byte, error)
	DecryptToString(blob []byte) (string, error)
}

// KekProvider wraps and unwraps per-row DEKs with a key-encryption key (KEK).
type KekProvider interface {
	// ActiveKekID identifies the KEK used to wrap new DEKs (e.g. "local:v1").
	ActiveKekID() string
	// Wrap seals a DEK with the active KEK.
	Wrap(dek []byte) ([]byte, error)
	// Unwrap opens a wrapped DEK using the named KEK.
	Unwrap(kekID string, wrappedDek []byte) ([]byte, error)
}

// EnvelopeCipher is the AES-256-GCM envelope cipher with a per-row DEK wrapped by a KekProvider.
type EnvelopeCipher struct {
	kek KekProvider
}

// NewEnvelopeCipher constructs a cipher over the given KEK provider.
func NewEnvelopeCipher(kek KekProvider) *EnvelopeCipher { return &EnvelopeCipher{kek: kek} }

// Encrypt seals plaintext into a self-describing envelope blob.
func (c *EnvelopeCipher) Encrypt(plaintext []byte) ([]byte, error) {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Go's Seal appends a 16-byte tag to the ciphertext; the blob layout stores tag and ciphertext
	// separately, so split the sealed output back into ciphertext || tag.
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	ct := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	wrappedDek, err := c.kek.Wrap(dek)
	if err != nil {
		return nil, err
	}
	kekID := []byte(c.kek.ActiveKekID())
	if len(kekID) > 0xFF {
		return nil, errors.New("kekId is too long to encode (max 255 bytes)")
	}
	if len(wrappedDek) > 0xFFFF {
		return nil, errors.New("wrapped DEK is too long to encode")
	}

	total := len(magic) + 1 + 1 + len(kekID) + 2 + len(wrappedDek) + nonceSize + tagSize + len(ct)
	blob := make([]byte, 0, total)
	blob = append(blob, magic...)
	blob = append(blob, version)
	blob = append(blob, byte(len(kekID)))
	blob = append(blob, kekID...)
	blob = binary.BigEndian.AppendUint16(blob, uint16(len(wrappedDek)))
	blob = append(blob, wrappedDek...)
	blob = append(blob, nonce...)
	blob = append(blob, tag...)
	blob = append(blob, ct...)
	return blob, nil
}

// Decrypt opens an envelope blob produced by Encrypt, including existing stored ciphertext.
func (c *EnvelopeCipher) Decrypt(blob []byte) ([]byte, error) {
	o := 0
	if len(blob) < len(magic)+2 || string(blob[:len(magic)]) != magic {
		return nil, errors.New("not a recognized envelope blob (bad magic)")
	}
	o += len(magic)

	if blob[o] != version {
		return nil, fmt.Errorf("unsupported envelope version %d", blob[o])
	}
	o++

	kekIDLen := int(blob[o])
	o++
	if len(blob) < o+kekIDLen+2 {
		return nil, errors.New("envelope truncated (kekId)")
	}
	kekID := string(blob[o : o+kekIDLen])
	o += kekIDLen

	wrappedLen := int(binary.BigEndian.Uint16(blob[o:]))
	o += 2
	if len(blob) < o+wrappedLen+nonceSize+tagSize {
		return nil, errors.New("envelope truncated (body)")
	}
	wrappedDek := blob[o : o+wrappedLen]
	o += wrappedLen
	nonce := blob[o : o+nonceSize]
	o += nonceSize
	tag := blob[o : o+tagSize]
	o += tagSize
	ct := blob[o:]

	dek, err := c.kek.Unwrap(kekID, wrappedDek)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Recombine ciphertext || tag for Go's Open.
	sealed := make([]byte, 0, len(ct)+len(tag))
	sealed = append(sealed, ct...)
	sealed = append(sealed, tag...)
	return gcm.Open(nil, nonce, sealed, nil)
}

// EncryptString is a UTF-8 convenience wrapper over Encrypt.
func (c *EnvelopeCipher) EncryptString(plaintext string) ([]byte, error) {
	return c.Encrypt([]byte(plaintext))
}

// DecryptToString is a UTF-8 convenience wrapper over Decrypt.
func (c *EnvelopeCipher) DecryptToString(blob []byte) (string, error) {
	b, err := c.Decrypt(blob)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
