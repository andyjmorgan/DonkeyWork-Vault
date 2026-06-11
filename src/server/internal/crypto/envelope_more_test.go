package crypto

import (
	"errors"
	"strings"
	"testing"
)

type fakeKek struct {
	id       string
	wrap     []byte
	wrapErr  error
	unwrap   []byte
	unwrapEr error
}

func (f fakeKek) ActiveKekID() string { return f.id }
func (f fakeKek) Wrap(dek []byte) ([]byte, error) {
	if f.wrapErr != nil {
		return nil, f.wrapErr
	}
	return f.wrap, nil
}
func (f fakeKek) Unwrap(string, []byte) ([]byte, error) {
	if f.unwrapEr != nil {
		return nil, f.unwrapEr
	}
	return f.unwrap, nil
}

func TestEncrypt_WrapError(t *testing.T) {
	c := NewEnvelopeCipher(fakeKek{id: "k", wrapErr: errors.New("kms down")})
	if _, err := c.Encrypt([]byte("x")); err == nil {
		t.Fatal("expected wrap error")
	}
}

func TestEncrypt_KekIDTooLong(t *testing.T) {
	c := NewEnvelopeCipher(fakeKek{id: strings.Repeat("a", 300), wrap: make([]byte, 60)})
	if _, err := c.Encrypt([]byte("x")); err == nil {
		t.Fatal("expected kekId too long")
	}
}

func TestEncrypt_WrappedTooLong(t *testing.T) {
	c := NewEnvelopeCipher(fakeKek{id: "k", wrap: make([]byte, 70000)})
	if _, err := c.Encrypt([]byte("x")); err == nil {
		t.Fatal("expected wrapped DEK too long")
	}
}

func TestDecrypt_UnwrapError(t *testing.T) {
	// Build a structurally valid blob with the real cipher, then decrypt with a kek that errors.
	real := newTestCipher(t)
	blob, _ := real.EncryptString("hi")
	c := NewEnvelopeCipher(fakeKek{id: "local:v1", unwrapEr: errors.New("no key")})
	if _, err := c.Decrypt(blob); err == nil {
		t.Fatal("expected unwrap error")
	}
}

func TestDecrypt_BadDEKLength(t *testing.T) {
	real := newTestCipher(t)
	blob, _ := real.EncryptString("hi")
	// Unwrap returns a 10-byte "key" → aes.NewCipher fails inside Decrypt.
	c := NewEnvelopeCipher(fakeKek{id: "local:v1", unwrap: make([]byte, 10)})
	if _, err := c.Decrypt(blob); err == nil {
		t.Fatal("expected aes key length error")
	}
}

func TestDecryptToStringError(t *testing.T) {
	c := newTestCipher(t)
	if _, err := c.DecryptToString([]byte("not-a-blob")); err == nil {
		t.Fatal("expected error")
	}
}
