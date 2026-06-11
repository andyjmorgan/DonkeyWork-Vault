package crypto

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"
)

// failReader fails after okReads successful (zero-filled) reads.
type failReader struct{ okReads int }

func (r *failReader) Read(p []byte) (int, error) {
	if r.okReads <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	r.okReads--
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func withRandReader(t *testing.T, r io.Reader) {
	t.Helper()
	orig := randReader
	t.Cleanup(func() { randReader = orig })
	randReader = r
}

// TestEncryptRandDEKError covers the DEK rand.Read error branch.
func TestEncryptRandDEKError(t *testing.T) {
	c := newTestCipher(t)
	withRandReader(t, &failReader{okReads: 0})
	if _, err := c.Encrypt([]byte("x")); err == nil {
		t.Fatal("expected DEK read error")
	}
}

// TestEncryptRandNonceError covers the nonce rand.Read error branch (DEK read succeeds first).
func TestEncryptRandNonceError(t *testing.T) {
	c := newTestCipher(t)
	withRandReader(t, &failReader{okReads: 1})
	if _, err := c.Encrypt([]byte("x")); err == nil {
		t.Fatal("expected nonce read error")
	}
}

// TestWrapRandNonceError covers the nonce rand.Read error branch in LocalKekProvider.Wrap.
func TestWrapRandNonceError(t *testing.T) {
	p, err := NewLocalKekProvider("local:v1", goodKeks())
	if err != nil {
		t.Fatal(err)
	}
	withRandReader(t, &failReader{okReads: 0})
	if _, err := p.Wrap(make([]byte, dekSize)); err == nil {
		t.Fatal("expected nonce read error")
	}
}

// TestDecryptBodyTruncation truncates a blob just past the 2-byte wrappedLen field so the body
// length check (wrappedDek||nonce||tag) fails, covering the "envelope truncated (body)" branch.
func TestDecryptBodyTruncation(t *testing.T) {
	c := newTestCipher(t)
	blob, err := c.EncryptString("hello")
	if err != nil {
		t.Fatal(err)
	}
	// Header is magic(4)+version(1)+kekIDLen(1)+kekID(8)+wrappedLenField(2) = 16 bytes for "local:v1".
	// Cut one byte into the body so the full wrappedDek/nonce/tag cannot be read.
	cut := 4 + 1 + 1 + len(testKekID) + 2 + 1
	if cut >= len(blob) {
		t.Fatalf("blob too small: %d", len(blob))
	}
	if _, err := c.Decrypt(blob[:cut]); err == nil {
		t.Fatal("expected body-truncation error")
	}
}

// TestNewGCMBadKey exercises the aes.NewCipher error path inside newGCM with an invalid key length.
func TestNewGCMBadKey(t *testing.T) {
	if _, err := newGCM(make([]byte, 10)); err == nil {
		t.Fatal("expected aes.NewCipher error for 10-byte key")
	}
}

// TestWrapUnwrapRoundTrip exercises the happy path of the local KEK provider directly.
func TestWrapUnwrapRoundTrip(t *testing.T) {
	p, err := NewLocalKekProvider("local:v1", map[string]string{
		"local:v1": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{0x5a}, dekSize)
	wrapped, err := p.Wrap(dek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	got, err := p.Unwrap("local:v1", wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("dek round-trip mismatch")
	}
}
