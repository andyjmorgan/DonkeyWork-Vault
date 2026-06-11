package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func goodKeks() map[string]string {
	return map[string]string{"local:v1": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}
}

func TestNewLocalKekProvider_Errors(t *testing.T) {
	cases := []struct {
		name   string
		active string
		keks   map[string]string
	}{
		{"empty active", "", goodKeks()},
		{"no keks", "local:v1", map[string]string{}},
		{"bad base64", "local:v1", map[string]string{"local:v1": "!!!notbase64"}},
		{"wrong length", "local:v1", map[string]string{"local:v1": base64.StdEncoding.EncodeToString([]byte("short"))}},
		{"active missing", "local:v9", goodKeks()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewLocalKekProvider(c.active, c.keks); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestUnwrapErrors(t *testing.T) {
	p, err := NewLocalKekProvider("local:v1", goodKeks())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Unwrap("nope", make([]byte, 60)); err == nil {
		t.Fatal("expected unknown kek error")
	}
	if _, err := p.Unwrap("local:v1", []byte{1, 2, 3}); err == nil {
		t.Fatal("expected too-short error")
	}
	if _, err := p.Unwrap("local:v1", make([]byte, 60)); err == nil {
		t.Fatal("expected gcm open failure on garbage")
	}
}

func TestDecryptTruncations(t *testing.T) {
	c := newTestCipher(t)
	blob, _ := c.EncryptString("hello")
	// Truncate within the kekId header and within the body.
	for _, n := range []int{5, 7, 10, len(blob) - 1} {
		if n <= 0 || n >= len(blob) {
			continue
		}
		if _, err := c.Decrypt(blob[:n]); err == nil {
			t.Fatalf("expected error decrypting truncated blob at %d", n)
		}
	}
}

func TestUnsupportedVersion(t *testing.T) {
	c := newTestCipher(t)
	blob, _ := c.EncryptString("hello")
	blob[4] = 9 // bump version byte
	if _, err := c.Decrypt(blob); err == nil {
		t.Fatal("expected unsupported version error")
	}
}
