package oauth

import (
	"io"
	"testing"
)

func TestRandomBase64urlReadError(t *testing.T) {
	orig := randReader
	t.Cleanup(func() { randReader = orig })
	randReader = errReader{}

	if _, err := GenerateVerifier(); err == nil {
		t.Fatal("expected error when randReader fails")
	}
	if _, err := RandomState(); err == nil {
		t.Fatal("expected error when randReader fails")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
