package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// A fixed 32-byte KEK so tests are deterministic across runs.
const testKekID = "local:v1"

var testKekB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, 32))

func newTestCipher(t *testing.T) *EnvelopeCipher {
	t.Helper()
	kek, err := NewLocalKekProvider(testKekID, map[string]string{testKekID: testKekB64})
	if err != nil {
		t.Fatalf("NewLocalKekProvider: %v", err)
	}
	return NewEnvelopeCipher(kek)
}

func TestRoundTrip(t *testing.T) {
	c := newTestCipher(t)
	for _, pt := range []string{"", "hello", "dwv_secret_value", "a much longer secret with unicode → ✓ 🦄"} {
		blob, err := c.EncryptString(pt)
		if err != nil {
			t.Fatalf("encrypt %q: %v", pt, err)
		}
		got, err := c.DecryptToString(blob)
		if err != nil {
			t.Fatalf("decrypt %q: %v", pt, err)
		}
		if got != pt {
			t.Fatalf("round-trip mismatch: got %q want %q", got, pt)
		}
	}
}

// TestBlobLayout asserts the exact on-disk header the .NET service also writes, so a blob produced
// here is binary-compatible with one produced by EnvelopeCipherService (and vice versa).
func TestBlobLayout(t *testing.T) {
	c := newTestCipher(t)
	blob, err := c.EncryptString("payload")
	if err != nil {
		t.Fatal(err)
	}

	o := 0
	if string(blob[o:o+4]) != "DWV1" {
		t.Fatalf("bad magic: %x", blob[:4])
	}
	o += 4
	if blob[o] != version {
		t.Fatalf("bad version: %d", blob[o])
	}
	o++
	kekIDLen := int(blob[o])
	o++
	if got := string(blob[o : o+kekIDLen]); got != testKekID {
		t.Fatalf("bad kekId: %q", got)
	}
	o += kekIDLen
	wrappedLen := int(binary.BigEndian.Uint16(blob[o:]))
	o += 2
	// wrappedDek = nonce(12) || tag(16) || ciphertext(32-byte DEK) = 60 bytes.
	if wrappedLen != nonceSize+tagSize+dekSize {
		t.Fatalf("unexpected wrapped DEK length: %d", wrappedLen)
	}
}

// TestCrossDecrypt decrypts a blob assembled by hand to the documented C# layout, proving the
// reader matches the spec rather than just its own writer.
func TestCrossDecrypt(t *testing.T) {
	kek, err := NewLocalKekProvider(testKekID, map[string]string{testKekID: testKekB64})
	if err != nil {
		t.Fatal(err)
	}
	c := NewEnvelopeCipher(kek)

	// Build a valid envelope using the low-level primitives, mimicking an external producer.
	plaintext := []byte("external-producer")
	dek := bytes.Repeat([]byte{0x07}, dekSize)
	gcm, _ := newGCM(dek)
	nonce := bytes.Repeat([]byte{0x01}, nonceSize)
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	ct, tag := sealed[:len(sealed)-tagSize], sealed[len(sealed)-tagSize:]
	wrapped, err := kek.Wrap(dek)
	if err != nil {
		t.Fatal(err)
	}

	var blob []byte
	blob = append(blob, "DWV1"...)
	blob = append(blob, version)
	blob = append(blob, byte(len(testKekID)))
	blob = append(blob, testKekID...)
	blob = binary.BigEndian.AppendUint16(blob, uint16(len(wrapped)))
	blob = append(blob, wrapped...)
	blob = append(blob, nonce...)
	blob = append(blob, tag...)
	blob = append(blob, ct...)

	got, err := c.Decrypt(blob)
	if err != nil {
		t.Fatalf("decrypt hand-built blob: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q want %q", got, plaintext)
	}
}

func TestBadMagic(t *testing.T) {
	c := newTestCipher(t)
	if _, err := c.Decrypt([]byte("XXXX____")); err == nil {
		t.Fatal("expected error on bad magic")
	}
}
