// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package security

import (
	"bytes"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	methods := []int{0, 1, 2, 3, 4, 5}
	plaintext := []byte("masterdnsvpn-roundtrip-test")
	rawKey := "0123456789abcdef0123456789abcdef"

	for _, method := range methods {
		codec, err := NewCodec(method, rawKey)
		if err != nil {
			t.Fatalf("NewCodec(%d) returned error: %v", method, err)
		}

		ciphertext, err := codec.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt failed for method %d: %v", method, err)
		}

		decrypted, err := codec.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt failed for method %d: %v", method, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("round-trip mismatch for method %d", method)
		}
	}
}

func TestCodecRejectsInvalidCiphertext(t *testing.T) {
	codec, err := NewCodec(3, "0123456789abcdef")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	if _, err := codec.Decrypt([]byte{1, 2, 3}); err == nil {
		t.Fatal("Decrypt should reject truncated AES-GCM ciphertext")
	}
}

func TestCodecXORChangesData(t *testing.T) {
	codec, err := NewCodec(1, "key-material")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	plaintext := []byte("xor-data")
	ciphertext, err := codec.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("XOR encryption should change non-empty data")
	}
}
