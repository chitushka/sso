package secrets

import (
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	e := NewAESGCM("0123456789abcdef0123456789abcdef")
	ct, err := e.Encrypt("bind-password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, "enc:v1:") {
		t.Fatalf("missing prefix: %s", ct)
	}
	if strings.Contains(ct, "bind-password") {
		t.Fatal("ciphertext contains plaintext")
	}
	pt, err := e.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "bind-password" {
		t.Fatalf("got %q", pt)
	}
}

func TestDecryptLegacyPlaintextPassthrough(t *testing.T) {
	e := NewAESGCM("0123456789abcdef0123456789abcdef")
	pt, err := e.Decrypt("legacy-plaintext")
	if err != nil {
		t.Fatal(err)
	}
	if pt != "legacy-plaintext" {
		t.Fatalf("got %q", pt)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	e1 := NewAESGCM("0123456789abcdef0123456789abcdef")
	e2 := NewAESGCM("another-key-another-key-another!")
	ct, err := e1.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2.Decrypt(ct); err == nil {
		t.Fatal("decrypt with wrong key must fail")
	}
}
