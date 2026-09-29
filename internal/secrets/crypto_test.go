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

func TestDecryptRejectsPlaintext(t *testing.T) {
	e := NewAESGCM("0123456789abcdef0123456789abcdef")
	if _, err := e.Decrypt("plaintext"); err == nil {
		t.Fatal("plaintext secret must be rejected")
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
