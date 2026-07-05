package mfa

import (
	"testing"
	"time"
)

func TestRFC6238Vector(t *testing.T) {
	// RFC 6238 Appendix B test vector: secret "12345678901234567890" (SHA-1),
	// T=59 → TOTP 94287082 → last 6 digits 287082.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // base32 of the ASCII secret
	got, err := code(secret, 1)                  // 59/30 = 1
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Fatalf("want 287082, got %s", got)
	}
}

func TestVerifyWindow(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	current, err := code(secret, uint64(now.Unix())/30)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(secret, current, now) {
		t.Fatal("current code must verify")
	}
	previous, _ := code(secret, uint64(now.Unix())/30-1)
	if !Verify(secret, previous, now) {
		t.Fatal("previous period code must verify (drift window)")
	}
	old, _ := code(secret, uint64(now.Unix())/30-5)
	if Verify(secret, old, now) && old != current && old != previous {
		t.Fatal("stale code must not verify")
	}
	if Verify(secret, "000000", now) && current != "000000" && previous != "000000" {
		t.Fatal("wrong code must not verify")
	}
}
